use std::time::Duration;

use base64::Engine as _;

use crate::wallet;

const REQUEST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"getFeeState","params":[]}"#;
const HEAD_REQUEST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"getLastBlockId","params":[]}"#;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const IO_TIMEOUT: Duration = Duration::from_secs(10);

const MAX_REPLY: u64 = 1024 * 1024;

const MAX_BLOCK_REPLY: u64 = 8 * 1024 * 1024;

const BLOCK_TIMESTAMP_OFFSET: usize = 8 + 32 + 32;
const BLOCK_HEADER_SIZE: usize = BLOCK_TIMESTAMP_OFFSET + 8;

pub(crate) fn get_fee_state() -> String {
    fee_quote()
        .map(|quote| quote.to_string())
        .unwrap_or_default()
}

pub(crate) fn fee_quote() -> Option<serde_json::Value> {
    let Some(sequencer) = wallet::sequencer_addr() else {
        eprintln!("get_fee_state: no sequencer configured yet");
        return None;
    };
    match fetch_quote(&sequencer) {
        Ok(quote) => Some(quote),
        Err(e) => {
            eprintln!("get_fee_state: {sequencer}: {e}");
            None
        }
    }
}

#[cfg(test)]
pub(crate) fn fetch(sequencer: &str) -> Result<String, String> {
    fetch_quote(sequencer).map(|quote| quote.to_string())
}

fn fetch_quote(sequencer: &str) -> Result<serde_json::Value, String> {
    result_object(&post(sequencer, REQUEST)?)
}

pub(crate) fn chain_head() -> Option<u64> {
    let sequencer = wallet::sequencer_addr()?;
    rpc_result(&sequencer, HEAD_REQUEST, MAX_REPLY)
        .ok()?
        .as_u64()
}

pub(crate) fn head_block_timestamp_ms() -> Option<u64> {
    let Some(sequencer) = wallet::sequencer_addr() else {
        eprintln!("head_block_timestamp_ms: no sequencer configured yet");
        return None;
    };
    match fetch_head_timestamp(&sequencer) {
        Ok(timestamp) => Some(timestamp),
        Err(e) => {
            eprintln!("head_block_timestamp_ms: {sequencer}: {e}");
            None
        }
    }
}

pub(crate) fn fetch_head_timestamp(sequencer: &str) -> Result<u64, String> {
    let head = rpc_result(sequencer, HEAD_REQUEST, MAX_REPLY)?
        .as_u64()
        .ok_or_else(|| "getLastBlockId reply is not a block number".to_owned())?;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getBlock", "params": [head]
    })
    .to_string();
    let result = rpc_result(sequencer, &body, MAX_BLOCK_REPLY)?;
    if result.is_null() {
        return Err(format!("block {head} is missing"));
    }
    let encoded = result
        .as_str()
        .ok_or_else(|| "getBlock reply is not a base64 block".to_owned())?;
    let block = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("getBlock reply is not base64: {e}"))?;
    block_header_timestamp(&block).ok_or_else(|| format!("block {head} carries no timestamp"))
}

fn block_header_timestamp(block: &[u8]) -> Option<u64> {
    let field = block.get(BLOCK_TIMESTAMP_OFFSET..BLOCK_HEADER_SIZE)?;
    let timestamp = u64::from_le_bytes(field.try_into().ok()?);
    (timestamp != 0).then_some(timestamp)
}

pub(crate) fn tx_included(tx_hash: &str) -> Option<bool> {
    let sequencer = wallet::sequencer_addr()?;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [tx_hash]
    })
    .to_string();
    match rpc_result(&sequencer, &body, MAX_REPLY) {
        Ok(result) => Some(!result.is_null()),
        Err(e) => {
            eprintln!("tx_included: {sequencer}: {e}");
            None
        }
    }
}

fn post_capped(url: &str, body: &str, cap: u64) -> Result<String, String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("not an http(s) sequencer: '{url}'"));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(IO_TIMEOUT)
        .timeout_write(IO_TIMEOUT)
        .build();
    let reply = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(body)
        .map_err(|e| e.to_string())?;
    let mut text = String::new();
    std::io::Read::read_to_string(
        &mut std::io::Read::take(reply.into_reader(), cap),
        &mut text,
    )
    .map_err(|e| format!("read: {e}"))?;
    Ok(text)
}

fn post(url: &str, body: &str) -> Result<String, String> {
    post_capped(url, body, MAX_REPLY)
}

fn rpc_result(url: &str, body: &str, cap: u64) -> Result<serde_json::Value, String> {
    let mut reply: serde_json::Value = serde_json::from_str(&post_capped(url, body, cap)?)
        .map_err(|e| format!("reply parse: {e}"))?;
    if let Some(error) = reply.get("error") {
        return Err(format!("RPC error {error}"));
    }
    reply
        .get_mut("result")
        .map(serde_json::Value::take)
        .ok_or_else(|| "reply carries no result".to_owned())
}

#[cfg(test)]
fn result_of(body: &str) -> Result<String, String> {
    result_object(body).map(|result| result.to_string())
}

fn result_object(body: &str) -> Result<serde_json::Value, String> {
    let mut reply: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("reply parse: {e}"))?;
    if let Some(error) = reply.get("error") {
        return Err(format!("RPC error {error}"));
    }
    match reply.get_mut("result") {
        Some(result) if result.is_object() => Ok(result.take()),
        _ => Err("reply carries no result object".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    const QUOTE: &str = r#"{"height":15082,"base_fee_exec":8,"base_fee_stor":8,"next_base_fee_exec_floor":8,"next_base_fee_exec_ceiling":9,"next_base_fee_stor_floor":8,"next_base_fee_stor_ceiling":9,"max_gas_exec":10000000,"max_gas_stor":1000000}"#;

    fn ok_reply(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn read_request(conn: &mut TcpStream) -> String {
        let mut raw = Vec::new();
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let n = conn.read(&mut chunk).unwrap();
            assert!(n > 0, "client closed before sending the headers");
            raw.extend_from_slice(&chunk[..n]);
        };
        let headers = String::from_utf8_lossy(&raw[..header_end]).to_ascii_lowercase();
        let length: usize = headers
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .expect("content-length header")
            .trim()
            .parse()
            .unwrap();
        while raw.len() < header_end + length {
            let n = conn.read(&mut chunk).unwrap();
            assert!(n > 0, "client closed before sending the whole body");
            raw.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8(raw).unwrap()
    }

    #[test]
    fn only_http_and_https_sequencers_are_asked() {
        assert!(post("ftp://seq.local/", REQUEST)
            .unwrap_err()
            .contains("not an http(s)"));
        assert!(post("209.38.241.182:3140", REQUEST).is_err());
    }

    #[test]
    fn a_quote_passes_through_with_every_field() {
        let rpc = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{QUOTE}}}"#);
        let out = result_of(&rpc).unwrap();
        let got: serde_json::Value = serde_json::from_str(&out).unwrap();
        let want: serde_json::Value = serde_json::from_str(QUOTE).unwrap();
        assert_eq!(got, want);
        assert!(!out.contains(' '), "compact JSON: {out}");
    }

    #[test]
    fn rpc_errors_and_non_objects_are_refused() {
        let missing =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        assert!(result_of(missing).is_err());
        assert!(result_of(r#"{"jsonrpc":"2.0","id":1,"result":8}"#).is_err());
        assert!(result_of("garbage").is_err());
    }

    #[test]
    fn a_non_200_reply_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut chunk = [0u8; 4096];
            let _ = conn.read(&mut chunk).unwrap();
            conn.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n")
                .unwrap();
        });
        assert!(fetch(&format!("http://127.0.0.1:{port}/")).is_err());
        server.join().unwrap();
    }

    #[test]
    fn a_round_trip_against_a_local_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let request = read_request(&mut conn);
            let rpc = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{QUOTE}}}"#);
            conn.write_all(&ok_reply(&rpc)).unwrap();
            request
        });
        let out = fetch(&format!("http://127.0.0.1:{port}/")).unwrap();
        let request = server.join().unwrap();
        assert!(request.starts_with("POST / HTTP/1.1\r\n"), "{request}");
        assert!(request.ends_with(REQUEST), "{request}");
        assert!(out.contains(r#""next_base_fee_exec_ceiling":9"#), "{out}");
    }

    #[test]
    fn nothing_listening_is_an_error_not_a_hang() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(fetch(&format!("http://127.0.0.1:{port}/")).is_err());
    }

    fn borsh_block(timestamp: u64) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&7u64.to_le_bytes());
        raw.extend_from_slice(&[0x11; 32]);
        raw.extend_from_slice(&[0x22; 32]);
        raw.extend_from_slice(&timestamp.to_le_bytes());
        raw.extend_from_slice(&[0; 9]);
        raw
    }

    #[test]
    fn the_timestamp_is_the_last_header_field() {
        let block = borsh_block(1_700_000_000_123);
        assert_eq!(block_header_timestamp(&block), Some(1_700_000_000_123));
        assert_eq!(BLOCK_HEADER_SIZE, 80);
        assert_eq!(
            block_header_timestamp(&block[..79]),
            None,
            "shorter than a header"
        );
        assert_eq!(
            block_header_timestamp(&borsh_block(0)),
            None,
            "a zero timestamp is no time"
        );
    }

    #[test]
    fn the_head_timestamp_is_read_in_two_calls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let first = read_request(&mut conn);
            assert!(first.ends_with(HEAD_REQUEST), "{first}");
            conn.write_all(&ok_reply(r#"{"jsonrpc":"2.0","id":1,"result":41}"#))
                .unwrap();
            drop(conn);
            let (mut conn, _) = listener.accept().unwrap();
            let second = read_request(&mut conn);
            assert!(second.contains(r#""method":"getBlock""#), "{second}");
            assert!(second.contains(r#""params":[41]"#), "{second}");
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(borsh_block(1_700_000_000_123));
            conn.write_all(&ok_reply(&format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":"{encoded}"}}"#
            )))
            .unwrap();
        });
        let timestamp = fetch_head_timestamp(&format!("http://127.0.0.1:{port}/")).unwrap();
        server.join().unwrap();
        assert_eq!(timestamp, 1_700_000_000_123);
    }

    #[test]
    fn a_missing_or_malformed_block_is_no_time() {
        for result in [r#"null"#, r#""not base64!""#, r#"{"header":{}}"#] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let reply = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
            let server = std::thread::spawn(move || {
                let (mut conn, _) = listener.accept().unwrap();
                read_request(&mut conn);
                conn.write_all(&ok_reply(r#"{"jsonrpc":"2.0","id":1,"result":3}"#))
                    .unwrap();
                drop(conn);
                let (mut conn, _) = listener.accept().unwrap();
                read_request(&mut conn);
                conn.write_all(&ok_reply(&reply)).unwrap();
            });
            assert!(
                fetch_head_timestamp(&format!("http://127.0.0.1:{port}/")).is_err(),
                "{result}"
            );
            server.join().unwrap();
        }
    }
}
