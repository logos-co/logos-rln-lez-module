use std::sync::OnceLock;

use serde::Deserialize;

use crate::base58;
use crate::rln_core::bytes_to_hex;

const TABLE_JSON: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/networks.json"));

const FORMAT: &str = "lez-rln-networks";

#[derive(Deserialize)]
struct Table {
    format: String,
    version: u32,
    networks: Vec<Network>,
}

#[derive(Deserialize)]
pub(crate) struct Network {
    pub(crate) reference: String,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "descriptive; read by the tests and by humans")
    )]
    pub(crate) description: String,
    pub(crate) sequencer: String,
    pub(crate) registries: Vec<Registry>,
}

#[derive(Deserialize)]
pub(crate) struct Registry {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "identifies the deployment for whoever edits the table"
        )
    )]
    pub(crate) deployment: String,
    pub(crate) config_account: String,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "identifies the deployment for whoever edits the table"
        )
    )]
    pub(crate) tree_id: String,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "identifies the deployment for whoever edits the table"
        )
    )]
    pub(crate) registration_program_id: String,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "identifies the deployment for whoever edits the table"
        )
    )]
    pub(crate) merkle_program_id: String,
}

fn parse(raw: &str) -> Result<Vec<Network>, String> {
    let table: Table = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if table.format != FORMAT {
        return Err(format!("format is '{}', expected '{FORMAT}'", table.format));
    }
    if table.version != 1 {
        return Err(format!("version {} is not supported", table.version));
    }
    Ok(table.networks)
}

fn table() -> &'static [Network] {
    static TABLE: OnceLock<Vec<Network>> = OnceLock::new();
    TABLE.get_or_init(|| {
        parse(TABLE_JSON).unwrap_or_else(|e| {
            eprintln!("lez-rln networks: the embedded networks.json is unusable: {e}");
            Vec::new()
        })
    })
}

pub(crate) fn network(reference: &str) -> Option<&'static Network> {
    table().iter().find(|n| n.reference == reference)
}

pub(crate) fn network_of_config(config_hex: &str) -> Option<&'static Network> {
    let config_hex = config_hex.trim().to_ascii_lowercase();
    table().iter().find(|n| {
        n.registries.iter().any(|r| {
            base58::decode32(&r.config_account).is_some_and(|b| bytes_to_hex(&b) == config_hex)
        })
    })
}

pub(crate) fn known_references() -> Vec<&'static str> {
    table().iter().map(|n| n.reference.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_table_parses() {
        let networks = parse(TABLE_JSON).expect("networks.json");
        assert!(!networks.is_empty());
        assert_eq!(table().len(), networks.len());
    }

    #[test]
    fn a_foreign_format_or_version_is_refused() {
        assert!(parse(r#"{"format":"other","version":1,"networks":[]}"#).is_err());
        assert!(parse(r#"{"format":"lez-rln-networks","version":2,"networks":[]}"#).is_err());
        assert!(parse("not json").is_err());
    }

    #[test]
    fn references_are_lowercase_caip2_and_unique() {
        let refs = known_references();
        for r in &refs {
            assert!(
                !r.is_empty()
                    && r.len() <= 32
                    && r.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "'{r}' is not a CAIP-2 reference"
            );
            assert_eq!(*r, r.to_ascii_lowercase(), "'{r}' is not lowercase");
        }
        let mut sorted = refs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), refs.len(), "duplicate reference in {refs:?}");
    }

    #[test]
    fn config_accounts_decode_and_are_unique() {
        let mut seen = Vec::new();
        for n in table() {
            assert!(
                !n.registries.is_empty(),
                "{} lists no registry",
                n.reference
            );
            for r in &n.registries {
                let bytes = base58::decode32(&r.config_account).unwrap_or_else(|| {
                    panic!("{}: {} is not base58", r.deployment, r.config_account)
                });
                let hex = bytes_to_hex(&bytes);
                assert!(!seen.contains(&hex), "{} listed twice", r.config_account);
                seen.push(hex);
                for id in [&r.tree_id, &r.registration_program_id, &r.merkle_program_id] {
                    assert!(
                        crate::hex::hex_to_bytes32(id).is_some(),
                        "{}: {id} is not 32-byte hex",
                        r.deployment
                    );
                }
                assert!(!r.deployment.is_empty());
            }
        }
    }

    #[test]
    fn sequencers_are_http_urls_with_a_trailing_slash() {
        for n in table() {
            let s = &n.sequencer;
            assert!(
                (s.starts_with("http://") || s.starts_with("https://")) && s.ends_with('/'),
                "{}: sequencer '{s}'",
                n.reference
            );
            assert!(
                !n.description.is_empty(),
                "{} has no description",
                n.reference
            );
        }
    }

    #[test]
    fn every_registry_resolves_to_its_network() {
        for n in table() {
            assert_eq!(
                network(&n.reference).map(|m| m.reference.as_str()),
                Some(n.reference.as_str())
            );
            for r in &n.registries {
                let hex = bytes_to_hex(&base58::decode32(&r.config_account).expect("base58"));
                for config in [hex.clone(), hex.to_ascii_uppercase()] {
                    assert_eq!(
                        network_of_config(&config).map(|m| m.reference.as_str()),
                        Some(n.reference.as_str()),
                        "{}: {config}",
                        r.deployment
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_or_miscased_lookups_find_nothing() {
        assert!(network_of_config(&"ab".repeat(32)).is_none());
        assert!(network("mainnet").is_none());
        let first = &table()[0].reference;
        assert!(
            network(&first.to_ascii_uppercase()).is_none(),
            "lookups are exact; callers lowercase"
        );
    }

    #[test]
    fn the_references_consumers_name_exist() {
        for reference in ["devnet", "testnet"] {
            assert!(network(reference).is_some(), "no `{reference}` network");
        }
    }
}
