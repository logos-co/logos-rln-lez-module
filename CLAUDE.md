# logos-rln-lez-module

- The staged SDK (`logos-rust-sdk-src/`) and the scaffold
  (`rust-lib/generated/provider_gen.rs`) are gitignored and come from
  `nix run .#generate`, which takes lidl-gen, the SDK source and the
  `--protocol-version` from the builder flake.lock pins — so they cannot
  drift from the nix build. Re-run it after any flake.lock or `.lidl`
  change; a stale stage fails `cargo --locked` since the SDK crate is
  versioned. The builder is pinned by rev, not tag:
  `nix flake lock --override-input logos-module-builder github:logos-co/logos-module-builder/<rev>`.
  flake.lock carries TWO logos-rust-sdk nodes with different revs: only the root
  `logos-rust-sdk` node matters — it is what logos-module-builder's
  `lidl-gen`/`rust-sdk-src` build against. `logos-rust-sdk_2` is inert for
  our `type: core` modules (it belongs to the logos-standalone-app →
  logos-capability-module demo chain, only evaluated for `type: ui`
  modules); its drift can be ignored.
