{
  description = "Logos module: the RLN registry provider on LEZ";

  nixConfig = {
    extra-substituters = [ "https://cache.nix.logos.co/public" ];
    extra-trusted-public-keys = [
      "public:zaDAOkd+E3cQyFm9J7qejQYd9HoLJc1SJvnk68hNWeI="
    ];
  };

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    logos-execution-zone.url =
      "github:logos-blockchain/logos-execution-zone/v0.4.0-rc3";
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" "x86_64-windows" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems fn;

      module = logos-module-builder.lib.mkLogosModule {
        src = ./.;
        configFile = ./metadata.json;
        flakeInputs = inputs;
        externalLibInputs = {
          core_ffi = {
            input = inputs.logos-execution-zone;
            packages.default = "core";
          };
        };
      };
    in
    {
      packages = forAllSystems (system:
        let m = module.packages.${system};
        in m // {
          rln_lez_module = m.default;
        });

      inherit (module) config;

      apps = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          lidlGen = logos-module-builder.inputs.logos-rust-sdk.packages.${system}.lidl-gen;
          sdkSrc = logos-module-builder.packages.${system}.rust-sdk-src;
          protocolVersion =
            let
              header = builtins.readFile
                "${logos-module-builder.inputs.logos-protocol}/cpp/logos_protocol.h";
              parts = builtins.split "LOGOS_PROTOCOL_VERSION_STRING \"([^\"]*)\"" header;
            in
            if builtins.length parts < 2
            then throw "logos-protocol header carries no LOGOS_PROTOCOL_VERSION_STRING"
            else builtins.head (builtins.elemAt parts 1);
          generate = pkgs.writeShellApplication {
            name = "rln-lez-module-generate";
            runtimeInputs = [ lidlGen pkgs.gitMinimal ];
            text = ''
              root="''${1:-$(git rev-parse --show-toplevel)}"
              echo "generating rust-lib/generated/provider_gen.rs (protocol ${protocolVersion}) ..."
              mkdir -p "$root/rust-lib/generated"
              logos-lidl-gen "$root/rust-lib/rln_lez_module.lidl" --provider \
                --concurrency multi \
                --protocol-version ${protocolVersion} \
                -o "$root/rust-lib/generated/provider_gen.rs"
              echo "staging the SDK source at logos-rust-sdk-src/ ..."
              rm -rf "''${root:?}/logos-rust-sdk-src"
              cp -RL "${sdkSrc}" "$root/logos-rust-sdk-src"
              chmod -R u+w "$root/logos-rust-sdk-src"
              echo "done. bare 'cargo build' now works in rust-lib/"
            '';
          };
        in {
          generate = {
            type = "app";
            program = "${generate}/bin/rln-lez-module-generate";
          };
        });
    };
}
