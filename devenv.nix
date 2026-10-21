{ pkgs, lib, ... }:

{
  dotenv.enable = true;

  packages = with pkgs; [
    just
    jq

    lld

    cargo-audit
    cargo-deny
    cargo-fuzz
    cargo-hack
    cargo-release
    cargo-watch
  ];

  languages = {
    rust = {
      enable = true;
      channel = "stable";
      # `just wasm`: the transport-free crates on a JS host.
      targets = [ "wasm32-unknown-unknown" ];

      # lld.enable = true;
    };

    javascript = {
      enable = true;

      npm.enable = true;
    };
  };

  profiles = {
    # Fuzzing and the docs.rs build: devenv --profile nightly shell
    nightly.module = {
      languages.rust.channel = lib.mkForce "nightly";
    };

    # The MSRV (rust-version in Cargo.toml): devenv --profile msrv shell
    msrv.module = {
      languages.rust.version = "1.91.0";
    };
  };

  services = {
    # vault = {
    #   enable = true;
    # };
  };
}
