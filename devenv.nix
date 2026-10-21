{ pkgs, lib, ... }:

{
  dotenv.enable = true;

  packages = with pkgs; [
    just
    jq
    # `just wasm`: wasm-bindgen-test-runner runs the wasm32 tests under Node.
    nodejs

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

      lld.enable = true;
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

    # wasm32 (`just wasm`): devenv --profile wasm shell. lld sets `RUSTFLAGS=-C link-arg=-fuse-ld=lld`,
    # which rust-lld rejects when linking wasm; without it the workflow's RUSTFLAGS apply as well.
    wasm.module = {
      languages.rust.lld.enable = lib.mkForce false;
    };
  };

  services = {
    # vault = {
    #   enable = true;
    # };
  };
}
