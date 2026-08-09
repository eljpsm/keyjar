{
  description = "keyjar";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # Single source of truth for name, version, and description.
        cargoToml = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package;
      in
      {
        # Everything `make test` / `make lint` / `make fmt` need.
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.rust-analyzer
            pkgs.gnumake
            pkgs.cargo-llvm-cov
          ];
          # rust-analyzer needs the std sources for completion in the deps.
          env.RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
          # cargo-llvm-cov looks for rustup's llvm-tools-preview; point it at
          # nixpkgs' LLVM instead.
          env.LLVM_COV = "${pkgs.llvmPackages.llvm}/bin/llvm-cov";
          env.LLVM_PROFDATA = "${pkgs.llvmPackages.llvm}/bin/llvm-profdata";
        };

        # `nix build` / `nix run` keyjar itself.
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = cargoToml.name;
          version = cargoToml.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          meta = {
            description = cargoToml.description;
            license = pkgs.lib.licenses.gpl3Plus;
            mainProgram = "keyjar";
          };
        };

        # buildRustPackage runs `cargo test` in its check phase, so building
        # the package is also the test run for `nix flake check`.
        checks.default = self.packages.${system}.default;
      }
    );
}
