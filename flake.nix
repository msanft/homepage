{
  description = "Nix Flake containing the basic tools for tinkering with this website.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; }; in
      {
        packages.default = pkgs.stdenvNoCC.mkDerivation {
          name = "homepage";
          version = "0-unstable-2025-03-10";

          src = ./.;

          buildInputs = with pkgs; [ hugo ];

          buildPhase = ''
            hugo
          '';

          installPhase = ''
            mkdir -p $out
            cp -r public/* $out
          '';
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            hugo
          ];
        };
      }
    );
}
