{
  description = "Moritz Sanft's SvelteKit homepage.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages.default = pkgs.stdenv.mkDerivation (finalAttrs: {
          pname = "homepage";
          version = "0-unstable-2026-08-24";

          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: _type:
              let
                name = builtins.baseNameOf (toString path);
              in
              !(builtins.elem name [
                "node_modules"
                ".svelte-kit"
                "build"
                "result"
              ]);
          };

          nativeBuildInputs = [
            pkgs.nodejs_22
            pkgs.pnpm_10.configHook
          ];

          pnpmDeps = pkgs.pnpm_10.fetchDeps {
            inherit (finalAttrs) pname version src;
            fetcherVersion = 2;
            hash = "sha256-yB8ymONwkfvH47AqEWKEga9cuK9AtAyQpRilHyAs0dc=";
          };

          buildPhase = ''
            runHook preBuild
            pnpm build
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out
            cp -r build/. $out/
            runHook postInstall
          '';
        });

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            nodejs_22
            pnpm_10
          ];
        };
      }
    );
}
