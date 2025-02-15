{ inputs, ... }:
{
  perSystem = { config, self', pkgs, lib, ... }: {
    devShells.default = pkgs.mkShell {
      name = "merka-vault-shell";
      inputsFrom = [
        self'.devShells.rust
        config.pre-commit.devShell # See ./nix/modules/pre-commit.nix
      ];
      packages = with pkgs; [
        just
        nixd # Nix language server
        bacon
        act
        config.process-compose.cargo-doc-live.outputs.package
      ];
    };
  };
}
