{
  description = "Encrypt anything with a password";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }: flake-utils.lib.eachDefaultSystem (system: let
    pkgs = nixpkgs.legacyPackages.${system};
  in rec {
    packages.secret = pkgs.buildGoModule {
      name = "secret";
      src = ./.;
      vendorSha256 = "sha256-x8NM5/TMnUmwy+8gW+r9WNoyhPNL8TW6acjc0xkUGR4=";
      meta = with pkgs.lib; {
        description = "Encrypt anything with a password";
        homepage = "https://github.com/quackduck/secret";
        license = licenses.mit;
        platforms = platforms.linux ++ platforms.darwin;
      };
    };
    defaultPackage = packages.secret;
  });
}
