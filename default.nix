{ nixpkgs ? import <nixpkgs> {}, compiler ? "ghc7101" }:

let ptrace = nixpkgs.haskell.packages.${compiler}.callPackage ../ptrace {}; in

let

  inherit (nixpkgs) pkgs;

  f = { mkDerivation, base, binary, bytestring, containers, mtl
      , ptrace, stdenv, unix
      }:
      mkDerivation {
        pname = "trace";
        version = "0.1";
        src = ./.;
        buildDepends = [
          base binary bytestring containers mtl ptrace unix
        ];
        license = stdenv.lib.licenses.mit;
      };

  drv = pkgs.haskell.packages.${compiler}.callPackage f { ptrace = ptrace; };

in

  if pkgs.lib.inNixShell then drv.env else drv
