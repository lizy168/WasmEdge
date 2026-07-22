#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <wasmedgec> <input.wasm> <output-dir>" >&2
  exit 1
fi

wasmedgec=$(realpath "$1")
input=$(realpath "$2")
output_dir=$3

mkdir -p "$output_dir"
cd "$output_dir"

"$wasmedgec" --dump-ir "$input" output.aot.wasm
llvm-readobj --file-headers --sections --symbols --relocations wasm.o > object.txt
llvm-objdump -dr wasm.o > disassembly.txt
