# AOT Object Relocation Inventory

The native object linker inventory records the relocations and disassembly
produced by representative AOT compilations. Each fixture should be collected
for this matrix:

| Optimization | CPU target | Interruptible |
| --- | --- | --- |
| O0 | generic | normal |
| O0 | generic | interruptible |
| O0 | host | normal |
| O0 | host | interruptible |
| O3 | generic | normal |
| O3 | generic | interruptible |
| O3 | host | normal |
| O3 | host | interruptible |

The inventory covers scalar operations, direct and indirect calls, globals,
tables, memory, SIMD, atomics, and exceptions.

Use `utils/llvm/collect-aot-relocations.sh` to generate `object.txt` and
`disassembly.txt`. Publish these reports as CI artifacts for comparison; do not
commit generated reports, AOT modules, object files, or other binaries.
