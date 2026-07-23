# AOT Object Relocation Inventory

The native object linker inventory records the relocations and disassembly
produced by representative AOT compilations. Each fixture should be collected
for this matrix:

| Optimization | CPU target | Interruptible |
| --- | --- | --- |
| O0 | generic | normal |
| O0 | generic | interruptible |
| O0 | tuned | normal |
| O0 | tuned | interruptible |
| O2 | generic | normal |
| O2 | generic | interruptible |
| O2 | tuned | normal |
| O2 | tuned | interruptible |

The inventory covers scalar operations, direct and indirect calls, globals,
tables, memory, SIMD, atomics, and exceptions.

Cross-target tests use explicit tuned CPUs rather than claiming they represent
the build host: Cortex-A8, Cortex-A53, generic-rv64 with the A extension, and
z13. ARM exceptions use a defined cantunwind table because standard LLVM ARM
personality tables import `__aeabi_unwind_cpp_pr0`, which the linker rejects.

Use `utils/llvm/collect-aot-relocations.sh` to generate `object.txt` and
`disassembly.txt`. Publish these reports as CI artifacts for comparison; do not
commit generated reports, AOT modules, object files, or other binaries.
