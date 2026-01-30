# CombiSan  
CombiSan is a sanitizer that combines detection of addressability issues, use-of-uninitialized-memory (UUM) errors, and other undefined behavior bugs at the same time. In the context of fuzzing, it prevents early bugs from masking later ones by using a novel deferred detection mode, where bugs are aggregated and analyzed upon test case completion, where the fuzzer will treat them according to their class.

Our paper "CombiSan: Unifying Software Sanitizers for Comprehensive Fuzzing" has been accepted for publication at USENIX Security 2026.

#### Artifact Evaluation

If you are evaluating this artifact, please refer to `AE.md` for more detailed instructions on how to perform the proposed experiments.

## Building LLVM

To build CombiSan's custom LLVM version, first clone the repository:

```
git clone --recursive https://github.com/vusec/combisan.git
cd combisan
```
Then compile LLVM with its standard procedure

```
cd llvm-project
mkdir build
cd build
cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_ENABLE_RUNTIMES="compiler-rt" -DCMAKE_BUILD_TYPE=Release -GNinja -DCMAKE_EXPORT_COMPILE_COMMANDS=On -DLLVM_PARALLEL_LINK_JOBS=1 -DLLVM_TARGETS_TO_BUILD=X86 -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF ../llvm
ninja
```

Please note how `LLVM_PARALLEL_LINK_JOBS` is set to 1 to ease compilation on lower end machines, but it can be set it to a higher value on target machines with more RAM available to speed up compilation time (as a rule of thumb, 1 parallel job per 16 GB of RAM is a good choice).

The compilation process is automated by the `build_llvm.sh` script.

## Building AFL++

To build CombiSan's modified AFL++ version:

```
cd AFL_CombiSan
make CFLAGS="-DCOMBISAN -DCOMBISAN_DEBUG" LLVM_CONFIG=/path/to/CombiSan/llvm-project clean all
```
Also, make sure to have Valgrind installed, or install it with, e.g.:
```
sudo apt install valgrind
```



## Using CombiSan
`-fsanitize=address` enables CombiSan's detection of addressability issues and UUM errors. Additional detection of other UB can be enabled by setting the relevant flags; e.g., `-fsanitize=undefined` enables all of them. So, given a test file `test.c` we can compile it with CombiSan's instrumentation using a command line similar to:
```
path/to/combisan/llvm-project/build/bin/clang -fsanitize=address test.c -o test
```

Additionally, `-fsanitize-recover=address` allows execution to continue after violations, which is needed for deferred detection of bugs while fuzzing.

To fuzz with CombiSan, one can use a command similar to the following:
```
path/to/AFL_CombiSan/afl-fuzz -i corpus/ -o out -m none -- path/to/target/instrumented_target
```
More detailed instructions can be found in AFL++ documentation.

CombiSan needs an uninstrumented binary to verify loads of uninitialized memory. Make sure to recompile your software without sanitizers and provide its location with `COMBISAN_UNINSTRUMENTED=path/to/target/uninstrumented_target`. If one is not provided, CombiSan will still save the test cases it would test with valgrind in `out/violations/` to be reproduced asynchronously.

## Docker

To ease both compilation and use, especially for fuzzing, we provide Dockerfiles in the `docker` directory. The Dockerfiles use the OSS-Fuzz docker image as a base, but they can be trivially modified to start from another image (e.g. any recent Ubuntu version) by just installing some dependency that the OSS-Fuzz containers already installed.

This folder also contains Dockerfiles to build the targets of our evaluation. You may find them in the `oss-fuzz` and `fts` subdirectories for OSS-Fuzz and Google's Fuzzer Test Suite targets respectively.

## Testing with Infra

We provide an infrastructure to test CombiSan, in the `infra/` directory. It allows tests with the SPEC benchmarks, for performance, and with the Juliet Test Suite, for bug detection capabilities.

To use it, please provide the installation path of SPEC and the installation path of a clean LLVM 20.1.0 installation through the `SPEC_DIR` and `CLEAN_LLVM_DIR` respectively. To download and install a clean LLVM 20.1.0, the `build_llvm_clean.sh` script is provided.

##### SPEC
To run SPEC, use the following command:
```
python3 setup.py run spec2017 baseline_O2 asan_O2 csan-rec_O2 msan-rec_O2 --build --parallel=proc --parallelmax=1
```

Change `spec2017` to `spec2006` to change version. You can see the results with:
```
python3 ./setup.py report spec2017 results/last/ --aggregate geomean --field runtime:median maxrss:medians
```

Please note how tests with the SPEC benchmarks are performed using the O2 optimization level, as they should.

##### Juliet
Execute Juliet with the following command line:
```
python3 setup.py run juliet csan_O0 --build --parallel=proc --parallelmax=$(nproc) --cwe 121 122 124 126 127 415 416 457 190 191 194 476 758 843 &> juliet_out
```
Redirecting output to a file (e.g., `juliet_out`) is useful to later parse the results, as the testing infrastructure produces some noise that you may want to filter out. You can do this with:
```
cat juliet_out | grep Passed
```
CombiSan and other sanitizers have few false positives and false negatives on Juliet test cases, please refer to the paper for a detailed explanation.

You can run Juliet with the other tools by switching `csan_O0` to, e.g., `asan_O0`. Juliet tests should be done with O0, not with higher optimization levels (such as O2) as this is known to mask bugs. 

## Repository structure

- `AFL_CombiSan` contains a patched version of AFL++ 4.32c that supports the execution of CombiSan.
- `llvm-project` contains a modified version of LLVM 20.1.0 which applies CombiSan's instrumentation.
- `docker` contains Dockerfiles used to build (and use) CombiSan inside Docker.
- `infra` contains an infrastructure to test CombiSan.
- `cves` and `arvo` contain additional tests against known bugs and vulnerabilities.

#### Inspecting the source code

Both LLVM and AFL++ are big projects. CombiSan's major features are implemented in:
- LLVM
    - Runtime: `llvm-project/compiler-rt/lib/`
        - `asan/asan_report.cpp` contains the run-time management of addressability issues and UUM errors.
        - `ubsan/ubsan_handlers.cpp` contains the run-time management of undefined behaviors.
        - `sanitizer_common.cpp`, `asan/asan_rtl.cpp`, and `asan/asan_poisoning.cpp` contain addition code so support CombiSan's functionalities
    - CombiSan's pass: `llvm-project/llvm/lib/Transforms/`
        - `Instrumentation/AddressSanitizer.cpp` contains the pass that applies CombiSan's instrumentation.
        - `Utils/ASanStackFrameLayout.cpp` contains support for stack management.
- AFL++
    - `AFL_CombiSan/src/afl-fuzz-run.c` contains the code that analyzes the results of each fuzzing execution.
    - `AFL_CombiSan/src/afl-fuzz.c` contains the code that initializes and destroys CombiSan's runtime features.
    - CombiSan's code in AFL++ is completely defined under `#ifdef COMBISAN` sections. Search them in the code to find all the remaining, less relevant, patches (e.g., printing custom stats, management of additional directories etc.)

All CombiSan’s additions can be found in both modules by searching for `CombiSan` (without case sensitivity) in the source files.

## Troubleshooting
If ASan randomly crashes sometimes, this is likely due to recent changes to ASLR in the Linux kernel.  
Currently, the workaround is:
`sudo sysctl vm.mmap_rnd_bits=28`

If Juliet runs very slowly, it could be due to core dumps being processed on every buggy (crashing) binary. Consider disabling apport:
```
sudo systemctl disable --now apport.service
sudo service apport stop
```
