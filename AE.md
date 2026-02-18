# Artifact Evaluation

This file contains extensive instructions for performing the artifact evaluation of CombiSan. We provide SSH access to a machine in our lab to the artifact evaluators with the SPEC CPU benchmarks preinstalled, in case the evaluators do not possess a SPEC CPU license.

## Prerequisites

To test CombiSan, make sure you installed the dependencies:
```
sudo apt install gcc g++ cmake ninja-build docker
```
Please note how Docker's package name may vary depending on your OS version and package manager (e.g., `docker.io` for some versions of Ubuntu, or `sudo snap install docker` on snap)

#### Cloning and building

To obtain CombiSan, clone its repository:

```
git clone --recursive https://github.com/vusec/combisan.git
cd combisan
```
Then compile LLVM with the provided script:
```
./build_llvm.sh
```
This script is designed to be executed on a machine with more RAM than a common laptop. If you are trying to build LLVM on a different machine than the one we provided, change the parameter `LLVM_PARALLEL_LINK_JOBS` according to the amount of RAM you have; approximately 1 per 16 GB of RAM is a reasonable value. If there are out-of-memory (Killed) errors during compilation, reduce this value.

#### Building an unmodified LLVM

A clean LLVM 20.1.0 (the version CombiSan is based on) is needed for comparison with ASan, MSan, and UBSan. Build it, with: 
```
./build_llvm_clean.sh
```
This script is very similar to the one executed before; the same limit to RAM usage applies.


#### Environment variables

Two variables need to be exported for the next experiments to run:
```
export CLEAN_LLVM_DIR=path/to/combisan/llvm-project-20.1.0.src/build
export SPEC_DIR=/usr/spec/
```

To double check, running this command:
```
$CLEAN_LLVM_DIR/bin/clang --version
```

Should give the following result
```
clang version 20.1.0 (git@github.com:llvm/llvm-project.git 24a30daaa559829ad079f2ff7f73eb4e18095f88)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: path/to/combisan/llvm-20/llvm-project/build/bin
```

While this command
```
ls $SPEC_DIR
```
Should at least list the following directories (depending on your setup):
```
spec2006 spec20017
```

## Experiment E1 - Juliet

To test detection accuracy, we propose an experiment using the Juliet Test Suite, with a comparison to the three state-of-the-art sanitizers (ASan, MSan, and UBSan). To execute this test, simply run:

```
python3 setup.py run juliet csan_O0 --build --parallel=proc --parallelmax=$(nproc) --cwe 121 122 124 126 127 415 416 457 190 191 194 476 758 843 &> juliet_out
```
Redirecting output to a file (e.g., `juliet_out`) is useful to later parse the results, as the testing infrastructure produces some noise that you may want to filter out. Parse the results with:
```
cat juliet_out | grep Passed
```

The expected results are as follows (in any order):
```
10:59:36 [INFO] CWE124: Passed 932/932 GOOD tests
10:59:36 [INFO] CWE124: Passed 932/932 BAD tests
11:02:12 [INFO] CWE122: Passed 3177/3178 GOOD tests
11:02:12 [INFO] CWE122: Passed 3178/3178 BAD tests
11:02:39 [INFO] CWE194: Passed 540/540 GOOD tests
11:02:39 [INFO] CWE194: Passed 540/540 BAD tests
11:02:59 [INFO] CWE758: Passed 494/494 GOOD tests
11:02:59 [INFO] CWE758: Passed 422/494 BAD tests
11:03:43 [INFO] CWE457: Passed 866/882 GOOD tests
11:03:43 [INFO] CWE457: Passed 882/882 BAD tests
11:04:20 [INFO] CWE415: Passed 765/765 GOOD tests
11:04:20 [INFO] CWE415: Passed 765/765 BAD tests
11:06:22 [INFO] CWE121: Passed 2634/2634 GOOD tests
11:06:22 [INFO] CWE121: Passed 2634/2634 BAD tests
11:06:32 [INFO] CWE190: Passed 2262/2299 GOOD tests
11:06:32 [INFO] CWE190: Passed 627/2299 BAD tests
11:06:34 [INFO] CWE476: Passed 279/285 GOOD tests
11:06:34 [INFO] CWE476: Passed 268/285 BAD tests
11:06:58 [INFO] CWE126: Passed 612/612 GOOD tests
11:06:58 [INFO] CWE126: Passed 612/612 BAD tests
11:07:04 [INFO] CWE843: Passed 0/74 GOOD tests
11:07:04 [INFO] CWE843: Passed 74/74 BAD tests
11:07:23 [INFO] CWE416: Passed 374/374 GOOD tests
11:07:23 [INFO] CWE416: Passed 374/374 BAD tests
11:07:30 [INFO] CWE191: Passed 1714/1714 GOOD tests
11:07:30 [INFO] CWE191: Passed 447/1714 BAD tests
11:08:03 [INFO] CWE127: Passed 932/932 GOOD tests
11:08:03 [INFO] CWE127: Passed 932/932 BAD tests
```

CombiSan and the other sanitizers run into a few false positives and false negatives on the Juliet test cases, please refer to the paper for a detailed explanation.

You can run Juliet with the other tools by switching `csan_O0` to, e.g., `asan_O0`. Juliet tests should run with O0, not with higher optimization levels (such as O2), as this is known to mask bugs. In case you want to reproduce these bugs with other tools, CWEs `121` `122` `124` `126` `127` `415` `416` refer to "ASan bugs", CWE `457` are UUM errors (i.e., "MSan bugs"), while the others are other undefined behavior ("UBSan bugs").

This test reproduces results from Table 4 in the paper.

## Experiment E2 - SPEC CPU

To showcase CombiSan's performance overhead (both runtime and memory), we use the SPEC CPU benchmarking suite. As detailed in Section 6.3 of the paper, the fairest comparison for both CombiSan and MSan is a version where bugs/violations are detected, but no error is raised. Both CombiSan and MSan can be built in this mode with the `build_llvm_SPEC.sh` script. Please note that this will replace any previous installation of CombiSan's LLVM (e.g., the one made for E1), so make sure you are done using it, or back it up for later reuse.

After compiling CombiSan, simply run:
```
python3 setup.py run spec2017 baseline_O2 asan_O2 csan-rec_O2 msan-rec_O2 --build --parallel=proc --parallelmax=1
```

You can view the results with:
```
python3 ./setup.py report spec2017 results/last/ --field runtime:median maxrss:median
```

Both commands above can also be run on SPEC CPU2006 by switching `spec2017` to `spec2006`. You can also view the results of other runs by changing `results/last` into a specific `results/` subdirectory, e.g. `results/run.2026-01-27.16-27-46`. The expected results should be similar to this:

```
+ spec2017 aggregated data ---------------------------------------------------------------------+
|                asan_O2          baseline_O2         csan-rec_O2          msan-rec_O2          |
|                runtime maxrss   runtime     maxrss  runtime     maxrss   runtime     maxrss   |
|benchmark       median  median   median      median  median      median   median      median   |
+-----------------------------------------------------------------------------------------------+
|500.perlbench_r 377      2533168 153          457616 529          3081004 428          1027532 |
|502.gcc_r       351     14130420 111         6511436 448         16542264 353         15177724 |
|505.mcf_r       245       919272 211          623952 284          1105664 334          1248620 |
|508.namd_r      180       502784  94.1        166656 263           566784 306           352568 |
|510.parest_r    443      1420564 178          430856 579          1699384 496          1121872 |
|519.lbm_r       103       476160  94.0        420608 191           528640 171           841984 |
|520.omnetpp_r   556      1179396 157          248260 676          1321216 478           520232 |
|523.xalancbmk_r 225      2889588 122          491568 357          3270476 228          1097948 |
|525.x264_r      176       474112  86.0        361984 300           533504 182           772544 |
|531.deepsjeng_r 307       727808 175          718336 387           907520 359          1426532 |
|538.imagick_r   333       822884 219          293528 593           945512 408           588988 |
|541.leela_r     457      1120372 243           26516 626          1282416 480            51104 |
|544.nab_r       242       539964 125          150108 262           604492 279           326820 |
|557.xz_r        269      2947556 197         2323668 310          3494236 409          4533648 |
+-----------------------------------------------------------------------------------------------+
```

Geomean overhead aggregates can be calculated by dividing each entry by the baseline entry, and then taking the geomean of the decimal multipliers.

This experiment reproduces the results obtained and discussed in Section 6.3.

## Experiment E3 - Fuzzing

To evaluate CombiSan's fuzzing capabilities, and in particular its deferred detection of bugs, we propose a fuzzing experiment.

#### Prepare Docker

Build CombiSan's Docker image with:

```
cd docker/combisan/ 
docker build -t combisan .
```
This will once again build CombiSan's LLVM. `LLVM_PARALLEL_LINK_JOBS` is set to 1, but can be set to a higher value to speed up compilation time.

Additionally, the directory `docker/compiler` contains a Dockerfile to build a "clean" fuzzing environment (i.e., with base LLVM and AFL++). It can be built with the same commands described above, just replace the image's tag with `-t compiler`:

```
cd docker/compiler/ 
docker build -t compiler .
```


Please use the tags we suggest here for the docker images (i.e., `combisan` and `compiler`), as the Dockerfiles rely on it. If you change them, also change the targets' Dockerfiles accordingly.

#### Build the targets

All the targets we used (from both OSS-Fuzz and FTS, with the versions we used) can be compiled using commands similar to the one described above. For example, to compile `libxml2` from FTS:

```
cd docker/fts/libxml2/libxml2_combisan/ 
docker build -t libxml2_combisan .
```

Each target can be compiled in multiple versions:
- `combisan`: which uses CombiSan's instrumentation
- `asan`,`msan`,`ubsan`: which use the relative sanitizer
- `afl`: which does not use any sanitizer
- `absan`: which uses ASan and UBSan at the same time
- `ablated`: which enables CombiSan without UB detection

### Fuzzing
To perform fuzzing, spawn a container of a previously built target with, e.g.:
```
docker run -it libxml2_combisan bash
```
Then start fuzzing with:
```
$AFL/afl-fuzz -i in -o out -m none -- $EXECUTABLE_NAME_BASE
```
Note how this command works in every container built with our Dockerfiles, as both the `combisan` and `compiler` images define the necessary variables.

#### Deferred detection of bugs

Three targets from FTS (`libxml2`, `pcre2`, and `re2`) contain an additional directory with multiple copies of crashing inputs that can be used as seeds to show deferred detection in action. While these inputs cause crashes, CombiSan will treat them according to its deferred detection policies and will continue fuzzing with some of them (Section 4 of the paper), while regular AFL++ would discard all of them for triggering crashes. You can test this with, e.g.:
```
$AFL/afl-fuzz -i crashes -o out -m none -- $EXECUTABLE_NAME_BASE
```
And checking the AFL++'s output to see how ASan bugs are always treated as crashes, while MSan bugs depend on violations, and UBSan bugs are only treated as crashes the first time they are detected.

