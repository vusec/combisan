FROM gcr.io/oss-fuzz-base/base-builder

ENV DEBIAN_FRONTEND=noninteractive

#Install the dependencies
RUN apt-get update && apt-get install -y nano gdb wget 
#valgrind wget libc++-dev libc++abi-dev

#Download and build the same version of LLVM
#We can't use the prebuilt ones as they expect a higher glibc version...
RUN apt-get install -y cmake ninja-build
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-20.1.0/llvm-project-20.1.0.src.tar.xz
RUN tar -xf llvm-project-20.1.0.src.tar.xz 
RUN mkdir llvm-project-20.1.0.src/build
WORKDIR llvm-project-20.1.0.src/build
#remove flags to compile LLVM, but save them to be restored
ENV TMP_CFLAGS=$CFLAGS
ENV CFLAGS=""
ENV TMP_CXXFLAGS=$CXXFLAGS
ENV CXXFLAGS=""
ENV TMP_CXXFLAGS_EXTRA=$CXXFLAGS_EXTRA
ENV CXXFLAGS_EXTRA=""
RUN cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_ENABLE_RUNTIMES="compiler-rt;libcxx;libcxxabi" -DCMAKE_BUILD_TYPE=Release -GNinja -DLLVM_PARALLEL_LINK_JOBS=6  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF -DLIBCXXABI_USE_LLVM_UNWINDER=OFF ../llvm 
RUN ninja
RUN ninja install-cxx install-cxxabi

ENV LLVM="$SRC/llvm-project-20.1.0.src/"

#Now build the MSan-compiled libc++
RUN mkdir $LLVM/msan_libs
WORKDIR $LLVM/msan_libs
RUN cmake -GNinja -S ../runtimes -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" -DCMAKE_C_COMPILER=$LLVM/build/bin/clang -DCMAKE_CXX_COMPILER=$LLVM/build/bin/clang++ -DLLVM_USE_SANITIZER=Memory -DLIBCXXABI_USE_LLVM_UNWINDER=OFF
RUN ninja
ENV MSAN_LIBS="$LLVM/msan_libs/lib/"

RUN cp $LLVM/build/lib/x86_64-unknown-linux-gnu/* /usr/local/lib/x86_64-unknown-linux-gnu/
RUN cp $LLVM/build/lib/x86_64-unknown-linux-gnu/* /usr/lib/x86_64-linux-gnu/

#Download and build AFL++
WORKDIR $SRC
RUN wget https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v4.32c.tar.gz
RUN tar -xf v4.32c.tar.gz
WORKDIR AFLplusplus-4.32c
RUN make LLVM_CONFIG=$LLVM/build/bin/llvm-config clean all

ENV AFL="$SRC/AFLplusplus-4.32c/"

#build the latest version of valgrind to support debug symbols
WORKDIR $SRC
RUN apt install -y autoconf
RUN git clone https://sourceware.org/git/valgrind.git valgrind
WORKDIR $SRC/valgrind
RUN ./autogen.sh
RUN ./configure
RUN make install

ENV CC="$AFL/afl-clang-fast"
ENV CXX="$AFL/afl-clang-fast++"

#New method: manually set them to remove libc++ stuff and -Wno-xxx flags that do not exist anymore
ENV CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=vla-cxx-extension -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -pthread -fsanitize-recover=address"
ENV CXXFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=vla-cxx-extension -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -pthread -fsanitize-recover=address"
ENV CXXFLAGS_EXTRA=""

#OSS-Fuzz's flags, we only removed unsigned integer overflows (which do not cause crashes anyway since they do not set no recover for them)
ENV SANITIZER_FLAGS_undefined "-fsanitize=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr"


#setup the out directory and the dummy seed
RUN mkdir $OUT/in
RUN echo "hi" > $OUT/in/in

RUN cp $AFL/utils/aflpp_driver/libAFLDriver.a /usr/lib/libFuzzingEngine.a

#set asan exit code so that AFL detects the crash
ENV ASAN_OPTIONS="exitcode=-1:abort_on_error=1:symbolize=0"

#Tell UBSan to crash
ENV UBSAN_OPTIONS="abort_on_error=1"

ENV SANITIZER=""

WORKDIR $SRC
