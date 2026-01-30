FROM gcr.io/oss-fuzz-base/base-builder

ENV DEBIAN_FRONTEND=noninteractive

#Install the dependencies
RUN apt-get update && apt-get install -y openssh-client nano gdb 
#valgrind libc++-dev libc++abi-dev

#Add the Key to the ssh client and download combisan
RUN git clone --recursive https://github.com/vusec/combisan.git

#Build LLVM
RUN apt-get install -y cmake ninja-build
RUN mkdir combisan/llvm-project/build
WORKDIR combisan/llvm-project/build
#remove flags to compile LLVM, but save them to be restored
ENV TMP_CFLAGS=$CFLAGS
ENV CFLAGS=""
ENV TMP_CXXFLAGS=$CXXFLAGS
ENV CXXFLAGS=""
ENV TMP_CXXFLAGS_EXTRA=$CXXFLAGS_EXTRA
ENV CXXFLAGS_EXTRA=""
#change LLVM_PARALLEL_LINK_JOBS if you want faster compilation. Too high value may stall your machine though.
RUN cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_ENABLE_RUNTIMES="compiler-rt;libcxx;libcxxabi" -DCMAKE_BUILD_TYPE=Release -GNinja -DLLVM_PARALLEL_LINK_JOBS=1  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF -DLIBCXXABI_USE_LLVM_UNWINDER=OFF ../llvm
RUN ninja
RUN ninja install-cxx install-cxxabi

ENV LLVM="/src/combisan/llvm-project/"

#Add the libc++ libraries to the environment; for whatever reason cmake does not seem to install them properly
#Old method: use LD_LIBRARY_PATH
#ENV LD_LIBRARY_PATH="$LLVM/build/lib/x86_64-unknown-linux-gnu/"
RUN cp $LLVM/build/lib/x86_64-unknown-linux-gnu/* /usr/local/lib/x86_64-unknown-linux-gnu/
RUN cp $LLVM/build/lib/x86_64-unknown-linux-gnu/* /usr/lib/x86_64-linux-gnu/

#Build AFL++
WORKDIR ../../AFL_CombiSan
RUN make CFLAGS="-DCOMBISAN -DCOMBISAN_DEBUG" LLVM_CONFIG=$LLVM/build/bin/llvm-config clean all
#RUN make LLVM_CONFIG=$LLVM/build/bin/llvm-config clean all
ENV AFL="/src/combisan/AFL_CombiSan/"

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

ENV SANITIZER_FLAGS_undefined="-fsanitize=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fsanitize-recover=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,returns-nonnull-attribute,shift,signed-integer-overflow,vla-bound,vptr"

#New method: manually set them to remove libc++ stuff and -Wno-xxx flags that do not exist anymore
ENV CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=vla-cxx-extension -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -pthread -fsanitize-recover=address ${SANITIZER_FLAGS_undefined}"
ENV CXXFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=vla-cxx-extension -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -pthread -fsanitize-recover=address ${SANITIZER_FLAGS_undefined}"
ENV CXXFLAGS_EXTRA=""

#we always want combisan
ENV AFL_USE_ASAN=1
ENV ASAN_OPTIONS="abort_on_error=1:symbolize=0"

#setup the out directory and the dummy seed
RUN mkdir $OUT/in
RUN echo "hi" > $OUT/in/in

#copy the driver in position
RUN cp $AFL/utils/aflpp_driver/libAFLDriver.a /usr/lib/libFuzzingEngine.a

WORKDIR $SRC
