cd  llvm-project

#remove old builds
if [ -d build ]; then
    rm -rf build
fi

mkdir build
cd build

#cmake, consider lowering LLVM_PARALLEL_LINK_JOBS to not saturate RAM. One job per 16 GB of ram is a good value
#adding CFLAGS to enable CombiSanR and MSanR
CXXFLAGS=" -D COMBISAN_BENCH_SPEC=1" cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_ENABLE_RUNTIMES="compiler-rt;libcxx;libcxxabi" -DCMAKE_BUILD_TYPE=Release -GNinja -DLLVM_PARALLEL_LINK_JOBS=8  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF -DLIBCXXABI_USE_LLVM_UNWINDER=OFF ../llvm
ninja

cd ../../
