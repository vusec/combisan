if [ ! -f llvm-project-20.1.0.src.tar.xz ]; then
    wget https://github.com/llvm/llvm-project/releases/download/llvmorg-20.1.0/llvm-project-20.1.0.src.tar.xz
fi

if [ ! -d llvm-project-20.1.0.src/ ]; then
    tar -xf llvm-project-20.1.0.src.tar.xz
fi

#remove old builds
if [ -d llvm-project-20.1.0.src/build ]; then
    rm -rf llvm-project-20.1.0.src/build
fi

mkdir llvm-project-20.1.0.src/build
cd llvm-project-20.1.0.src/build

#cmake, consider lowering LLVM_PARALLEL_LINK_JOBS to not saturate RAM. One job per 16 GB of ram is a good value
cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_ENABLE_RUNTIMES="compiler-rt;libcxx;libcxxabi" -DCMAKE_BUILD_TYPE=Release -GNinja -DLLVM_PARALLEL_LINK_JOBS=8  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF -DLIBCXXABI_USE_LLVM_UNWINDER=OFF ../llvm
ninja

cd ../../
