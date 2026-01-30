#!/usr/bin/env python3
import sys
import os.path
curdir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(curdir, 'infra'))

import infra

LLVM_DIR = os.path.join(curdir, 'llvm-project', 'build')

#ENV var. Notice that this raises an exception if they not defined.
#https://github.com/llvm/llvm-project/releases/download/llvmorg-20.1.0/llvm-project-20.1.0.src.tar.xz
CLEAN_LLVM_DIR = os.environ['CLEAN_LLVM_DIR']
SPEC_DIR = os.environ['SPEC_DIR']

# -fdelayed-template-parsing for 483.xalancbmk/523.xalancbmk_r to compile with LLVM/Clang 20
# -fwrapv-pointer for 445.gobmk to not get an assertion error. due to pointer wrap overflow UB
STD_CFLAGS = ["-g", "-Wno-int-conversion", "-fwrapv-pointer", "-fdelayed-template-parsing"]

ASAN_CFLAGS = ["-fsanitize=address"]
ASAN_LDFLAGS = ["-fsanitize=address"]

MSAN_CFLAGS = ["-fsanitize=memory"]
MSAN_LDFLAGS = ["-fsanitize=memory"]

#OSS-Fuzz flags for UB detection
UBSAN_CFLAGS = ["-fsanitize=float-cast-overflow,alignment,unsigned-integer-overflow,array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr", "-fno-sanitize-recover=float-cast-overflow,alignment,unsigned-integer-overflow,array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,returns-nonnull-attribute,shift,signed-integer-overflow,vla-bound,vptr"]
UBSAN_LDFLAGS = ["-fsanitize=float-cast-overflow,alignment,unsigned-integer-overflow,array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr", "-fno-sanitize-recover=float-cast-overflow,alignment,unsigned-integer-overflow,array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,returns-nonnull-attribute,shift,signed-integer-overflow,vla-bound,vptr"]

STD_LDFLAGS = ["-fuse-ld=lld"]

class Baseline(infra.Instance):
    name = 'baseline'
    def __init__(self, opt_level):
        self.name += "_" + opt_level
        self.opt = ["-" + opt_level]
    def configure(self, ctx):
        ctx.cc = LLVM_DIR + "/bin/clang"
        ctx.cxx = LLVM_DIR + "/bin/clang++"
        ctx.cflags += self.opt + STD_CFLAGS
        ctx.cxxflags += self.opt + STD_CFLAGS
        ctx.ldflags += STD_LDFLAGS

class CombiSan(infra.Instance):
    name = 'csan'
    def __init__(self, opt_level):
        self.name += "_" + opt_level
        self.opt = ["-" + opt_level]
    def configure(self, ctx):
        ctx.cc = LLVM_DIR + "/bin/clang"
        ctx.cxx = LLVM_DIR + "/bin/clang++"
        ctx.cflags += self.opt + STD_CFLAGS + ASAN_CFLAGS + UBSAN_CFLAGS
        ctx.cxxflags += self.opt + STD_CFLAGS + ASAN_CFLAGS + UBSAN_CFLAGS
        ctx.ldflags += STD_LDFLAGS + ASAN_LDFLAGS + UBSAN_LDFLAGS
    def prepare_run(self, ctx):
        ctx.runenv["ASAN_OPTIONS"] = "alloc_dealloc_mismatch=0:detect_odr_violation=0:detect_leaks=0"

class ASan(infra.Instance):
    name = 'asan'
    def __init__(self, opt_level):
        self.name += "_" + opt_level
        self.opt = ["-" + opt_level]
    def configure(self, ctx):
        ctx.cc = CLEAN_LLVM_DIR + "/bin/clang"
        ctx.cxx = CLEAN_LLVM_DIR + "/bin/clang++"
        ctx.cflags += self.opt + STD_CFLAGS + ASAN_CFLAGS
        ctx.cxxflags += self.opt + STD_CFLAGS + ASAN_CFLAGS
        ctx.ldflags += STD_LDFLAGS + ASAN_LDFLAGS
    def prepare_run(self, ctx):
        ctx.runenv["ASAN_OPTIONS"] = "alloc_dealloc_mismatch=0:detect_odr_violation=0:detect_leaks=0"

class MSan(infra.Instance):
    name = 'msan'
    def __init__(self, opt_level):
        self.name += "_" + opt_level
        self.opt = ["-" + opt_level]
    def configure(self, ctx):
        ctx.cc = CLEAN_LLVM_DIR + "/bin/clang"
        ctx.cxx = CLEAN_LLVM_DIR + "/bin/clang++"
        ctx.cflags += self.opt + STD_CFLAGS + MSAN_CFLAGS
        ctx.cxxflags += self.opt + STD_CFLAGS + MSAN_CFLAGS
        ctx.ldflags += STD_LDFLAGS + MSAN_LDFLAGS
    def prepare_run(self, ctx):
       ctx.runenv["MSAN_OPTIONS"] = "suppress_equal_pcs=0:halt_on_error=0:report_umrs=0"

class UBSan(infra.Instance):
    name = 'ubsan'
    def __init__(self, opt_level):
        self.name += "_" + opt_level
        self.opt = ["-" + opt_level]
    def configure(self, ctx):
        ctx.cc = CLEAN_LLVM_DIR + "/bin/clang"
        ctx.cxx = CLEAN_LLVM_DIR + "/bin/clang++"
        ctx.cflags += self.opt + STD_CFLAGS + UBSAN_CFLAGS
        ctx.cxxflags += self.opt + STD_CFLAGS + UBSAN_CFLAGS
        ctx.ldflags += STD_LDFLAGS + UBSAN_LDFLAGS

class CombiSanRecover(infra.Instance):
    name = 'csan-rec'
    def __init__(self, opt_level):
        self.name += "_" + opt_level
        self.opt = ["-" + opt_level]
    CFLAGS = ASAN_CFLAGS + ["-fsanitize-recover=address"]
    LDFLAGS = ASAN_LDFLAGS + ["-fsanitize-recover=address"]
    def configure(self, ctx):
        ctx.cc = LLVM_DIR + "/bin/clang"
        ctx.cxx = LLVM_DIR + "/bin/clang++"
        ctx.cflags += self.opt + STD_CFLAGS + self.CFLAGS
        ctx.cxxflags += self.opt + STD_CFLAGS + self.CFLAGS
        ctx.ldflags += STD_LDFLAGS + self.LDFLAGS
    def prepare_run(self, ctx):
        ctx.runenv["ASAN_OPTIONS"] = "suppress_equal_pcs=0:halt_on_error=0:alloc_dealloc_mismatch=0:detect_odr_violation=0:detect_leaks=0"

class MSanRecover(infra.Instance):
    name = 'msan-rec'
    def __init__(self, opt_level):
        self.name += "_" + opt_level
        self.opt = ["-" + opt_level]
    CFLAGS = MSAN_CFLAGS + ["-fsanitize-recover=memory"]
    LDFLAGS = MSAN_LDFLAGS + ["-fsanitize-recover=memory"]
    def configure(self, ctx):
        ctx.cc = LLVM_DIR + "/bin/clang"
        ctx.cxx = LLVM_DIR + "/bin/clang++"
        ctx.cflags += self.opt + STD_CFLAGS + self.CFLAGS
        ctx.cxxflags += self.opt + STD_CFLAGS + self.CFLAGS
        ctx.ldflags += STD_LDFLAGS + self.LDFLAGS
    def prepare_run(self, ctx):
       ctx.runenv["MSAN_OPTIONS"] = "suppress_equal_pcs=0:halt_on_error=0:report_umrs=0"

if __name__ == '__main__':
    setup = infra.Setup(__file__)

    #create both O0 and O2
    for opt in ["O0", "O2"]:
        setup.add_instance(Baseline(opt))
        setup.add_instance(CombiSan(opt))
        setup.add_instance(ASan(opt))
        setup.add_instance(MSan(opt))
        setup.add_instance(UBSan(opt))
        setup.add_instance(CombiSanRecover(opt))
        setup.add_instance(MSanRecover(opt))

    setup.add_target(infra.targets.SPEC2006(
        patches = ['asan'],
        source=os.path.join(SPEC_DIR, 'spec2006'),
        source_type='installed',
        force_cpu=0
    ))

    setup.add_target(infra.targets.SPEC2017(
        patches = ['asan'],
        source=os.path.join(SPEC_DIR, 'spec2017'),
        source_type='installed',
        default_benchmarks=["intrate_pure_c","intrate_pure_cpp", "fprate_pure_c","fprate_pure_cpp"],
        force_cpu=0
    ))


    setup.add_target(infra.targets.Juliet())

    setup.main()
