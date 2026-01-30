//===- AddressSanitizer.cpp - memory error detector -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address basic correctness
// checker.
// Details of the algorithm:
//  https://github.com/google/sanitizers/wiki/AddressSanitizerAlgorithm
//
// FIXME: This sanitizer does not yet handle scalable vectors
//
//===----------------------------------------------------------------------===//
#include "llvm/Transforms/Instrumentation/AddressSanitizer.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/StackSafetyAnalysis.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/Demangle/ItaniumDemangle.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/EHPersonalities.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicsAArch64.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerOptions.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Instrumentation.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <queue>
#include <sstream>
#include <string>
#include <tuple>

using namespace llvm;

#define DEBUG_TYPE "asan"

// CombiSan: 3 -> 2
static const uint64_t kDefaultShadowScale = 2;
static const uint64_t kDefaultShadowOffset32 = 1ULL << 29;
static const uint64_t kDefaultShadowOffset64 = 1ULL << 44;
static const uint64_t kDynamicShadowSentinel =
    std::numeric_limits<uint64_t>::max();
static const uint64_t kSmallX86_64ShadowOffsetBase = 0x7FFFFFFF;  // < 2G.
static const uint64_t kSmallX86_64ShadowOffsetAlignMask = ~0xFFFULL;
static const uint64_t kLinuxKasan_ShadowOffset64 = 0xdffffc0000000000;
static const uint64_t kPPC64_ShadowOffset64 = 1ULL << 44;
static const uint64_t kSystemZ_ShadowOffset64 = 1ULL << 52;
static const uint64_t kMIPS_ShadowOffsetN32 = 1ULL << 29;
static const uint64_t kMIPS32_ShadowOffset32 = 0x0aaa0000;
static const uint64_t kMIPS64_ShadowOffset64 = 1ULL << 37;
static const uint64_t kAArch64_ShadowOffset64 = 1ULL << 36;
static const uint64_t kLoongArch64_ShadowOffset64 = 1ULL << 46;
static const uint64_t kRISCV64_ShadowOffset64 = kDynamicShadowSentinel;
static const uint64_t kFreeBSD_ShadowOffset32 = 1ULL << 30;
static const uint64_t kFreeBSD_ShadowOffset64 = 1ULL << 46;
static const uint64_t kFreeBSDAArch64_ShadowOffset64 = 1ULL << 47;
static const uint64_t kFreeBSDKasan_ShadowOffset64 = 0xdffff7c000000000;
static const uint64_t kNetBSD_ShadowOffset32 = 1ULL << 30;
static const uint64_t kNetBSD_ShadowOffset64 = 1ULL << 46;
static const uint64_t kNetBSDKasan_ShadowOffset64 = 0xdfff900000000000;
static const uint64_t kPS_ShadowOffset64 = 1ULL << 40;
static const uint64_t kWindowsShadowOffset32 = 3ULL << 28;
static const uint64_t kEmscriptenShadowOffset = 0;

// The shadow memory space is dynamically allocated.
static const uint64_t kWindowsShadowOffset64 = kDynamicShadowSentinel;

static const size_t kMinStackMallocSize = 1 << 6;   // 64B
static const size_t kMaxStackMallocSize = 1 << 16;  // 64K
static const uintptr_t kCurrentStackFrameMagic = 0x41B58AB3;
static const uintptr_t kRetiredStackFrameMagic = 0x45E0360E;

const char kAsanModuleCtorName[] = "asan.module_ctor";
const char kAsanModuleDtorName[] = "asan.module_dtor";
static const uint64_t kAsanCtorAndDtorPriority = 1;
// On Emscripten, the system needs more than one priorities for constructors.
static const uint64_t kAsanEmscriptenCtorAndDtorPriority = 50;
const char kAsanReportErrorTemplate[] = "__asan_report_";
const char kAsanRegisterGlobalsName[] = "__asan_register_globals";
const char kAsanUnregisterGlobalsName[] = "__asan_unregister_globals";
const char kAsanRegisterImageGlobalsName[] = "__asan_register_image_globals";
const char kAsanUnregisterImageGlobalsName[] =
    "__asan_unregister_image_globals";
const char kAsanRegisterElfGlobalsName[] = "__asan_register_elf_globals";
const char kAsanUnregisterElfGlobalsName[] = "__asan_unregister_elf_globals";
const char kAsanPoisonGlobalsName[] = "__asan_before_dynamic_init";
const char kAsanUnpoisonGlobalsName[] = "__asan_after_dynamic_init";
const char kAsanInitName[] = "__asan_init";
const char kAsanVersionCheckNamePrefix[] = "__asan_version_mismatch_check_v";
const char kAsanPtrCmp[] = "__sanitizer_ptr_cmp";
const char kAsanPtrSub[] = "__sanitizer_ptr_sub";
const char kAsanHandleNoReturnName[] = "__asan_handle_no_return";
static const int kMaxAsanStackMallocSizeClass = 10;
const char kAsanStackMallocNameTemplate[] = "__asan_stack_malloc_";
const char kAsanStackMallocAlwaysNameTemplate[] =
    "__asan_stack_malloc_always_";
const char kAsanStackFreeNameTemplate[] = "__asan_stack_free_";
const char kAsanGenPrefix[] = "___asan_gen_";
const char kODRGenPrefix[] = "__odr_asan_gen_";
const char kSanCovGenPrefix[] = "__sancov_gen_";
const char kAsanSetShadowPrefix[] = "__asan_set_shadow_";
const char kAsanPoisonStackMemoryName[] = "__asan_poison_stack_memory";
const char kAsanUnpoisonStackMemoryName[] = "__asan_unpoison_stack_memory";

// ASan version script has __asan_* wildcard. Triple underscore prevents a
// linker (gold) warning about attempting to export a local symbol.
const char kAsanGlobalsRegisteredFlagName[] = "___asan_globals_registered";

const char kAsanOptionDetectUseAfterReturn[] =
    "__asan_option_detect_stack_use_after_return";

const char kAsanShadowMemoryDynamicAddress[] =
    "__asan_shadow_memory_dynamic_address";

const char kAsanAllocaPoison[] = "__asan_alloca_poison";
const char kAsanAllocasUnpoison[] = "__asan_allocas_unpoison";

const char kAMDGPUAddressSharedName[] = "llvm.amdgcn.is.shared";
const char kAMDGPUAddressPrivateName[] = "llvm.amdgcn.is.private";
const char kAMDGPUBallotName[] = "llvm.amdgcn.ballot.i64";
const char kAMDGPUUnreachableName[] = "llvm.amdgcn.unreachable";

// Accesses sizes are powers of two: 1, 2, 4, 8, 16.
static const size_t kNumberOfAccessSizes = 5;

static const uint64_t kAllocaRzSize = 32;

// ASanAccessInfo implementation constants.
constexpr size_t kCompileKernelShift = 0;
constexpr size_t kCompileKernelMask = 0x1;
constexpr size_t kAccessSizeIndexShift = 1;
constexpr size_t kAccessSizeIndexMask = 0xf;
constexpr size_t kIsWriteShift = 5;
constexpr size_t kIsWriteMask = 0x1;

// Command-line flags.

static cl::opt<bool> ClEnableKasan(
    "asan-kernel", cl::desc("Enable KernelAddressSanitizer instrumentation"),
    cl::Hidden, cl::init(false));

static cl::opt<bool> ClRecover(
    "asan-recover",
    cl::desc("Enable recovery mode (continue-after-error)."),
    cl::Hidden, cl::init(false));

static cl::opt<bool> ClInsertVersionCheck(
    "asan-guard-against-version-mismatch",
    cl::desc("Guard against compiler/runtime version mismatch."), cl::Hidden,
    cl::init(true));

// This flag may need to be replaced with -f[no-]asan-reads.
static cl::opt<bool> ClInstrumentReads("asan-instrument-reads",
                                       cl::desc("instrument read instructions"),
                                       cl::Hidden, cl::init(true));

static cl::opt<bool> ClInstrumentWrites(
    "asan-instrument-writes", cl::desc("instrument write instructions"),
    cl::Hidden, cl::init(true));

static cl::opt<bool>
    ClUseStackSafety("asan-use-stack-safety", cl::Hidden, cl::init(true),
                     cl::Hidden, cl::desc("Use Stack Safety analysis results"),
                     cl::Optional);

static cl::opt<bool> ClInstrumentAtomics(
    "asan-instrument-atomics",
    cl::desc("instrument atomic instructions (rmw, cmpxchg)"), cl::Hidden,
    cl::init(true));

static cl::opt<bool>
    ClInstrumentByval("asan-instrument-byval",
                      cl::desc("instrument byval call arguments"), cl::Hidden,
                      cl::init(true));

static cl::opt<bool> ClAlwaysSlowPath(
    "asan-always-slow-path",
    cl::desc("use instrumentation with slow path for all accesses"), cl::Hidden,
    cl::init(false));

static cl::opt<bool> ClForceDynamicShadow(
    "asan-force-dynamic-shadow",
    cl::desc("Load shadow address into a local variable for each function"),
    cl::Hidden, cl::init(false));

static cl::opt<bool>
    ClWithIfunc("asan-with-ifunc",
                cl::desc("Access dynamic shadow through an ifunc global on "
                         "platforms that support this"),
                cl::Hidden, cl::init(true));

static cl::opt<bool> ClWithIfuncSuppressRemat(
    "asan-with-ifunc-suppress-remat",
    cl::desc("Suppress rematerialization of dynamic shadow address by passing "
             "it through inline asm in prologue."),
    cl::Hidden, cl::init(true));

// This flag limits the number of instructions to be instrumented
// in any given BB. Normally, this should be set to unlimited (INT_MAX),
// but due to http://llvm.org/bugs/show_bug.cgi?id=12652 we temporary
// set it to 10000.
static cl::opt<int> ClMaxInsnsToInstrumentPerBB(
    "asan-max-ins-per-bb", cl::init(10000),
    cl::desc("maximal number of instructions to instrument in any given BB"),
    cl::Hidden);

// This flag may need to be replaced with -f[no]asan-stack.
static cl::opt<bool> ClStack("asan-stack", cl::desc("Handle stack memory"),
                             cl::Hidden, cl::init(true));
static cl::opt<uint32_t> ClMaxInlinePoisoningSize(
    "asan-max-inline-poisoning-size",
    cl::desc(
        "Inline shadow poisoning for blocks up to the given size in bytes."),
    cl::Hidden, cl::init(64));

static cl::opt<AsanDetectStackUseAfterReturnMode> ClUseAfterReturn(
    "asan-use-after-return",
    cl::desc("Sets the mode of detection for stack-use-after-return."),
    cl::values(
        clEnumValN(AsanDetectStackUseAfterReturnMode::Never, "never",
                   "Never detect stack use after return."),
        clEnumValN(
            AsanDetectStackUseAfterReturnMode::Runtime, "runtime",
            "Detect stack use after return if "
            "binary flag 'ASAN_OPTIONS=detect_stack_use_after_return' is set."),
        clEnumValN(AsanDetectStackUseAfterReturnMode::Always, "always",
                   "Always detect stack use after return.")),
    cl::Hidden, cl::init(AsanDetectStackUseAfterReturnMode::Runtime));

static cl::opt<bool> ClRedzoneByvalArgs("asan-redzone-byval-args",
                                        cl::desc("Create redzones for byval "
                                                 "arguments (extra copy "
                                                 "required)"), cl::Hidden,
                                        cl::init(true));

static cl::opt<bool> ClUseAfterScope("asan-use-after-scope",
                                     cl::desc("Check stack-use-after-scope"),
                                     cl::Hidden, cl::init(false));

// This flag may need to be replaced with -f[no]asan-globals.
static cl::opt<bool> ClGlobals("asan-globals",
                               cl::desc("Handle global objects"), cl::Hidden,
                               cl::init(true));

static cl::opt<bool> ClInitializers("asan-initialization-order",
                                    cl::desc("Handle C++ initializer order"),
                                    cl::Hidden, cl::init(true));

static cl::opt<bool> ClInvalidPointerPairs(
    "asan-detect-invalid-pointer-pair",
    cl::desc("Instrument <, <=, >, >=, - with pointer operands"), cl::Hidden,
    cl::init(false));

static cl::opt<bool> ClInvalidPointerCmp(
    "asan-detect-invalid-pointer-cmp",
    cl::desc("Instrument <, <=, >, >= with pointer operands"), cl::Hidden,
    cl::init(false));

static cl::opt<bool> ClInvalidPointerSub(
    "asan-detect-invalid-pointer-sub",
    cl::desc("Instrument - operations with pointer operands"), cl::Hidden,
    cl::init(false));

static cl::opt<unsigned> ClRealignStack(
    "asan-realign-stack",
    cl::desc("Realign stack to the value of this flag (power of two)"),
    cl::Hidden, cl::init(32));

static cl::opt<int> ClInstrumentationWithCallsThreshold(
    "asan-instrumentation-with-call-threshold",
    cl::desc("If the function being instrumented contains more than "
             "this number of memory accesses, use callbacks instead of "
             "inline checks (-1 means never use callbacks)."),
    cl::Hidden, cl::init(7000));

static cl::opt<std::string> ClMemoryAccessCallbackPrefix(
    "asan-memory-access-callback-prefix",
    cl::desc("Prefix for memory access callbacks"), cl::Hidden,
    cl::init("__asan_"));

static cl::opt<bool> ClKasanMemIntrinCallbackPrefix(
    "asan-kernel-mem-intrinsic-prefix",
    cl::desc("Use prefix for memory intrinsics in KASAN mode"), cl::Hidden,
    cl::init(false));

static cl::opt<bool>
    ClInstrumentDynamicAllocas("asan-instrument-dynamic-allocas",
                               cl::desc("instrument dynamic allocas"),
                               cl::Hidden, cl::init(true));

static cl::opt<bool> ClSkipPromotableAllocas(
    "asan-skip-promotable-allocas",
    cl::desc("Do not instrument promotable allocas"), cl::Hidden,
    cl::init(true));

static cl::opt<AsanCtorKind> ClConstructorKind(
    "asan-constructor-kind",
    cl::desc("Sets the ASan constructor kind"),
    cl::values(clEnumValN(AsanCtorKind::None, "none", "No constructors"),
               clEnumValN(AsanCtorKind::Global, "global",
                          "Use global constructors")),
    cl::init(AsanCtorKind::Global), cl::Hidden);
// These flags allow to change the shadow mapping.
// The shadow mapping looks like
//    Shadow = (Mem >> scale) + offset

static cl::opt<int> ClMappingScale("asan-mapping-scale",
                                   cl::desc("scale of asan shadow mapping"),
                                   cl::Hidden, cl::init(0));

static cl::opt<uint64_t>
    ClMappingOffset("asan-mapping-offset",
                    cl::desc("offset of asan shadow mapping [EXPERIMENTAL]"),
                    cl::Hidden, cl::init(0));

// Optimization flags. Not user visible, used mostly for testing
// and benchmarking the tool.

static cl::opt<bool> ClOpt("asan-opt", cl::desc("Optimize instrumentation"),
                           cl::Hidden, cl::init(true));

static cl::opt<bool> ClOptimizeCallbacks("asan-optimize-callbacks",
                                         cl::desc("Optimize callbacks"),
                                         cl::Hidden, cl::init(false));

static cl::opt<bool> ClOptSameTemp(
    "asan-opt-same-temp", cl::desc("Instrument the same temp just once"),
    cl::Hidden, cl::init(true));

static cl::opt<bool> ClOptGlobals("asan-opt-globals",
                                  cl::desc("Don't instrument scalar globals"),
                                  cl::Hidden, cl::init(true));

static cl::opt<bool> ClOptStack(
    "asan-opt-stack", cl::desc("Don't instrument scalar stack variables"),
    cl::Hidden, cl::init(false));

static cl::opt<bool> ClDynamicAllocaStack(
    "asan-stack-dynamic-alloca",
    cl::desc("Use dynamic alloca to represent stack variables"), cl::Hidden,
    cl::init(true));

static cl::opt<uint32_t> ClForceExperiment(
    "asan-force-experiment",
    cl::desc("Force optimization experiment (for testing)"), cl::Hidden,
    cl::init(0));

static cl::opt<bool>
    ClUsePrivateAlias("asan-use-private-alias",
                      cl::desc("Use private aliases for global variables"),
                      cl::Hidden, cl::init(true));

static cl::opt<bool>
    ClUseOdrIndicator("asan-use-odr-indicator",
                      cl::desc("Use odr indicators to improve ODR reporting"),
                      cl::Hidden, cl::init(true));

static cl::opt<bool>
    ClUseGlobalsGC("asan-globals-live-support",
                   cl::desc("Use linker features to support dead "
                            "code stripping of globals"),
                   cl::Hidden, cl::init(true));

// This is on by default even though there is a bug in gold:
// https://sourceware.org/bugzilla/show_bug.cgi?id=19002
static cl::opt<bool>
    ClWithComdat("asan-with-comdat",
                 cl::desc("Place ASan constructors in comdat sections"),
                 cl::Hidden, cl::init(true));

static cl::opt<AsanDtorKind> ClOverrideDestructorKind(
    "asan-destructor-kind",
    cl::desc("Sets the ASan destructor kind. The default is to use the value "
             "provided to the pass constructor"),
    cl::values(clEnumValN(AsanDtorKind::None, "none", "No destructors"),
               clEnumValN(AsanDtorKind::Global, "global",
                          "Use global destructors")),
    cl::init(AsanDtorKind::Invalid), cl::Hidden);

// Debug flags.

static cl::opt<int> ClDebug("asan-debug", cl::desc("debug"), cl::Hidden,
                            cl::init(0));

static cl::opt<int> ClDebugStack("asan-debug-stack", cl::desc("debug stack"),
                                 cl::Hidden, cl::init(0));

static cl::opt<std::string> ClDebugFunc("asan-debug-func", cl::Hidden,
                                        cl::desc("Debug func"));

static cl::opt<int> ClDebugMin("asan-debug-min", cl::desc("Debug min inst"),
                               cl::Hidden, cl::init(-1));

static cl::opt<int> ClDebugMax("asan-debug-max", cl::desc("Debug max inst"),
                               cl::Hidden, cl::init(-1));

STATISTIC(NumInstrumentedReads, "Number of instrumented reads");
STATISTIC(NumInstrumentedWrites, "Number of instrumented writes");
STATISTIC(NumOptimizedAccessesToGlobalVar,
          "Number of optimized accesses to global vars");
STATISTIC(NumOptimizedAccessesToStackVar,
          "Number of optimized accesses to stack vars");

// Total number of loads provably not having UUM candidates
static uint64_t NumNoUUMLoads = 0;

// CombiSan program allocs map
std::map<std::string, std::string> ProgramAllocMap = {
  {"malloc", "asan_malloc_uninit"},
  {"calloc", "asan_calloc_uninit"},
  {"realloc", "asan_realloc_uninit"},
  {"reallocarray", "asan_reallocarray_uninit"},
  {"memalign", "asan_memalign_uninit"},
  {"__libc_memalign", "asan___libc_memalign_uninit"},
  {"aligned_alloc", "asan_aligned_alloc_uninit"},
  {"posix_memalign", "asan_posix_memalign_uninit"},
  {"valloc", "asan_valloc_uninit"},
  {"pvalloc", "asan_pvalloc_uninit"},
  {"_Znwm", "asan_new_uninit"},
  {"_Znam", "asan_new_arr_uninit"},
  {"_ZnwmRKSt9nothrow_t", "asan_new_thr_uninit"},
  {"_ZnamRKSt9nothrow_t", "asan_new_thr_arr_uninit"},
  {"_ZnwmSt11align_val_t", "asan_new_aln_uninit"},
  {"_ZnamSt11align_val_t", "asan_new_arr_aln_uninit"},
  {"_ZnwmSt11align_val_tRKSt9nothrow_t", "asan_new_thr_aln_uninit"},
  {"_ZnamSt11align_val_tRKSt9nothrow_t", "asan_new_thr_aln_arr_uninit"},
};

namespace {

/// This struct defines the shadow mapping using the rule:
///   shadow = (mem >> Scale) ADD-or-OR Offset.
/// If InGlobal is true, then
///   extern char __asan_shadow[];
///   shadow = (mem >> Scale) + &__asan_shadow
struct ShadowMapping {
  int Scale;
  uint64_t Offset;
  bool OrShadowOffset;
  bool InGlobal;
};

} // end anonymous namespace

static ShadowMapping getShadowMapping(const Triple &TargetTriple, int LongSize,
                                      bool IsKasan) {
  bool IsAndroid = TargetTriple.isAndroid();
  bool IsIOS = TargetTriple.isiOS() || TargetTriple.isWatchOS() ||
               TargetTriple.isDriverKit();
  bool IsMacOS = TargetTriple.isMacOSX();
  bool IsFreeBSD = TargetTriple.isOSFreeBSD();
  bool IsNetBSD = TargetTriple.isOSNetBSD();
  bool IsPS = TargetTriple.isPS();
  bool IsLinux = TargetTriple.isOSLinux();
  bool IsPPC64 = TargetTriple.getArch() == Triple::ppc64 ||
                 TargetTriple.getArch() == Triple::ppc64le;
  bool IsSystemZ = TargetTriple.getArch() == Triple::systemz;
  bool IsX86_64 = TargetTriple.getArch() == Triple::x86_64;
  bool IsMIPSN32ABI = TargetTriple.isABIN32();
  bool IsMIPS32 = TargetTriple.isMIPS32();
  bool IsMIPS64 = TargetTriple.isMIPS64();
  bool IsArmOrThumb = TargetTriple.isARM() || TargetTriple.isThumb();
  bool IsAArch64 = TargetTriple.getArch() == Triple::aarch64 ||
                   TargetTriple.getArch() == Triple::aarch64_be;
  bool IsLoongArch64 = TargetTriple.isLoongArch64();
  bool IsRISCV64 = TargetTriple.getArch() == Triple::riscv64;
  bool IsWindows = TargetTriple.isOSWindows();
  bool IsFuchsia = TargetTriple.isOSFuchsia();
  bool IsEmscripten = TargetTriple.isOSEmscripten();
  bool IsAMDGPU = TargetTriple.isAMDGPU();

  ShadowMapping Mapping;

  Mapping.Scale = kDefaultShadowScale;
  if (ClMappingScale.getNumOccurrences() > 0) {
    Mapping.Scale = ClMappingScale;
  }

  if (LongSize == 32) {
    if (IsAndroid)
      Mapping.Offset = kDynamicShadowSentinel;
    else if (IsMIPSN32ABI)
      Mapping.Offset = kMIPS_ShadowOffsetN32;
    else if (IsMIPS32)
      Mapping.Offset = kMIPS32_ShadowOffset32;
    else if (IsFreeBSD)
      Mapping.Offset = kFreeBSD_ShadowOffset32;
    else if (IsNetBSD)
      Mapping.Offset = kNetBSD_ShadowOffset32;
    else if (IsIOS)
      Mapping.Offset = kDynamicShadowSentinel;
    else if (IsWindows)
      Mapping.Offset = kWindowsShadowOffset32;
    else if (IsEmscripten)
      Mapping.Offset = kEmscriptenShadowOffset;
    else
      Mapping.Offset = kDefaultShadowOffset32;
  } else {  // LongSize == 64
    // Fuchsia is always PIE, which means that the beginning of the address
    // space is always available.
    if (IsFuchsia)
      Mapping.Offset = 0;
    else if (IsPPC64)
      Mapping.Offset = kPPC64_ShadowOffset64;
    else if (IsSystemZ)
      Mapping.Offset = kSystemZ_ShadowOffset64;
    else if (IsFreeBSD && IsAArch64)
        Mapping.Offset = kFreeBSDAArch64_ShadowOffset64;
    else if (IsFreeBSD && !IsMIPS64) {
      if (IsKasan)
        Mapping.Offset = kFreeBSDKasan_ShadowOffset64;
      else
        Mapping.Offset = kFreeBSD_ShadowOffset64;
    } else if (IsNetBSD) {
      if (IsKasan)
        Mapping.Offset = kNetBSDKasan_ShadowOffset64;
      else
        Mapping.Offset = kNetBSD_ShadowOffset64;
    } else if (IsPS)
      Mapping.Offset = kPS_ShadowOffset64;
    else if (IsLinux && IsX86_64) {
      if (IsKasan)
        Mapping.Offset = kLinuxKasan_ShadowOffset64;
      else
        Mapping.Offset = (kSmallX86_64ShadowOffsetBase &
                          (kSmallX86_64ShadowOffsetAlignMask << Mapping.Scale));
    } else if (IsWindows && IsX86_64) {
      Mapping.Offset = kWindowsShadowOffset64;
    } else if (IsMIPS64)
      Mapping.Offset = kMIPS64_ShadowOffset64;
    else if (IsIOS)
      Mapping.Offset = kDynamicShadowSentinel;
    else if (IsMacOS && IsAArch64)
      Mapping.Offset = kDynamicShadowSentinel;
    else if (IsAArch64)
      Mapping.Offset = kAArch64_ShadowOffset64;
    else if (IsLoongArch64)
      Mapping.Offset = kLoongArch64_ShadowOffset64;
    else if (IsRISCV64)
      Mapping.Offset = kRISCV64_ShadowOffset64;
    else if (IsAMDGPU)
      Mapping.Offset = (kSmallX86_64ShadowOffsetBase &
                        (kSmallX86_64ShadowOffsetAlignMask << Mapping.Scale));
    else
      Mapping.Offset = kDefaultShadowOffset64;
  }

  if (ClForceDynamicShadow) {
    Mapping.Offset = kDynamicShadowSentinel;
  }

  if (ClMappingOffset.getNumOccurrences() > 0) {
    Mapping.Offset = ClMappingOffset;
  }

  // OR-ing shadow offset if more efficient (at least on x86) if the offset
  // is a power of two, but on ppc64 and loongarch64 we have to use add since
  // the shadow offset is not necessarily 1/8-th of the address space.  On
  // SystemZ, we could OR the constant in a single instruction, but it's more
  // efficient to load it once and use indexed addressing.
  Mapping.OrShadowOffset = !IsAArch64 && !IsPPC64 && !IsSystemZ && !IsPS &&
                           !IsRISCV64 && !IsLoongArch64 &&
                           !(Mapping.Offset & (Mapping.Offset - 1)) &&
                           Mapping.Offset != kDynamicShadowSentinel;
  bool IsAndroidWithIfuncSupport =
      IsAndroid && !TargetTriple.isAndroidVersionLT(21);
  Mapping.InGlobal = ClWithIfunc && IsAndroidWithIfuncSupport && IsArmOrThumb;

  return Mapping;
}

namespace llvm {
void getAddressSanitizerParams(const Triple &TargetTriple, int LongSize,
                               bool IsKasan, uint64_t *ShadowBase,
                               int *MappingScale, bool *OrShadowOffset) {
  auto Mapping = getShadowMapping(TargetTriple, LongSize, IsKasan);
  *ShadowBase = Mapping.Offset;
  *MappingScale = Mapping.Scale;
  *OrShadowOffset = Mapping.OrShadowOffset;
}

ASanAccessInfo::ASanAccessInfo(int32_t Packed)
    : Packed(Packed),
      AccessSizeIndex((Packed >> kAccessSizeIndexShift) & kAccessSizeIndexMask),
      IsWrite((Packed >> kIsWriteShift) & kIsWriteMask),
      CompileKernel((Packed >> kCompileKernelShift) & kCompileKernelMask) {}

ASanAccessInfo::ASanAccessInfo(bool IsWrite, bool CompileKernel,
                               uint8_t AccessSizeIndex)
    : Packed((IsWrite << kIsWriteShift) +
             (CompileKernel << kCompileKernelShift) +
             (AccessSizeIndex << kAccessSizeIndexShift)),
      AccessSizeIndex(AccessSizeIndex), IsWrite(IsWrite),
      CompileKernel(CompileKernel) {}

} // namespace llvm

static uint64_t getRedzoneSizeForScale(int MappingScale) {
  // Redzone used for stack and globals is at least 32 bytes.
  // For scales 6 and 7, the redzone has to be 64 and 128 bytes respectively.
  return std::max(32U, 1U << MappingScale);
}

static uint64_t GetCtorAndDtorPriority(Triple &TargetTriple) {
  if (TargetTriple.isOSEmscripten()) {
    return kAsanEmscriptenCtorAndDtorPriority;
  } else {
    return kAsanCtorAndDtorPriority;
  }
}

static Twine genName(StringRef suffix) {
  return Twine(kAsanGenPrefix) + suffix;
}

namespace {
/// Helper RAII class to post-process inserted asan runtime calls during a
/// pass on a single Function. Upon end of scope, detects and applies the
/// required funclet OpBundle.
class RuntimeCallInserter {
  Function *OwnerFn = nullptr;
  bool TrackInsertedCalls = false;
  SmallVector<CallInst *> InsertedCalls;

public:
  RuntimeCallInserter(Function &Fn) : OwnerFn(&Fn) {
    if (Fn.hasPersonalityFn()) {
      auto Personality = classifyEHPersonality(Fn.getPersonalityFn());
      if (isScopedEHPersonality(Personality))
        TrackInsertedCalls = true;
    }
  }

  ~RuntimeCallInserter() {
    if (InsertedCalls.empty())
      return;
    assert(TrackInsertedCalls && "Calls were wrongly tracked");

    DenseMap<BasicBlock *, ColorVector> BlockColors = colorEHFunclets(*OwnerFn);
    for (CallInst *CI : InsertedCalls) {
      BasicBlock *BB = CI->getParent();
      assert(BB && "Instruction doesn't belong to a BasicBlock");
      assert(BB->getParent() == OwnerFn &&
             "Instruction doesn't belong to the expected Function!");

      ColorVector &Colors = BlockColors[BB];
      // funclet opbundles are only valid in monochromatic BBs.
      // Note that unreachable BBs are seen as colorless by colorEHFunclets()
      // and will be DCE'ed later.
      if (Colors.empty())
        continue;
      if (Colors.size() != 1) {
        OwnerFn->getContext().emitError(
            "Instruction's BasicBlock is not monochromatic");
        continue;
      }

      BasicBlock *Color = Colors.front();
      BasicBlock::iterator EHPadIt = Color->getFirstNonPHIIt();

      if (EHPadIt != Color->end() && EHPadIt->isEHPad()) {
        // Replace CI with a clone with an added funclet OperandBundle
        OperandBundleDef OB("funclet", &*EHPadIt);
        auto *NewCall = CallBase::addOperandBundle(CI, LLVMContext::OB_funclet,
                                                   OB, CI->getIterator());
        NewCall->copyMetadata(*CI);
        CI->replaceAllUsesWith(NewCall);
        CI->eraseFromParent();
      }
    }
  }

  CallInst *createRuntimeCall(IRBuilder<> &IRB, FunctionCallee Callee,
                              ArrayRef<Value *> Args = {},
                              const Twine &Name = "") {
    assert(IRB.GetInsertBlock()->getParent() == OwnerFn);

    CallInst *Inst = IRB.CreateCall(Callee, Args, Name, nullptr);
    if (TrackInsertedCalls)
      InsertedCalls.push_back(Inst);
    return Inst;
  }
};

/// AddressSanitizer: instrument the code in module to find memory bugs.
struct AddressSanitizer {
  AddressSanitizer(Module &M, const StackSafetyGlobalInfo *SSGI,
                   int InstrumentationWithCallsThreshold,
                   uint32_t MaxInlinePoisoningSize, bool CompileKernel = false,
                   bool Recover = false, bool UseAfterScope = false,
                   AsanDetectStackUseAfterReturnMode UseAfterReturn =
                       AsanDetectStackUseAfterReturnMode::Runtime)
      : M(M),
        CompileKernel(ClEnableKasan.getNumOccurrences() > 0 ? ClEnableKasan
                                                            : CompileKernel),
        Recover(ClRecover.getNumOccurrences() > 0 ? ClRecover : Recover),
        UseAfterScope(UseAfterScope || ClUseAfterScope),
        UseAfterReturn(ClUseAfterReturn.getNumOccurrences() ? ClUseAfterReturn
                                                            : UseAfterReturn),
        SSGI(SSGI),
        InstrumentationWithCallsThreshold(
            ClInstrumentationWithCallsThreshold.getNumOccurrences() > 0
                ? ClInstrumentationWithCallsThreshold
                : InstrumentationWithCallsThreshold),
        MaxInlinePoisoningSize(ClMaxInlinePoisoningSize.getNumOccurrences() > 0
                                   ? ClMaxInlinePoisoningSize
                                   : MaxInlinePoisoningSize) {
    C = &(M.getContext());
    DL = &M.getDataLayout();
    LongSize = M.getDataLayout().getPointerSizeInBits();
    IntptrTy = Type::getIntNTy(*C, LongSize);
    PtrTy = PointerType::getUnqual(*C);
    Int32Ty = Type::getInt32Ty(*C);
    TargetTriple = Triple(M.getTargetTriple());

    Mapping = getShadowMapping(TargetTriple, LongSize, this->CompileKernel);

    assert(this->UseAfterReturn != AsanDetectStackUseAfterReturnMode::Invalid);
  }

  TypeSize getAllocaSizeInBytes(const AllocaInst &AI) const {
    return *AI.getAllocationSize(AI.getDataLayout());
  }

  /// Check if we want (and can) handle this alloca.
  bool isInterestingAlloca(const AllocaInst &AI);

  bool ignoreAccess(Instruction *Inst, Value *Ptr, bool &SafeInteresting);
  void getInterestingMemoryOperands(
      Instruction *I, SmallVectorImpl<InterestingMemoryOperand> &Interesting,
      SmallVectorImpl<InterestingMemoryOperand> &SafeInteresting);

  void collectConstructorSites(SmallVector<CallBase *, 16> &ConstructorCalls, std::set<AllocaInst *> &ConstructorAllocas, const TargetLibraryInfo *TLI);

  void replaceProgramAllocs(SmallVector<CallBase *, 16> &ProgramAllocs);
  void instrumentIndirectCalls(SmallVector<CallBase *, 16> &IndirectCalls);

  void analyzeUUMs(SmallVectorImpl<InterestingMemoryOperand> &Ops);

  void instrumentMop(ObjectSizeOffsetVisitor &ObjSizeVis,
                     InterestingMemoryOperand &O, bool UseCalls,
                     const DataLayout &DL, RuntimeCallInserter &RTCI,
                     SmallVector<InterestingMemoryOperand, 16> &SafeOperandsToInstrument);
  void MarkAsInitialized(Instruction *InsertBefore, Value *Addr, MaybeAlign Alignment, uint32_t TypeStoreSize);

  void instrumentSafeMop(ObjectSizeOffsetVisitor &ObjSizeVis,
                      InterestingMemoryOperand &O, bool UseCalls,
                      const DataLayout &DL, RuntimeCallInserter &RTCI);
  void instrumentPointerComparisonOrSubtraction(Instruction *I,
                                                RuntimeCallInserter &RTCI);
  void instrumentAddress(Instruction *OrigIns, Instruction *InsertBefore,
                         Value *Addr, MaybeAlign Alignment,
                         uint32_t TypeStoreSize, bool IsWrite,
                         Value *SizeArgument, bool UseCalls, uint32_t Exp,
                         RuntimeCallInserter &RTCI, bool NoUum);
  Instruction *instrumentAMDGPUAddress(Instruction *OrigIns,
                                       Instruction *InsertBefore, Value *Addr,
                                       uint32_t TypeStoreSize, bool IsWrite,
                                       Value *SizeArgument);
  Instruction *genAMDGPUReportBlock(IRBuilder<> &IRB, Value *Cond,
                                    bool Recover);
  void instrumentUnusualSizeOrAlignment(Instruction *I,
                                        Instruction *InsertBefore, Value *Addr,
                                        TypeSize TypeStoreSize, bool IsWrite,
                                        Value *SizeArgument, bool UseCalls,
                                        uint32_t Exp,
                                        RuntimeCallInserter &RTCI,
                                        bool NoUum);
  void instrumentMaskedLoadOrStore(AddressSanitizer *Pass, const DataLayout &DL,
                                   Type *IntptrTy, Value *Mask, Value *EVL,
                                   Value *Stride, Instruction *I, Value *Addr,
                                   MaybeAlign Alignment, unsigned Granularity,
                                   Type *OpType, bool IsWrite,
                                   Value *SizeArgument, bool UseCalls,
                                   uint32_t Exp, RuntimeCallInserter &RTCI,
                                   bool NoUum);
  Value *createSlowPathCmp(IRBuilder<> &IRB, Value *AddrLong,
                           Value *ShadowValue, uint32_t TypeStoreSize);
  Instruction *generateCrashCode(Instruction *InsertBefore, Value *Addr,
                                 bool IsWrite, size_t AccessSizeIndex,
                                 Value *SizeArgument, uint32_t Exp,
                                 RuntimeCallInserter &RTCI);
  void instrumentMemIntrinsic(MemIntrinsic *MI, RuntimeCallInserter &RTCI);
  Value *memToShadow(Value *Shadow, IRBuilder<> &IRB);
  bool suppressInstrumentationSiteForDebug(int &Instrumented);
  bool instrumentFunction(Function &F, const TargetLibraryInfo *TLI);
  bool maybeInsertAsanInitAtFunctionEntry(Function &F);
  bool maybeInsertDynamicShadowAtFunctionEntry(Function &F);
  void markEscapedLocalAllocas(Function &F);

private:
  friend struct FunctionStackPoisoner;

  void initializeCallbacks(const TargetLibraryInfo *TLI);

  bool LooksLikeCodeInBug11395(Instruction *I);
  bool GlobalIsLinkerInitialized(GlobalVariable *G);
  bool isSafeAccess(ObjectSizeOffsetVisitor &ObjSizeVis, Value *Addr,
                    TypeSize TypeStoreSize) const;

  /// Helper to cleanup per-function state.
  struct FunctionStateRAII {
    AddressSanitizer *Pass;

    FunctionStateRAII(AddressSanitizer *Pass) : Pass(Pass) {
      assert(Pass->ProcessedAllocas.empty() &&
             "last pass forgot to clear cache");
      assert(!Pass->LocalDynamicShadow);
    }

    ~FunctionStateRAII() {
      Pass->LocalDynamicShadow = nullptr;
      Pass->ProcessedAllocas.clear();
    }
  };

  Module &M;
  LLVMContext *C;
  const DataLayout *DL;
  Triple TargetTriple;
  int LongSize;
  bool CompileKernel;
  bool Recover;
  bool UseAfterScope;
  AsanDetectStackUseAfterReturnMode UseAfterReturn;
  Type *IntptrTy;
  Type *Int32Ty;
  PointerType *PtrTy;
  ShadowMapping Mapping;
  FunctionCallee AsanHandleNoReturnFunc;
  FunctionCallee AsanPtrCmpFunction, AsanPtrSubFunction;
  Constant *AsanShadowGlobal;

  // These arrays is indexed by AccessIsWrite, Experiment and log2(AccessSize).
  FunctionCallee AsanErrorCallback[2][2][kNumberOfAccessSizes];
  FunctionCallee AsanMemoryAccessCallback[2][2][kNumberOfAccessSizes];

  // These arrays is indexed by AccessIsWrite and Experiment.
  FunctionCallee AsanErrorCallbackSized[2][2];
  FunctionCallee AsanMemoryAccessCallbackSized[2][2];

  FunctionCallee AsanMemmove, AsanMemcpy, AsanMemset;
  Value *LocalDynamicShadow = nullptr;
  const StackSafetyGlobalInfo *SSGI;
  DenseMap<const AllocaInst *, bool> ProcessedAllocas;

  FunctionCallee AMDGPUAddressShared;
  FunctionCallee AMDGPUAddressPrivate;
  int InstrumentationWithCallsThreshold;
  uint32_t MaxInlinePoisoningSize;

  FunctionCallee CombiSanInit; 
};

class ModuleAddressSanitizer {
public:
  ModuleAddressSanitizer(Module &M, bool InsertVersionCheck,
                         bool CompileKernel = false, bool Recover = false,
                         bool UseGlobalsGC = true, bool UseOdrIndicator = true,
                         AsanDtorKind DestructorKind = AsanDtorKind::Global,
                         AsanCtorKind ConstructorKind = AsanCtorKind::Global)
      : M(M),
        CompileKernel(ClEnableKasan.getNumOccurrences() > 0 ? ClEnableKasan
                                                            : CompileKernel),
        InsertVersionCheck(ClInsertVersionCheck.getNumOccurrences() > 0
                               ? ClInsertVersionCheck
                               : InsertVersionCheck),
        Recover(ClRecover.getNumOccurrences() > 0 ? ClRecover : Recover),
        UseGlobalsGC(UseGlobalsGC && ClUseGlobalsGC && !this->CompileKernel),
        // Enable aliases as they should have no downside with ODR indicators.
        UsePrivateAlias(ClUsePrivateAlias.getNumOccurrences() > 0
                            ? ClUsePrivateAlias
                            : UseOdrIndicator),
        UseOdrIndicator(ClUseOdrIndicator.getNumOccurrences() > 0
                            ? ClUseOdrIndicator
                            : UseOdrIndicator),
        // Not a typo: ClWithComdat is almost completely pointless without
        // ClUseGlobalsGC (because then it only works on modules without
        // globals, which are rare); it is a prerequisite for ClUseGlobalsGC;
        // and both suffer from gold PR19002 for which UseGlobalsGC constructor
        // argument is designed as workaround. Therefore, disable both
        // ClWithComdat and ClUseGlobalsGC unless the frontend says it's ok to
        // do globals-gc.
        UseCtorComdat(UseGlobalsGC && ClWithComdat && !this->CompileKernel),
        DestructorKind(DestructorKind),
        ConstructorKind(ClConstructorKind.getNumOccurrences() > 0
                            ? ClConstructorKind
                            : ConstructorKind) {
    C = &(M.getContext());
    int LongSize = M.getDataLayout().getPointerSizeInBits();
    IntptrTy = Type::getIntNTy(*C, LongSize);
    PtrTy = PointerType::getUnqual(*C);
    TargetTriple = Triple(M.getTargetTriple());
    Mapping = getShadowMapping(TargetTriple, LongSize, this->CompileKernel);

    if (ClOverrideDestructorKind != AsanDtorKind::Invalid)
      this->DestructorKind = ClOverrideDestructorKind;
    assert(this->DestructorKind != AsanDtorKind::Invalid);
  }

  bool instrumentModule();

private:
  void initializeCallbacks();

  void instrumentGlobals(IRBuilder<> &IRB, bool *CtorComdat);
  void InstrumentGlobalsCOFF(IRBuilder<> &IRB,
                             ArrayRef<GlobalVariable *> ExtendedGlobals,
                             ArrayRef<Constant *> MetadataInitializers);
  void instrumentGlobalsELF(IRBuilder<> &IRB,
                            ArrayRef<GlobalVariable *> ExtendedGlobals,
                            ArrayRef<Constant *> MetadataInitializers,
                            const std::string &UniqueModuleId);
  void InstrumentGlobalsMachO(IRBuilder<> &IRB,
                              ArrayRef<GlobalVariable *> ExtendedGlobals,
                              ArrayRef<Constant *> MetadataInitializers);
  void
  InstrumentGlobalsWithMetadataArray(IRBuilder<> &IRB,
                                     ArrayRef<GlobalVariable *> ExtendedGlobals,
                                     ArrayRef<Constant *> MetadataInitializers);

  GlobalVariable *CreateMetadataGlobal(Constant *Initializer,
                                       StringRef OriginalName);
  void SetComdatForGlobalMetadata(GlobalVariable *G, GlobalVariable *Metadata,
                                  StringRef InternalSuffix);
  Instruction *CreateAsanModuleDtor();

  const GlobalVariable *getExcludedAliasedGlobal(const GlobalAlias &GA) const;
  bool shouldInstrumentGlobal(GlobalVariable *G) const;
  bool ShouldUseMachOGlobalsSection() const;
  StringRef getGlobalMetadataSection() const;
  void poisonOneInitializer(Function &GlobalInit);
  void createInitializerPoisonCalls();
  uint64_t getMinRedzoneSizeForGlobal() const {
    return getRedzoneSizeForScale(Mapping.Scale);
  }
  uint64_t getRedzoneSizeForGlobal(uint64_t SizeInBytes) const;
  int GetAsanVersion() const;
  GlobalVariable *getOrCreateModuleName();

  Module &M;
  bool CompileKernel;
  bool InsertVersionCheck;
  bool Recover;
  bool UseGlobalsGC;
  bool UsePrivateAlias;
  bool UseOdrIndicator;
  bool UseCtorComdat;
  AsanDtorKind DestructorKind;
  AsanCtorKind ConstructorKind;
  Type *IntptrTy;
  PointerType *PtrTy;
  LLVMContext *C;
  Triple TargetTriple;
  ShadowMapping Mapping;
  FunctionCallee AsanPoisonGlobals;
  FunctionCallee AsanUnpoisonGlobals;
  FunctionCallee AsanRegisterGlobals;
  FunctionCallee AsanUnregisterGlobals;
  FunctionCallee AsanRegisterImageGlobals;
  FunctionCallee AsanUnregisterImageGlobals;
  FunctionCallee AsanRegisterElfGlobals;
  FunctionCallee AsanUnregisterElfGlobals;

  Function *AsanCtorFunction = nullptr;
  Function *AsanDtorFunction = nullptr;
  GlobalVariable *ModuleName = nullptr;
};

// Stack poisoning does not play well with exception handling.
// When an exception is thrown, we essentially bypass the code
// that unpoisones the stack. This is why the run-time library has
// to intercept __cxa_throw (as well as longjmp, etc) and unpoison the entire
// stack in the interceptor. This however does not work inside the
// actual function which catches the exception. Most likely because the
// compiler hoists the load of the shadow value somewhere too high.
// This causes asan to report a non-existing bug on 453.povray.
// It sounds like an LLVM bug.
struct FunctionStackPoisoner : public InstVisitor<FunctionStackPoisoner> {
  Function &F;
  AddressSanitizer &ASan;
  RuntimeCallInserter &RTCI;
  std::set<AllocaInst *> ConstructorAllocas;
  DIBuilder DIB;
  LLVMContext *C;
  Type *IntptrTy;
  Type *IntptrPtrTy;
  ShadowMapping Mapping;

  SmallVector<AllocaInst *, 16> AllocaVec;
  SmallVector<AllocaInst *, 16> StaticAllocasToMoveUp;
  SmallVector<Instruction *, 8> RetVec;

  // CombiSan: safe allocas
  SmallVector<AllocaInst *, 16> SafeAllocas;

  FunctionCallee AsanStackMallocFunc[kMaxAsanStackMallocSizeClass + 1],
      AsanStackFreeFunc[kMaxAsanStackMallocSizeClass + 1];
  FunctionCallee AsanSetShadowFunc[0x100] = {};
  FunctionCallee AsanPoisonStackMemoryFunc, AsanUnpoisonStackMemoryFunc;
  FunctionCallee AsanAllocaPoisonFunc, AsanAllocasUnpoisonFunc;

  // Stores a place and arguments of poisoning/unpoisoning call for alloca.
  struct AllocaPoisonCall {
    IntrinsicInst *InsBefore;
    AllocaInst *AI;
    uint64_t Size;
    bool DoPoison;
  };
  SmallVector<AllocaPoisonCall, 8> DynamicAllocaPoisonCallVec;
  SmallVector<AllocaPoisonCall, 8> StaticAllocaPoisonCallVec;
  bool HasUntracedLifetimeIntrinsic = false;

  SmallVector<AllocaInst *, 1> DynamicAllocaVec;
  SmallVector<IntrinsicInst *, 1> StackRestoreVec;
  AllocaInst *DynamicAllocaLayout = nullptr;
  IntrinsicInst *LocalEscapeCall = nullptr;

  bool HasInlineAsm = false;
  bool HasReturnsTwiceCall = false;
  bool PoisonStack;

  FunctionStackPoisoner(Function &F, AddressSanitizer &ASan,
                        RuntimeCallInserter &RTCI, std::set<AllocaInst *> &ConstructorAllocas)
      : F(F), ASan(ASan), RTCI(RTCI), ConstructorAllocas(ConstructorAllocas),
        DIB(*F.getParent(), /*AllowUnresolved*/ false), C(ASan.C),
        IntptrTy(ASan.IntptrTy),
        IntptrPtrTy(PointerType::get(IntptrTy->getContext(), 0)),
        Mapping(ASan.Mapping),
        PoisonStack(ClStack &&
                    !Triple(F.getParent()->getTargetTriple()).isAMDGPU()) {}

  bool runOnFunction() {
    if (!PoisonStack)
      return false;

    if (ClRedzoneByvalArgs)
      copyArgsPassedByValToAllocas();

    // Collect alloca, ret, lifetime instructions etc.
    for (BasicBlock *BB : depth_first(&F.getEntryBlock())) visit(*BB);

    if (AllocaVec.empty() && DynamicAllocaVec.empty() && SafeAllocas.empty()) return false;

    initializeCallbacks(*F.getParent());

    if (HasUntracedLifetimeIntrinsic) {
      // If there are lifetime intrinsics which couldn't be traced back to an
      // alloca, we may not know exactly when a variable enters scope, and
      // therefore should "fail safe" by not poisoning them.
      StaticAllocaPoisonCallVec.clear();
      DynamicAllocaPoisonCallVec.clear();
    }

    processDynamicAllocas();
    processStaticAllocas();

    if (ClDebugStack) {
      LLVM_DEBUG(dbgs() << F);
    }
    return true;
  }

  // Arguments marked with the "byval" attribute are implicitly copied without
  // using an alloca instruction.  To produce redzones for those arguments, we
  // copy them a second time into memory allocated with an alloca instruction.
  void copyArgsPassedByValToAllocas();

  // Finds all Alloca instructions and puts
  // poisoned red zones around all of them.
  // Then unpoison everything back before the function returns.
  void processStaticAllocas();
  void processDynamicAllocas();

  void createDynamicAllocasInitStorage();

  // ----------------------- Visitors.
  /// Collect all Ret instructions, or the musttail call instruction if it
  /// precedes the return instruction.
  void visitReturnInst(ReturnInst &RI) {
    if (CallInst *CI = RI.getParent()->getTerminatingMustTailCall())
      RetVec.push_back(CI);
    else
      RetVec.push_back(&RI);
  }

  /// Collect all Resume instructions.
  void visitResumeInst(ResumeInst &RI) { RetVec.push_back(&RI); }

  /// Collect all CatchReturnInst instructions.
  void visitCleanupReturnInst(CleanupReturnInst &CRI) { RetVec.push_back(&CRI); }

  void unpoisonDynamicAllocasBeforeInst(Instruction *InstBefore,
                                        Value *SavedStack) {
    IRBuilder<> IRB(InstBefore);
    Value *DynamicAreaPtr = IRB.CreatePtrToInt(SavedStack, IntptrTy);
    // When we insert _asan_allocas_unpoison before @llvm.stackrestore, we
    // need to adjust extracted SP to compute the address of the most recent
    // alloca. We have a special @llvm.get.dynamic.area.offset intrinsic for
    // this purpose.
    if (!isa<ReturnInst>(InstBefore)) {
      Value *DynamicAreaOffset = IRB.CreateIntrinsic(
          Intrinsic::get_dynamic_area_offset, {IntptrTy}, {});

      DynamicAreaPtr = IRB.CreateAdd(IRB.CreatePtrToInt(SavedStack, IntptrTy),
                                     DynamicAreaOffset);
    }

    RTCI.createRuntimeCall(
        IRB, AsanAllocasUnpoisonFunc,
        {IRB.CreateLoad(IntptrTy, DynamicAllocaLayout), DynamicAreaPtr});
  }

  // Unpoison dynamic allocas redzones.
  void unpoisonDynamicAllocas() {
    for (Instruction *Ret : RetVec)
      unpoisonDynamicAllocasBeforeInst(Ret, DynamicAllocaLayout);

    for (Instruction *StackRestoreInst : StackRestoreVec)
      unpoisonDynamicAllocasBeforeInst(StackRestoreInst,
                                       StackRestoreInst->getOperand(0));
  }

  // Deploy and poison redzones around dynamic alloca call. To do this, we
  // should replace this call with another one with changed parameters and
  // replace all its uses with new address, so
  //   addr = alloca type, old_size, align
  // is replaced by
  //   new_size = (old_size + additional_size) * sizeof(type)
  //   tmp = alloca i8, new_size, max(align, 32)
  //   addr = tmp + 32 (first 32 bytes are for the left redzone).
  // Additional_size is added to make new memory allocation contain not only
  // requested memory, but also left, partial and right redzones.
  void handleDynamicAllocaCall(AllocaInst *AI);

  /// Collect Alloca instructions we want (and can) handle.
  void visitAllocaInst(AllocaInst &AI) {

    if(AI.isStaticAlloca() && ASan.getAllocaSizeInBytes(AI) >= 4194304ULL ) // CombiSan: build time perf
      return;

    // FIXME: Handle scalable vectors instead of ignoring them.
    const Type *AllocaType = AI.getAllocatedType();
    const auto *STy = dyn_cast<StructType>(AllocaType);
    if (!ASan.isInterestingAlloca(AI) || isa<ScalableVectorType>(AllocaType) ||
        (STy && STy->containsHomogeneousScalableVectorTypes())) {
      
      // CombiSan: also track uninstrumented allocas for MSan
      SafeAllocas.push_back(&AI);

      if (AI.isStaticAlloca()) {
        // Skip over allocas that are present *before* the first instrumented
        // alloca, we don't want to move those around.
        if (AllocaVec.empty())
          return;

        StaticAllocasToMoveUp.push_back(&AI);
      }
      return;
    }

    if (!AI.isStaticAlloca()){
      DynamicAllocaVec.push_back(&AI);
    }
    else{
      AllocaVec.push_back(&AI);
    }
  }

  /// Collect lifetime intrinsic calls to check for use-after-scope
  /// errors.
  void visitIntrinsicInst(IntrinsicInst &II) {
    Intrinsic::ID ID = II.getIntrinsicID();
    if (ID == Intrinsic::stackrestore) StackRestoreVec.push_back(&II);
    if (ID == Intrinsic::localescape) LocalEscapeCall = &II;
    if (!ASan.UseAfterScope)
      return;
    if (!II.isLifetimeStartOrEnd())
      return;
    // Found lifetime intrinsic, add ASan instrumentation if necessary.
    auto *Size = cast<ConstantInt>(II.getArgOperand(0));
    // If size argument is undefined, don't do anything.
    if (Size->isMinusOne()) return;
    // Check that size doesn't saturate uint64_t and can
    // be stored in IntptrTy.
    const uint64_t SizeValue = Size->getValue().getLimitedValue();
    if (SizeValue == ~0ULL ||
        !ConstantInt::isValueValidForType(IntptrTy, SizeValue))
      return;
    // Find alloca instruction that corresponds to llvm.lifetime argument.
    // Currently we can only handle lifetime markers pointing to the
    // beginning of the alloca.
    AllocaInst *AI = findAllocaForValue(II.getArgOperand(1), true);
    if (!AI) {
      HasUntracedLifetimeIntrinsic = true;
      return;
    }
    // We're interested only in allocas we can handle.
    if (!ASan.isInterestingAlloca(*AI))
      return;
    bool DoPoison = (ID == Intrinsic::lifetime_end);
    AllocaPoisonCall APC = {&II, AI, SizeValue, DoPoison};
    if (AI->isStaticAlloca())
      StaticAllocaPoisonCallVec.push_back(APC);
    else if (ClInstrumentDynamicAllocas)
      DynamicAllocaPoisonCallVec.push_back(APC);
  }

  void visitCallBase(CallBase &CB) {
    if (CallInst *CI = dyn_cast<CallInst>(&CB)) {
      HasInlineAsm |= CI->isInlineAsm() && &CB != ASan.LocalDynamicShadow;
      HasReturnsTwiceCall |= CI->canReturnTwice();
    }
  }

  // ---------------------- Helpers.
  void initializeCallbacks(Module &M);

  // Copies bytes from ShadowBytes into shadow memory for indexes where
  // ShadowMask is not zero. If ShadowMask[i] is zero, we assume that
  // ShadowBytes[i] is constantly zero and doesn't need to be overwritten.
  void copyToShadow(ArrayRef<uint8_t> ShadowMask, ArrayRef<uint8_t> ShadowBytes,
                    IRBuilder<> &IRB, Value *ShadowBase);
  void copyToShadow(ArrayRef<uint8_t> ShadowMask, ArrayRef<uint8_t> ShadowBytes,
                    size_t Begin, size_t End, IRBuilder<> &IRB,
                    Value *ShadowBase);
  void copyToShadowInline(ArrayRef<uint8_t> ShadowMask,
                          ArrayRef<uint8_t> ShadowBytes, size_t Begin,
                          size_t End, IRBuilder<> &IRB, Value *ShadowBase);

  void poisonAlloca(Value *V, uint64_t Size, IRBuilder<> &IRB, bool DoPoison);

  Value *createAllocaForLayout(IRBuilder<> &IRB, const ASanStackFrameLayout &L,
                               bool Dynamic);
  PHINode *createPHI(IRBuilder<> &IRB, Value *Cond, Value *ValueIfTrue,
                     Instruction *ThenTerm, Value *ValueIfFalse);
};

} // end anonymous namespace

void AddressSanitizerPass::printPipeline(
    raw_ostream &OS, function_ref<StringRef(StringRef)> MapClassName2PassName) {
  static_cast<PassInfoMixin<AddressSanitizerPass> *>(this)->printPipeline(
      OS, MapClassName2PassName);
  OS << '<';
  if (Options.CompileKernel)
    OS << "kernel";
  OS << '>';
}

AddressSanitizerPass::AddressSanitizerPass(
    const AddressSanitizerOptions &Options, bool UseGlobalGC,
    bool UseOdrIndicator, AsanDtorKind DestructorKind,
    AsanCtorKind ConstructorKind)
    : Options(Options), UseGlobalGC(UseGlobalGC),
      UseOdrIndicator(UseOdrIndicator), DestructorKind(DestructorKind),
      ConstructorKind(ConstructorKind) {}

PreservedAnalyses AddressSanitizerPass::run(Module &M,
                                            ModuleAnalysisManager &MAM) {
  // Return early if nosanitize_address module flag is present for the module.
  // This implies that asan pass has already run before.
  if (checkIfAlreadyInstrumented(M, "nosanitize_address"))
    return PreservedAnalyses::all();

  // Dump IR before instrumentation
  std::string modname(M.getName());
  std::string              str;
  std::string              hash;
  llvm::raw_string_ostream rso(str);
  M.print(rso, nullptr, false, false);
  hash = std::to_string(std::hash<std::string>{}(str));
  modname += hash;
  std::error_code ec;
  llvm::raw_fd_ostream OS(modname + "-pre.txt", ec);
  M.print(OS, nullptr);

  ModuleAddressSanitizer ModuleSanitizer(
      M, Options.InsertVersionCheck, Options.CompileKernel, Options.Recover,
      UseGlobalGC, UseOdrIndicator, DestructorKind, ConstructorKind);
  bool Modified = false;
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  const StackSafetyGlobalInfo *const SSGI =
      ClUseStackSafety ? &MAM.getResult<StackSafetyGlobalAnalysis>(M) : nullptr;
  for (Function &F : M) {
    AddressSanitizer FunctionSanitizer(
        M, SSGI, Options.InstrumentationWithCallsThreshold,
        Options.MaxInlinePoisoningSize, Options.CompileKernel, Options.Recover,
        Options.UseAfterScope, Options.UseAfterReturn);
    const TargetLibraryInfo &TLI = FAM.getResult<TargetLibraryAnalysis>(F);
    Modified |= FunctionSanitizer.instrumentFunction(F, &TLI);
  }
  Modified |= ModuleSanitizer.instrumentModule();
  if (!Modified)
    return PreservedAnalyses::all();

  // Dump IR after instrumentation
  llvm::raw_fd_ostream OS2(/*currentDateTime() +*/ modname + "-post.txt", ec);
  M.print(OS2, nullptr);

  if(NumNoUUMLoads > 0){
    FILE* fp = fopen("/tmp/nouums.txt", "a");
    std::string CurrWorkPath = std::getenv("PWD");
    std::string FullFilename = CurrWorkPath + "/" + M.getSourceFileName();
    fprintf(fp, "%s %lu\n", FullFilename.c_str(), NumNoUUMLoads);
    fflush(fp);
    fclose(fp);
  }

  PreservedAnalyses PA = PreservedAnalyses::none();
  // GlobalsAA is considered stateless and does not get invalidated unless
  // explicitly invalidated; PreservedAnalyses::none() is not enough. Sanitizers
  // make changes that require GlobalsAA to be invalidated.
  PA.abandon<GlobalsAA>();
  return PA;
}

static size_t TypeStoreSizeToSizeIndex(uint32_t TypeSize) {
  size_t Res = llvm::countr_zero(TypeSize / 8);
  assert(Res < kNumberOfAccessSizes);
  return Res;
}

/// Check if \p G has been created by a trusted compiler pass.
static bool GlobalWasGeneratedByCompiler(GlobalVariable *G) {
  // Do not instrument @llvm.global_ctors, @llvm.used, etc.
  if (G->getName().starts_with("llvm.") ||
      // Do not instrument gcov counter arrays.
      G->getName().starts_with("__llvm_gcov_ctr") ||
      // Do not instrument rtti proxy symbols for function sanitizer.
      G->getName().starts_with("__llvm_rtti_proxy"))
    return true;

  // Do not instrument asan globals.
  if (G->getName().starts_with(kAsanGenPrefix) ||
      G->getName().starts_with(kSanCovGenPrefix) ||
      G->getName().starts_with(kODRGenPrefix))
    return true;

  return false;
}

static bool isUnsupportedAMDGPUAddrspace(Value *Addr) {
  Type *PtrTy = cast<PointerType>(Addr->getType()->getScalarType());
  unsigned int AddrSpace = PtrTy->getPointerAddressSpace();
  if (AddrSpace == 3 || AddrSpace == 5)
    return true;
  return false;
}

Value *AddressSanitizer::memToShadow(Value *Shadow, IRBuilder<> &IRB) {
  // Shadow >> scale
  Shadow = IRB.CreateLShr(Shadow, Mapping.Scale);
  if (Mapping.Offset == 0) return Shadow;
  // (Shadow >> scale) | offset
  Value *ShadowBase;
  if (LocalDynamicShadow)
    ShadowBase = LocalDynamicShadow;
  else
    ShadowBase = ConstantInt::get(IntptrTy, Mapping.Offset);
  if (Mapping.OrShadowOffset)
    return IRB.CreateOr(Shadow, ShadowBase);
  else
    return IRB.CreateAdd(Shadow, ShadowBase);
}

// Instrument memset/memmove/memcpy
void AddressSanitizer::instrumentMemIntrinsic(MemIntrinsic *MI,
                                              RuntimeCallInserter &RTCI) {
  InstrumentationIRBuilder IRB(MI);
  if (isa<MemTransferInst>(MI)) {
    RTCI.createRuntimeCall(
        IRB, isa<MemMoveInst>(MI) ? AsanMemmove : AsanMemcpy,
        {IRB.CreateAddrSpaceCast(MI->getOperand(0), PtrTy),
         IRB.CreateAddrSpaceCast(MI->getOperand(1), PtrTy),
         IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
  } else if (isa<MemSetInst>(MI)) {
    RTCI.createRuntimeCall(
        IRB, AsanMemset,
        {IRB.CreateAddrSpaceCast(MI->getOperand(0), PtrTy),
         IRB.CreateIntCast(MI->getOperand(1), IRB.getInt32Ty(), false),
         IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
  }
  MI->eraseFromParent();
}

/// Check if we want (and can) handle this alloca.
bool AddressSanitizer::isInterestingAlloca(const AllocaInst &AI) {
  auto PreviouslySeenAllocaInfo = ProcessedAllocas.find(&AI);

  if (PreviouslySeenAllocaInfo != ProcessedAllocas.end())
    return PreviouslySeenAllocaInfo->getSecond();

  bool IsInteresting =
      (AI.getAllocatedType()->isSized() &&
       // alloca() may be called with 0 size, ignore it.
       ((!AI.isStaticAlloca()) || !getAllocaSizeInBytes(AI).isZero()) &&
       // We are only interested in allocas not promotable to registers.
       // Promotable allocas are common under -O0.
       (!ClSkipPromotableAllocas || !isAllocaPromotable(&AI)) &&
       // inalloca allocas are not treated as static, and we don't want
       // dynamic alloca instrumentation for them as well.
       !AI.isUsedWithInAlloca() &&
       // swifterror allocas are register promoted by ISel
       !AI.isSwiftError() &&
       // safe allocas are not interesting
       !(SSGI && SSGI->isSafe(AI))
      );

  ProcessedAllocas[&AI] = IsInteresting;
  return IsInteresting;
}

bool AddressSanitizer::ignoreAccess(Instruction *Inst, Value *Ptr, bool &SafeInteresting) {
  // Instrument accesses from different address spaces only for AMDGPU.
  Type *PtrTy = cast<PointerType>(Ptr->getType()->getScalarType());
  if (PtrTy->getPointerAddressSpace() != 0 &&
      !(TargetTriple.isAMDGPU() && !isUnsupportedAMDGPUAddrspace(Ptr)))
    return true;

  // Ignore swifterror addresses.
  // swifterror memory addresses are mem2reg promoted by instruction
  // selection. As such they cannot have regular uses like an instrumentation
  // function and it makes no sense to track them as memory.
  if (Ptr->isSwiftError())
    return true;

  // Treat memory accesses to promotable allocas as non-interesting since they
  // will not cause memory violations. This greatly speeds up the instrumented
  // executable at -O0.
  if (auto AI = dyn_cast_or_null<AllocaInst>(Ptr)){
    if (ClSkipPromotableAllocas && !isInterestingAlloca(*AI)){
      // CombiSan: we need to track these (load/store?)
      SafeInteresting = true;
      return true;
    }
  }

  if (SSGI != nullptr && SSGI->stackAccessIsSafe(*Inst) &&
      findAllocaForValue(Ptr)){
    SafeInteresting = true;
    return true;
  }

  return false;
}

bool isVTablePointerLoad(LoadInst *load) {
  MDNode *tbaa = load->getMetadata(LLVMContext::MD_tbaa);
  if (!tbaa) return false;

  // check TBAA for "vtable pointer"
  if (auto *root = dyn_cast<MDNode>(tbaa->getOperand(0))) {
    if (auto *tag = dyn_cast<MDString>(root->getOperand(0))) {
      return tag->getString().contains("vtable pointer");
    }
  }
  return false;
}

void AddressSanitizer::getInterestingMemoryOperands(
    Instruction *I, SmallVectorImpl<InterestingMemoryOperand> &Interesting, SmallVectorImpl<InterestingMemoryOperand> &SafeInteresting) {
  // Do not instrument the load fetching the dynamic shadow address.
  if (LocalDynamicShadow == I)
    return;

  bool TrackSafeAccess = false;

  if (LoadInst *LI = dyn_cast<LoadInst>(I)) {

    // CombiSan: check if this is a vtable load, or loads from a GEP on vtable pointer
    // instrumentIndirectCalls() causes static devirtualization to break (I think)
    // because we introduce a hard runtime dependency on the function pointer
    // as a result, these kind of vtable loads cannot be optimized, but we can skip them
    // alternatively: set Op.NoUum = true; to still perform ASan checks if relevant
    if(isVTablePointerLoad(LI)){
      return;
    }
    if(auto *gep = dyn_cast<GetElementPtrInst>(LI->getPointerOperand())){
      Value *vtablePtr = gep->getPointerOperand();
        if (auto *vtableLoad = dyn_cast<LoadInst>(vtablePtr)) {
          if (isVTablePointerLoad(vtableLoad)) {
            return;
          }
        }
    }

#if 1 // CombiSan: we always need to instrument loads to check for MSan...
      if (!ClInstrumentReads ){
        return;
      }
#else
    if (!ClInstrumentReads || ignoreAccess(I, LI->getPointerOperand(), TrackSafeAccess)){
      if(TrackSafeAccess){
        SafeInteresting.emplace_back(I, LI->getPointerOperandIndex(), false, LI->getType(), LI->getAlign());
      }
      return;
    }
#endif
    Interesting.emplace_back(I, LI->getPointerOperandIndex(), false,
                             LI->getType(), LI->getAlign());
  } else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
    if (!ClInstrumentWrites || ignoreAccess(I, SI->getPointerOperand(), TrackSafeAccess)){
      if(TrackSafeAccess){
        SafeInteresting.emplace_back(I, SI->getPointerOperandIndex(), true, SI->getValueOperand()->getType(), SI->getAlign());
      }
      return;
    }
    Interesting.emplace_back(I, SI->getPointerOperandIndex(), true,
                             SI->getValueOperand()->getType(), SI->getAlign());
  } else if (AtomicRMWInst *RMW = dyn_cast<AtomicRMWInst>(I)) {
    if (!ClInstrumentAtomics || ignoreAccess(I, RMW->getPointerOperand(), TrackSafeAccess)){
      if(TrackSafeAccess){
        SafeInteresting.emplace_back(I, RMW->getPointerOperandIndex(), true, RMW->getValOperand()->getType(), std::nullopt);
      }
    }
    return;
    Interesting.emplace_back(I, RMW->getPointerOperandIndex(), true,
                             RMW->getValOperand()->getType(), std::nullopt);
  } else if (AtomicCmpXchgInst *XCHG = dyn_cast<AtomicCmpXchgInst>(I)) {
    if (!ClInstrumentAtomics || ignoreAccess(I, XCHG->getPointerOperand(), TrackSafeAccess)){
      if(TrackSafeAccess){
        SafeInteresting.emplace_back(I, XCHG->getPointerOperandIndex(), true, XCHG->getCompareOperand()->getType(), std::nullopt);
      }
      return;
    }
    Interesting.emplace_back(I, XCHG->getPointerOperandIndex(), true,
                             XCHG->getCompareOperand()->getType(),
                             std::nullopt);
  } else if (auto CI = dyn_cast<CallInst>(I)) {
    switch (CI->getIntrinsicID()) {
    case Intrinsic::masked_load:
    case Intrinsic::masked_store:
    case Intrinsic::masked_gather:
    case Intrinsic::masked_scatter: {
      bool IsWrite = CI->getType()->isVoidTy();
      // Masked store has an initial operand for the value.
      unsigned OpOffset = IsWrite ? 1 : 0;
      if (IsWrite ? !ClInstrumentWrites : !ClInstrumentReads)
        return;

      auto BasePtr = CI->getOperand(OpOffset);
      if (ignoreAccess(I, BasePtr, TrackSafeAccess))
        if(!TrackSafeAccess)
          return;
      Type *Ty = IsWrite ? CI->getArgOperand(0)->getType() : CI->getType();
      MaybeAlign Alignment = Align(1);
      // Otherwise no alignment guarantees. We probably got Undef.
      if (auto *Op = dyn_cast<ConstantInt>(CI->getOperand(1 + OpOffset)))
        Alignment = Op->getMaybeAlignValue();
      Value *Mask = CI->getOperand(2 + OpOffset);
      if(TrackSafeAccess)
        SafeInteresting.emplace_back(I, OpOffset, IsWrite, Ty, Alignment, Mask);
      else
        Interesting.emplace_back(I, OpOffset, IsWrite, Ty, Alignment, Mask);
      break;
    }
    case Intrinsic::masked_expandload:
    case Intrinsic::masked_compressstore: {
      bool IsWrite = CI->getIntrinsicID() == Intrinsic::masked_compressstore;
      unsigned OpOffset = IsWrite ? 1 : 0;
      if (IsWrite ? !ClInstrumentWrites : !ClInstrumentReads)
        return;
      auto BasePtr = CI->getOperand(OpOffset);
      if (ignoreAccess(I, BasePtr, TrackSafeAccess))
        if(!TrackSafeAccess)
          return;
      MaybeAlign Alignment = BasePtr->getPointerAlignment(*DL);
      Type *Ty = IsWrite ? CI->getArgOperand(0)->getType() : CI->getType();

      IRBuilder IB(I);
      Value *Mask = CI->getOperand(1 + OpOffset);
      // Use the popcount of Mask as the effective vector length.
      Type *ExtTy = VectorType::get(IntptrTy, cast<VectorType>(Ty));
      Value *ExtMask = IB.CreateZExt(Mask, ExtTy);
      Value *EVL = IB.CreateAddReduce(ExtMask);
      Value *TrueMask = ConstantInt::get(Mask->getType(), 1);
      if(TrackSafeAccess)
        SafeInteresting.emplace_back(I, OpOffset, IsWrite, Ty, Alignment, TrueMask, EVL);
      else
        Interesting.emplace_back(I, OpOffset, IsWrite, Ty, Alignment, TrueMask, EVL);
      break;
    }
    case Intrinsic::vp_load:
    case Intrinsic::vp_store:
    case Intrinsic::experimental_vp_strided_load:
    case Intrinsic::experimental_vp_strided_store: {
      auto *VPI = cast<VPIntrinsic>(CI);
      unsigned IID = CI->getIntrinsicID();
      bool IsWrite = CI->getType()->isVoidTy();
      if (IsWrite ? !ClInstrumentWrites : !ClInstrumentReads)
        return;
      unsigned PtrOpNo = *VPI->getMemoryPointerParamPos(IID);
      Type *Ty = IsWrite ? CI->getArgOperand(0)->getType() : CI->getType();
      MaybeAlign Alignment = VPI->getOperand(PtrOpNo)->getPointerAlignment(*DL);
      Value *Stride = nullptr;
      if (IID == Intrinsic::experimental_vp_strided_store ||
          IID == Intrinsic::experimental_vp_strided_load) {
        Stride = VPI->getOperand(PtrOpNo + 1);
        // Use the pointer alignment as the element alignment if the stride is a
        // mutiple of the pointer alignment. Otherwise, the element alignment
        // should be Align(1).
        unsigned PointerAlign = Alignment.valueOrOne().value();
        if (!isa<ConstantInt>(Stride) ||
            cast<ConstantInt>(Stride)->getZExtValue() % PointerAlign != 0)
          Alignment = Align(1);
      }
      Interesting.emplace_back(I, PtrOpNo, IsWrite, Ty, Alignment,
                               VPI->getMaskParam(), VPI->getVectorLengthParam(),
                               Stride);
      break;
    }
    case Intrinsic::vp_gather:
    case Intrinsic::vp_scatter: {
      auto *VPI = cast<VPIntrinsic>(CI);
      unsigned IID = CI->getIntrinsicID();
      bool IsWrite = IID == Intrinsic::vp_scatter;
      if (IsWrite ? !ClInstrumentWrites : !ClInstrumentReads)
        return;
      unsigned PtrOpNo = *VPI->getMemoryPointerParamPos(IID);
      Type *Ty = IsWrite ? CI->getArgOperand(0)->getType() : CI->getType();
      MaybeAlign Alignment = VPI->getPointerAlignment();
      Interesting.emplace_back(I, PtrOpNo, IsWrite, Ty, Alignment,
                               VPI->getMaskParam(),
                               VPI->getVectorLengthParam());
      break;
    }
    default:
      for (unsigned ArgNo = 0; ArgNo < CI->arg_size(); ArgNo++) {
        if (!ClInstrumentByval || !CI->isByValArgument(ArgNo))
         continue;
        if(ignoreAccess(I, CI->getArgOperand(ArgNo), TrackSafeAccess)){
            if(!TrackSafeAccess)
              continue;
        }
        Type *Ty = CI->getParamByValType(ArgNo);
        if(TrackSafeAccess)
          SafeInteresting.emplace_back(I, ArgNo, false, Ty, Align(1));
        else
          Interesting.emplace_back(I, ArgNo, false, Ty, Align(1));
      }
    }
  }
}

static bool isPointerOperand(Value *V) {
  return V->getType()->isPointerTy() || isa<PtrToIntInst>(V);
}

// This is a rough heuristic; it may cause both false positives and
// false negatives. The proper implementation requires cooperation with
// the frontend.
static bool isInterestingPointerComparison(Instruction *I) {
  if (ICmpInst *Cmp = dyn_cast<ICmpInst>(I)) {
    if (!Cmp->isRelational())
      return false;
  } else {
    return false;
  }
  return isPointerOperand(I->getOperand(0)) &&
         isPointerOperand(I->getOperand(1));
}

// This is a rough heuristic; it may cause both false positives and
// false negatives. The proper implementation requires cooperation with
// the frontend.
static bool isInterestingPointerSubtraction(Instruction *I) {
  if (BinaryOperator *BO = dyn_cast<BinaryOperator>(I)) {
    if (BO->getOpcode() != Instruction::Sub)
      return false;
  } else {
    return false;
  }
  return isPointerOperand(I->getOperand(0)) &&
         isPointerOperand(I->getOperand(1));
}

bool AddressSanitizer::GlobalIsLinkerInitialized(GlobalVariable *G) {
  // If a global variable does not have dynamic initialization we don't
  // have to instrument it.  However, if a global does not have initializer
  // at all, we assume it has dynamic initializer (in other TU).
  if (!G->hasInitializer())
    return false;

  if (G->hasSanitizerMetadata() && G->getSanitizerMetadata().IsDynInit)
    return false;

  return true;
}

void AddressSanitizer::instrumentPointerComparisonOrSubtraction(
    Instruction *I, RuntimeCallInserter &RTCI) {
  IRBuilder<> IRB(I);
  FunctionCallee F = isa<ICmpInst>(I) ? AsanPtrCmpFunction : AsanPtrSubFunction;
  Value *Param[2] = {I->getOperand(0), I->getOperand(1)};
  for (Value *&i : Param) {
    if (i->getType()->isPointerTy())
      i = IRB.CreatePointerCast(i, IntptrTy);
  }
  RTCI.createRuntimeCall(IRB, F, Param);
}

void AddressSanitizer::instrumentIndirectCalls(SmallVector<CallBase *, 16> &IndirectCalls){

  Type* VoidPtrTy = PointerType::getUnqual(M.getContext());
  FunctionCallee IndirectCallHandler = M.getOrInsertFunction("__combisan_ind_get_handler", VoidPtrTy, VoidPtrTy);

  // replace indirect calls with calls to the fn ptr __combisan_ind_get_handler() returns
  // malloc -> asan_malloc_uninit

  for(CallBase *CB : IndirectCalls){
    IRBuilder<> IRB(CB);
    Value *FuncPtrAsVoidPtr = IRB.CreateBitOrPointerCast(CB->getCalledOperand(), VoidPtrTy);
    auto *IndHandler = IRB.CreateCall(IndirectCallHandler, {FuncPtrAsVoidPtr});
    CB->setCalledOperand(IRB.CreateBitOrPointerCast(IndHandler, FuncPtrAsVoidPtr->getType()));
  }
}

void AddressSanitizer::replaceProgramAllocs(SmallVector<CallBase *, 16> &ProgramAllocs){
  for(CallBase *CB : ProgramAllocs){

    // errs() << "Program Alloc to replace: " << *CB << "\n";
    Function *calledFunc = CB->getCalledFunction();
    if(calledFunc && calledFunc->hasName()){
      std::string funcName = calledFunc->getName().str();

      auto it = ProgramAllocMap.find(funcName);
      if(it != ProgramAllocMap.end()){ // contained
        // errs() << "Key: " << it->first << " Corresponding: " << it->second;

        FunctionCallee NewProgramAlloc = M.getOrInsertFunction(it->second, calledFunc->getFunctionType());

        IRBuilder<> IRB(CB);
        std::vector<Value *> args;
        for (auto& arg : CB->args()) {
          args.push_back(arg);
        }

        SmallVector<OperandBundleDef, 1> OpBundles;
        CB->getOperandBundlesAsDefs(OpBundles);

        CallBase *NewCall;
        if (InvokeInst *II = dyn_cast<InvokeInst>(CB)) {
          NewCall = IRB.CreateInvoke(NewProgramAlloc, II->getNormalDest(), II->getUnwindDest(), args, OpBundles);
        }
        else{
          NewCall = IRB.CreateCall(NewProgramAlloc, args, OpBundles);
        }

        assert(NewCall);
        CB->replaceAllUsesWith(NewCall);
        CB->eraseFromParent();
      }
    }
  }
}

void AddressSanitizer::collectConstructorSites(SmallVector<CallBase *, 16> &ConstructorCalls, std::set<AllocaInst *> &ConstructorAllocas, const TargetLibraryInfo *TLI){

  for(CallBase *CB : ConstructorCalls){
    // errs() << "looking at CB: " << *CB << "\n";
    // first operand 'this' is memory allocation
    Value *Vthis = CB->getArgOperand(0)->stripPointerCastsAndAliases();
    if(AllocaInst *AI = dyn_cast<AllocaInst>(Vthis)){
      // errs() << "constructor alloc ALLOCA " << *AI << "\n";
      ConstructorAllocas.insert(AI);
    }
    else if(CallBase *CBalloc = dyn_cast<CallBase>(Vthis)){
      if (isMallocOrCallocLikeFn(CBalloc, TLI)){ // includes 'new'
        // errs() << "constructor alloc CALL " << *CBalloc << "\n";
        // this should be 'new' with a constant size (generally)
        Value *Vsize = CBalloc->getArgOperand(0)->stripPointerCastsAndAliases();

        // XXX: it would be better to introduce a different allocator for this
        // that applies ASan redzones but sets MSan to initialized
        // but we cannot just use 'calloc' or so, since then we get alloc-dealloc mismatches on delete
        // for now: undo the uninitialization
        IRBuilder<> IRB(CB);
        if(CBalloc->getNextNode()){
          // move init directly after the alloc if possible
          IRB.SetInsertPoint(CBalloc->getNextNode());
        }
        IRB.CreateCall(CombiSanInit, {CBalloc, Vsize}, "combisan.init.ctor");
      }
    }
  }
}

static bool isIntrinsicCandidateUUM(Intrinsic::ID IID){
  switch (IID) {
    case Intrinsic::masked_store:
    case Intrinsic::masked_load:
    case Intrinsic::masked_expandload:
    case Intrinsic::masked_compressstore:
    case Intrinsic::masked_gather:
    case Intrinsic::masked_scatter:
    case Intrinsic::x86_sse_stmxcsr:
    case Intrinsic::x86_sse_ldmxcsr:
    // VectorConvertIntrinsic
    case Intrinsic::x86_avx512_vcvtsd2usi64:
    case Intrinsic::x86_avx512_vcvtsd2usi32:
    case Intrinsic::x86_avx512_vcvtss2usi64:
    case Intrinsic::x86_avx512_vcvtss2usi32:
    case Intrinsic::x86_avx512_cvttss2usi64:
    case Intrinsic::x86_avx512_cvttss2usi:
    case Intrinsic::x86_avx512_cvttsd2usi64:
    case Intrinsic::x86_avx512_cvttsd2usi:
    case Intrinsic::x86_avx512_cvtusi2ss:
    case Intrinsic::x86_avx512_cvtusi642sd:
    case Intrinsic::x86_avx512_cvtusi642ss:
    case Intrinsic::x86_sse2_cvtsd2si64:
    case Intrinsic::x86_sse2_cvtsd2si:
    case Intrinsic::x86_sse2_cvtsd2ss:
    case Intrinsic::x86_sse2_cvttsd2si64:
    case Intrinsic::x86_sse2_cvttsd2si:
    case Intrinsic::x86_sse_cvtss2si64:
    case Intrinsic::x86_sse_cvtss2si:
    case Intrinsic::x86_sse_cvttss2si64:
    case Intrinsic::x86_sse_cvttss2si:
    case Intrinsic::x86_sse_cvtps2pi:
    case Intrinsic::x86_sse_cvttps2pi:
    // AVXMaskedStore
    case Intrinsic::x86_avx_maskstore_ps:
    case Intrinsic::x86_avx_maskstore_pd:
    case Intrinsic::x86_avx_maskstore_ps_256:
    case Intrinsic::x86_avx_maskstore_pd_256:
    case Intrinsic::x86_avx2_maskstore_d:
    case Intrinsic::x86_avx2_maskstore_q:
    case Intrinsic::x86_avx2_maskstore_d_256:
    case Intrinsic::x86_avx2_maskstore_q_256:
    // AVXMaskedLoad
    case Intrinsic::x86_avx_maskload_ps:
    case Intrinsic::x86_avx_maskload_pd:
    case Intrinsic::x86_avx_maskload_ps_256:
    case Intrinsic::x86_avx_maskload_pd_256:
    case Intrinsic::x86_avx2_maskload_d:
    case Intrinsic::x86_avx2_maskload_q:
    case Intrinsic::x86_avx2_maskload_d_256:
    case Intrinsic::x86_avx2_maskload_q_256:
    // NEONVectorStoreIntrinsic
    case Intrinsic::aarch64_neon_st1x2:
    case Intrinsic::aarch64_neon_st1x3:
    case Intrinsic::aarch64_neon_st1x4:
    case Intrinsic::aarch64_neon_st2:
    case Intrinsic::aarch64_neon_st3:
    case Intrinsic::aarch64_neon_st4: 
    case Intrinsic::aarch64_neon_st2lane:
    case Intrinsic::aarch64_neon_st3lane:
    case Intrinsic::aarch64_neon_st4lane:
      return true;
    default:
      break;
  }
  return false;
}

void AddressSanitizer::analyzeUUMs(SmallVectorImpl<InterestingMemoryOperand> &Ops){

  /*
    TODO: copy metadata on stores.
    In that case, store operations no longer count as sinks, they are safe.
    Because if the value ever gets loaded, it has the right uninit state.
    But this only applies if there are no other sinks for the load.
    i.e., a load with store-only sinks
  */

  for(auto &Op : Ops){
    // loads only
    if(Op.IsWrite) continue;

    // errs() << "Analyzing... " << *Op.getInsn() << "\n";
    Value *LoadedValue = Op.getInsn();

    std::queue<Value*> worklist;
    std::set<Value*> visited;

    worklist.push(LoadedValue);
    visited.insert(LoadedValue);

    bool sink = false;

    while(!worklist.empty()){
      Value *V = worklist.front();
      // errs() << "looking at: " << *V << "\n";
      if(!isa<Argument>(V))
        V = V->stripPointerCastsAndAliases();
      worklist.pop();
      for(Use &Use : V->uses()){
        User *U = Use.getUser();
        if(visited.insert(U).second) { // not seen before

          if(isa<LoadInst>(U)){
            // load on a loaded value: pointer dereference sink
            sink = true;
          }
          else if(isa<StoreInst>(U)){
            // store (to a) loaded value: pointer dereference sink
            // TODO: store copy propagation
            sink = true;
          }
          else if(CallBase *CB = dyn_cast<CallBase>(U)){
            // call using loaded value: inter-procedural check for sinks
            Function *calledFunc = CB->getCalledFunction();
            if (calledFunc && !calledFunc->isDeclaration()) {
              unsigned idx = CB->getArgOperandNo(&Use);
              Argument *arg = calledFunc->getArg(idx);
              // XXX: check this 
              // XXX: this would work better with LTO
              // explore 'arg', do not set this call as sink.
              if(arg){
                // worklist.push(arg);
                // errs() << "Value [" << *V << "] becomes arg [" << *arg << "]\n";
                // continue;

                // TODO: we need to 'continue' here to not mark the call as a sink,
                // but exploring the 'arg' seems to crash. inter-procedural problem?
              }
            }
            // cannot check call: sink
            sink = true;
          }
          else if(isa<BranchInst>(U)){
            // branch based on the loaded value: sink
            sink = true;
          }
          else if(ReturnInst *RI = dyn_cast<ReturnInst>(U)){
            // returning the loaded value: sink
            Value *RetVal = RI->getReturnValue();
            // function does not return a value: skip
            if(!RetVal)
              continue;
            if(auto *I = dyn_cast<BitCastInst>(RetVal)){
              RetVal = I->getOperand(0);
            }
            if(auto *I = dyn_cast<CallInst>(RetVal)){
              if(I->isMustTailCall())
                continue;
            }
            sink = true;
          }
          else if(ExtractElementInst *EEI = dyn_cast<ExtractElementInst>(U)){
            // sink on the second argument
            if(V == EEI->getOperand(1)){
              sink = true;
            }
          }
          else if(InsertElementInst *IEI = dyn_cast<InsertElementInst>(U)){
            // sink on the third argument
            if(V == IEI->getOperand(2)){
              sink = true;
            }
          }
          else if(IntrinsicInst *II = dyn_cast<IntrinsicInst>(U)){
            // TODO: some unhandled intrinsics are also sinks
            Intrinsic::ID IID = II->getIntrinsicID();
            if(isIntrinsicCandidateUUM(IID))
              sink = true;
            // annotations are not interesting
            else if(II->isAssumeLikeIntrinsic())
              continue;
          }
          else if(isa<AtomicRMWInst>(U)){
            sink = true;
          }
          else if(isa<AtomicCmpXchgInst>(U)){
            sink = true;
          }
          else if(BinaryOperator *BO = dyn_cast<BinaryOperator>(U)){
            // for integer div operations: sink on the second argument
            switch (BO->getOpcode()) {
              case Instruction::UDiv:
              case Instruction::SDiv:
              case Instruction::URem:
              case Instruction::SRem:
                if(V == BO->getOperand(1)){
                  sink = true;
                }
                break;
              default:
                break; // not of interest
            }
          }

          // other instructions: not a sink, check their uses
          worklist.push(U);

        }
      }
      // we can stop, static analysis sink
      if(sink) break;
    }

    // at the end: if there was no sink, we do not need to check for UUM
    if(!sink){
      // errs() << "Sinkless!-------- " << *Op.getInsn() << "\n";
      Op.NoUum = true;
    }
  }
}


static void doInstrumentAddress(AddressSanitizer *Pass, Instruction *I,
                                Instruction *InsertBefore, Value *Addr,
                                MaybeAlign Alignment, unsigned Granularity,
                                TypeSize TypeStoreSize, bool IsWrite,
                                Value *SizeArgument, bool UseCalls,
                                uint32_t Exp, RuntimeCallInserter &RTCI,
                                bool NoUum) {
  // Instrument a 1-, 2-, 4-, 8-, or 16- byte access with one check
  // if the data is properly aligned.
  if (!TypeStoreSize.isScalable()) {
    const auto FixedSize = TypeStoreSize.getFixedValue();
    switch (FixedSize) {
    case 8:
    case 16:
    case 32:
    case 64:
    case 128:
      if (!Alignment || *Alignment >= Granularity ||
          *Alignment >= FixedSize / 8)
        return Pass->instrumentAddress(I, InsertBefore, Addr, Alignment,
                                       FixedSize, IsWrite, nullptr, UseCalls,
                                       Exp, RTCI, NoUum);
    }
  }

  Pass->instrumentUnusualSizeOrAlignment(I, InsertBefore, Addr, TypeStoreSize,
                                         IsWrite, nullptr, UseCalls, Exp, RTCI, NoUum);
}

void AddressSanitizer::instrumentMaskedLoadOrStore(
    AddressSanitizer *Pass, const DataLayout &DL, Type *IntptrTy, Value *Mask,
    Value *EVL, Value *Stride, Instruction *I, Value *Addr,
    MaybeAlign Alignment, unsigned Granularity, Type *OpType, bool IsWrite,
    Value *SizeArgument, bool UseCalls, uint32_t Exp,
    RuntimeCallInserter &RTCI, bool NoUum) {
  auto *VTy = cast<VectorType>(OpType);
  TypeSize ElemTypeSize = DL.getTypeStoreSizeInBits(VTy->getScalarType());
  auto Zero = ConstantInt::get(IntptrTy, 0);

  IRBuilder IB(I);
  Instruction *LoopInsertBefore = I;
  if (EVL) {
    // The end argument of SplitBlockAndInsertForLane is assumed bigger
    // than zero, so we should check whether EVL is zero here.
    Type *EVLType = EVL->getType();
    Value *IsEVLZero = IB.CreateICmpNE(EVL, ConstantInt::get(EVLType, 0));
    LoopInsertBefore = SplitBlockAndInsertIfThen(IsEVLZero, I, false);
    IB.SetInsertPoint(LoopInsertBefore);
    // Cast EVL to IntptrTy.
    EVL = IB.CreateZExtOrTrunc(EVL, IntptrTy);
    // To avoid undefined behavior for extracting with out of range index, use
    // the minimum of evl and element count as trip count.
    Value *EC = IB.CreateElementCount(IntptrTy, VTy->getElementCount());
    EVL = IB.CreateBinaryIntrinsic(Intrinsic::umin, EVL, EC);
  } else {
    EVL = IB.CreateElementCount(IntptrTy, VTy->getElementCount());
  }

  // Cast Stride to IntptrTy.
  if (Stride)
    Stride = IB.CreateZExtOrTrunc(Stride, IntptrTy);

  SplitBlockAndInsertForEachLane(EVL, LoopInsertBefore->getIterator(),
                                 [&](IRBuilderBase &IRB, Value *Index) {
    Value *MaskElem = IRB.CreateExtractElement(Mask, Index);
    if (auto *MaskElemC = dyn_cast<ConstantInt>(MaskElem)) {
      if (MaskElemC->isZero())
        // No check
        return;
      // Unconditional check
    } else {
      // Conditional check
      Instruction *ThenTerm = SplitBlockAndInsertIfThen(
          MaskElem, &*IRB.GetInsertPoint(), false);
      IRB.SetInsertPoint(ThenTerm);
    }

    Value *InstrumentedAddress;
    if (isa<VectorType>(Addr->getType())) {
      assert(
          cast<VectorType>(Addr->getType())->getElementType()->isPointerTy() &&
          "Expected vector of pointer.");
      InstrumentedAddress = IRB.CreateExtractElement(Addr, Index);
    } else if (Stride) {
      Index = IRB.CreateMul(Index, Stride);
      InstrumentedAddress = IRB.CreatePtrAdd(Addr, Index);
    } else {
      InstrumentedAddress = IRB.CreateGEP(VTy, Addr, {Zero, Index});
    }
    doInstrumentAddress(Pass, I, &*IRB.GetInsertPoint(), InstrumentedAddress,
                        Alignment, Granularity, ElemTypeSize, IsWrite,
                        SizeArgument, UseCalls, Exp, RTCI, NoUum);
  });
}

void AddressSanitizer::MarkAsInitialized(Instruction *InsertBefore, Value *Addr, MaybeAlign Alignment, uint32_t TypeStoreSize){

  InstrumentationIRBuilder IRB(InsertBefore);
  Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);
  Type *ShadowTy = IntegerType::get(*C, 8U); // 1-byte
  Type *ShadowPtrTy = PointerType::get(*C, 8U);
  Value *ShadowPtrInt = memToShadow(AddrLong, IRB);
  const uint64_t ShadowAlign = std::max<uint64_t>(Alignment.valueOrOne().value() >> Mapping.Scale, 1);

  // TypeStoreSize is in # bits
  if(TypeStoreSize == 64){ // 8 bytes
    // here we can read 8 * 2bits = 16 bits = 2 bytes of shadow memory in one go
    ShadowTy = IntegerType::get(*C, 16U);
    ShadowPtrTy = PointerType::get(*C, 16U);
  }
  else if(TypeStoreSize == 128){ // 16 bytes (SSE/AVX)
    // here we can read 16 * 2bits = 32 bits = 4 bytes of shadow memory in one go
    ShadowTy = IntegerType::get(*C, 32U);
    ShadowPtrTy = PointerType::get(*C, 32U);
  }
  Value *ShadowPtr = IRB.CreateIntToPtr(ShadowPtrInt, ShadowPtrTy);

  // 1/2 byte stores we need a partial bit update
  if(TypeStoreSize == 8 || TypeStoreSize == 16){
    // here we cannot guarantee the complete shadow byte was zero
    // so we AND with the old value to clear the relevant bits

    // we just need to extract the offset: ptr & 0x3 and index with it
    // probably we can benchmark this by never setting the 0xaa bits
    Value *ShadowValue = IRB.CreateAlignedLoad(ShadowTy, ShadowPtr, Align(ShadowAlign));

    uint64_t ClearBitsMask = 0;
    if(TypeStoreSize == 16){ // 2 bytes
      ClearBitsMask = 5; // binary 0101
    }
    else{ // 1 byte
      ClearBitsMask = 1; // binary 01
    }

    // bit_offset = (ptr & 0x3) << 1; // eq: (ptr%4)*2
    Value *PtrOffset = IRB.CreateAnd(AddrLong, ConstantInt::get(IntptrTy, 0x3));
    Value *BitOffset = IRB.CreateShl(PtrOffset, ConstantInt::get(IntptrTy, 0x1));

    // shadow &= ~(ClearBitsMask << (((address & 3) << 1) + 1));
    // aka: shadow = shadow & ~(ClearBitsMask << BitOffset+1)
    BitOffset = IRB.CreateAdd(BitOffset, (ConstantInt::get(IntptrTy, 0x1)));

    Value *InitBitShifted = IRB.CreateShl(ConstantInt::get(IntptrTy, ClearBitsMask), BitOffset);
    // dont use CreateNeg because we want bitwise complement, not arithmetic negation
    Value *MSanMask = IRB.CreateXor(InitBitShifted, ConstantInt::get(IntptrTy, -1));

    MSanMask = IRB.CreateIntCast(MSanMask, ShadowTy, false); // match ShadowTy
    Value *NewShadowByte = IRB.CreateAnd(ShadowValue, MSanMask);
    IRB.CreateAlignedStore(NewShadowByte, ShadowPtr, Align(ShadowAlign));
  }
  // 4/8/16 byte stores we can update complete shadow bytes
  else{
    // clear all shadow bits
    Value *MSanInit = ConstantInt::get(ShadowTy, 0); 
    IRB.CreateAlignedStore(MSanInit, ShadowPtr, Align(ShadowAlign));
  }
}

void AddressSanitizer::instrumentSafeMop(ObjectSizeOffsetVisitor &ObjSizeVis,
  InterestingMemoryOperand &O, bool UseCalls,
  const DataLayout &DL,
  RuntimeCallInserter &RTCI) {

  // CombiSan: provably safe stores still need to update MSan init metadata
  Value *Addr = O.getPtr();

  Instruction *InsertBefore = O.getInsn();
  MaybeAlign Alignment = O.Alignment;
  unsigned Granularity = 1 << Mapping.Scale;
  TypeSize TypeStoreSize = O.TypeStoreSize;

  // Instrument a 1-, 2-, 4-, 8-, or 16- byte access with faster updates
  // if the data is properly aligned.
  if (!TypeStoreSize.isScalable()) {
    const auto FixedSize = TypeStoreSize.getFixedValue();
    switch (FixedSize) {
    case 8:
    case 16:
    case 32:
    case 64:
    case 128:
      if (!Alignment || *Alignment >= Granularity || *Alignment >= FixedSize / 8){
        // these accesses are provably safe, so there is no need to mask ASan's bits
        // the access is known to be a store
        MarkAsInitialized(InsertBefore, Addr, Alignment, FixedSize);
        return;
      }
    }
  }

  // for unusual sizes: use calls for simplicity to initialize MSan...
  // here these are stores only
  InstrumentationIRBuilder IRB(InsertBefore);
  Value *NumBits = IRB.CreateTypeSize(IntptrTy, TypeStoreSize);
  Value *Size = IRB.CreateLShr(NumBits, ConstantInt::get(IntptrTy, 3));
  //errs() << "[ASan] Unusual Size Or Alignment (store): " << *O.getInsn() << "\n";

  Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);
  RTCI.createRuntimeCall(IRB, AsanMemoryAccessCallbackSized[O.IsWrite][0], {AddrLong, Size});
}

void AddressSanitizer::instrumentMop(ObjectSizeOffsetVisitor &ObjSizeVis,
                                     InterestingMemoryOperand &O, bool UseCalls,
                                     const DataLayout &DL,
                                     RuntimeCallInserter &RTCI,
                                     SmallVector<InterestingMemoryOperand, 16> &SafeOperandsToInstrument) {
  Value *Addr = O.getPtr();

  // Optimization experiments.
  // The experiments can be used to evaluate potential optimizations that remove
  // instrumentation (assess false negatives). Instead of completely removing
  // some instrumentation, you set Exp to a non-zero value (mask of optimization
  // experiments that want to remove instrumentation of this instruction).
  // If Exp is non-zero, this pass will emit special calls into runtime
  // (e.g. __asan_report_exp_load1 instead of __asan_report_load1). These calls
  // make runtime terminate the program in a special way (with a different
  // exit status). Then you run the new compiler on a buggy corpus, collect
  // the special terminations (ideally, you don't see them at all -- no false
  // negatives) and make the decision on the optimization.
  uint32_t Exp = ClForceExperiment;

  if (ClOpt && ClOptGlobals) {
    // If initialization order checking is disabled, a simple access to a
    // dynamically initialized global is always valid.
    GlobalVariable *G = dyn_cast<GlobalVariable>(getUnderlyingObject(Addr));
    if (G && (!ClInitializers || GlobalIsLinkerInitialized(G)) &&
        isSafeAccess(ObjSizeVis, Addr, O.TypeStoreSize)) {
      NumOptimizedAccessesToGlobalVar++;
      // track for MSan
      if(O.IsWrite)
        SafeOperandsToInstrument.push_back(O);
      return;
    }
  }

  if (ClOpt && ClOptStack) {
    // A direct inbounds access to a stack variable is always valid.
    if (isa<AllocaInst>(getUnderlyingObject(Addr)) &&
        isSafeAccess(ObjSizeVis, Addr, O.TypeStoreSize)) {
      NumOptimizedAccessesToStackVar++;
      // track for MSan
      if(O.IsWrite)
        SafeOperandsToInstrument.push_back(O);
      return;
    }
  }

  if (O.IsWrite)
    NumInstrumentedWrites++;
  else
    NumInstrumentedReads++;

  unsigned Granularity = 1 << Mapping.Scale;
  if (O.MaybeMask) {
    instrumentMaskedLoadOrStore(this, DL, IntptrTy, O.MaybeMask, O.MaybeEVL,
                                O.MaybeStride, O.getInsn(), Addr, O.Alignment,
                                Granularity, O.OpType, O.IsWrite, nullptr,
                                UseCalls, Exp, RTCI, O.NoUum);
  } else {
    doInstrumentAddress(this, O.getInsn(), O.getInsn(), Addr, O.Alignment,
                        Granularity, O.TypeStoreSize, O.IsWrite, nullptr,
                        UseCalls, Exp, RTCI, O.NoUum);
  }
}

Instruction *AddressSanitizer::generateCrashCode(Instruction *InsertBefore,
                                                 Value *Addr, bool IsWrite,
                                                 size_t AccessSizeIndex,
                                                 Value *SizeArgument,
                                                 uint32_t Exp,
                                                 RuntimeCallInserter &RTCI) {
  InstrumentationIRBuilder IRB(InsertBefore);
  Value *ExpVal = Exp == 0 ? nullptr : ConstantInt::get(IRB.getInt32Ty(), Exp);
  CallInst *Call = nullptr;
  if (SizeArgument) {
    if (Exp == 0)
      Call = RTCI.createRuntimeCall(IRB, AsanErrorCallbackSized[IsWrite][0],
                                    {Addr, SizeArgument});
    else
      Call = RTCI.createRuntimeCall(IRB, AsanErrorCallbackSized[IsWrite][1],
                                    {Addr, SizeArgument, ExpVal});
  } else {
    if (Exp == 0)
      Call = RTCI.createRuntimeCall(
          IRB, AsanErrorCallback[IsWrite][0][AccessSizeIndex], Addr);
    else
      Call = RTCI.createRuntimeCall(
          IRB, AsanErrorCallback[IsWrite][1][AccessSizeIndex], {Addr, ExpVal});
  }

  Call->setCannotMerge();
  return Call;
}

Value *AddressSanitizer::createSlowPathCmp(IRBuilder<> &IRB, Value *AddrLong,
                                           Value *ShadowValue,
                                           uint32_t TypeStoreSize) {
#if 1 // CombiSan: new slow-check

  // XXX: double check the alignment here
  // i.e., does instrumentUnusualSizeOrAlignment's double 1-byte check guarantee
  // that a 2-byte access here never spans more than 1 shadow granule?
  // e.g., mis-aligning a 2-byte access to be 1 byte in bounds and 1 byte OOB
  // is not detected unless the address is aligned to the granularity
  // this is an issue originating from ASan, which has the same issue for
  // partially oob pointers that are not 8-byte aligned.

  // bit_offset = (ptr & 0x3) << 1; // eq: (ptr%4)*2
  Value *PtrAligned = IRB.CreateAnd(AddrLong, ConstantInt::get(IntptrTy, 0x3));
  Value *BitOffset = IRB.CreateShl(PtrAligned, ConstantInt::get(IntptrTy, 0x1));

  // zero extend the 8-bit shadow value to make sure we dont read junk when shifting
  Value *ShadowZext = IRB.CreateZExt(ShadowValue, IRB.getInt64Ty());

  // shadow value is now aligned to the corresponding pointer
  Value *ShadowShifted = IRB.CreateLShr(ShadowZext, BitOffset);

  // the selected shadow bits
  Value *ShadowSel;

  if(TypeStoreSize == 8){ // 1-byte
    // two_bit_val = (shadow >> bit_offset) & 0x3
    ShadowSel = IRB.CreateAnd(ShadowShifted, ConstantInt::get(IntptrTy, 0x3));
  }
  else if(TypeStoreSize == 16){ // 2-bytes
    // four_bit_val = (shadow >> bit_offset) & 0xF
    ShadowSel = IRB.CreateAnd(ShadowShifted, ConstantInt::get(IntptrTy, 0xF));
  }
  else{
    report_fatal_error("Unexpected slow path TypeStoreSize");
  }

  // if the selected shadow value == 0, it is valid
  return IRB.CreateIsNotNull(ShadowSel);

  // -------other check strategies (like BEXT)-------
  /*
  Value *PtrAligned = IRB.CreateAnd(AddrLong, ConstantInt::get(IntptrTy, 0x3));
  Value *BitOffset = IRB.CreateShl(PtrAligned, ConstantInt::get(IntptrTy, 0x1));
  // For the control operand, the low 8 bits are the offset and bits [15:8] are the length.
  // We want to extract 2 bits, so length = 2, which goes into bits [15:8]:
  Value *LengthPart = IRB.getInt32(2 << 8);
  Value *BitOffset32 = IRB.CreateIntCast(BitOffset, IRB.getInt32Ty(), false);
  Value *Control = IRB.CreateOr(BitOffset32, LengthPart);
  Value *ShadowValue32 = IRB.CreateIntCast(ShadowValue, IRB.getInt32Ty(), false);
  // BMI2: two_bit_val = _bextr_u32(shadow_value, (original_ptr & 0x3) << 1, 2); // x86_bmi_bextr_32 x86_tbm_bextri_u32
  Value *BEXT = IRB.CreateIntrinsic(IRB.getInt32Ty(), Intrinsic::x86_bmi_bextr_32, {ShadowValue32, Control});
  return IRB.CreateIsNotNull(BEXT);
  */
#else 
  size_t Granularity = static_cast<size_t>(1) << Mapping.Scale;
  // Addr & (Granularity - 1)
  Value *LastAccessedByte =
      IRB.CreateAnd(AddrLong, ConstantInt::get(IntptrTy, Granularity - 1));
  // (Addr & (Granularity - 1)) + size - 1
  if (TypeStoreSize / 8 > 1)
    LastAccessedByte = IRB.CreateAdd(
        LastAccessedByte, ConstantInt::get(IntptrTy, TypeStoreSize / 8 - 1));
  // (uint8_t) ((Addr & (Granularity-1)) + size - 1)
  LastAccessedByte =
      IRB.CreateIntCast(LastAccessedByte, ShadowValue->getType(), false);
  // ((uint8_t) ((Addr & (Granularity-1)) + size - 1)) >= ShadowValue
  return IRB.CreateICmpSGE(LastAccessedByte, ShadowValue);
#endif
}

Instruction *AddressSanitizer::instrumentAMDGPUAddress(
    Instruction *OrigIns, Instruction *InsertBefore, Value *Addr,
    uint32_t TypeStoreSize, bool IsWrite, Value *SizeArgument) {
  // Do not instrument unsupported addrspaces.
  if (isUnsupportedAMDGPUAddrspace(Addr))
    return nullptr;
  Type *PtrTy = cast<PointerType>(Addr->getType()->getScalarType());
  // Follow host instrumentation for global and constant addresses.
  if (PtrTy->getPointerAddressSpace() != 0)
    return InsertBefore;
  // Instrument generic addresses in supported addressspaces.
  IRBuilder<> IRB(InsertBefore);
  Value *IsShared = IRB.CreateCall(AMDGPUAddressShared, {Addr});
  Value *IsPrivate = IRB.CreateCall(AMDGPUAddressPrivate, {Addr});
  Value *IsSharedOrPrivate = IRB.CreateOr(IsShared, IsPrivate);
  Value *Cmp = IRB.CreateNot(IsSharedOrPrivate);
  Value *AddrSpaceZeroLanding =
      SplitBlockAndInsertIfThen(Cmp, InsertBefore, false);
  InsertBefore = cast<Instruction>(AddrSpaceZeroLanding);
  return InsertBefore;
}

Instruction *AddressSanitizer::genAMDGPUReportBlock(IRBuilder<> &IRB,
                                                    Value *Cond, bool Recover) {
  Module &M = *IRB.GetInsertBlock()->getModule();
  Value *ReportCond = Cond;
  if (!Recover) {
    auto Ballot = M.getOrInsertFunction(kAMDGPUBallotName, IRB.getInt64Ty(),
                                        IRB.getInt1Ty());
    ReportCond = IRB.CreateIsNotNull(IRB.CreateCall(Ballot, {Cond}));
  }

  auto *Trm =
      SplitBlockAndInsertIfThen(ReportCond, &*IRB.GetInsertPoint(), false,
                                MDBuilder(*C).createUnlikelyBranchWeights());
  Trm->getParent()->setName("asan.report");

  if (Recover)
    return Trm;

  Trm = SplitBlockAndInsertIfThen(Cond, Trm, false);
  IRB.SetInsertPoint(Trm);
  return IRB.CreateCall(
      M.getOrInsertFunction(kAMDGPUUnreachableName, IRB.getVoidTy()), {});
}

void AddressSanitizer::instrumentAddress(Instruction *OrigIns,
                                         Instruction *InsertBefore, Value *Addr,
                                         MaybeAlign Alignment,
                                         uint32_t TypeStoreSize, bool IsWrite,
                                         Value *SizeArgument, bool UseCalls,
                                         uint32_t Exp,
                                         RuntimeCallInserter &RTCI,
                                         bool NoUum) {
  if (TargetTriple.isAMDGPU()) {
    InsertBefore = instrumentAMDGPUAddress(OrigIns, InsertBefore, Addr,
                                           TypeStoreSize, IsWrite, SizeArgument);
    if (!InsertBefore)
      return;
  }

  InstrumentationIRBuilder IRB(InsertBefore);
  size_t AccessSizeIndex = TypeStoreSizeToSizeIndex(TypeStoreSize);

#if 1 // CombiSan: new standard check

  // for Store operations:
  // ASan: first check if the shadow is redzone (ASan-bits only!)
  // MSan: update the corresponding shadow bytes/bits to valid (0)
  // N.B.: loads implicitly check for both MSan and ASan validity with != 0
  // how do we only check if ASan's bits are set, while ignoring MSan's bits
  // clearly, we cannot check for zero due to MSan's bits
  // we also need to account for partial validity of the shadow granule
  // we AND with 0x55 (binary 01010101) to only select ASan's bits, and then the result must be non-zero.

  Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);
  Type *ShadowTy = IntegerType::get(*C, 8U); // 1-byte
  Type *ShadowPtrTy = PointerType::get(*C, 8U);
  Value *ShadowPtrInt = memToShadow(AddrLong, IRB);
  const uint64_t ShadowAlign = std::max<uint64_t>(Alignment.valueOrOne().value() >> Mapping.Scale, 1);
  bool GenSlowPath = (TypeStoreSize == 8 || TypeStoreSize == 16);
  Instruction *CrashTerm = nullptr;
  uint64_t StoreMask = 0x55; // b01010101 (ASan-only, 1 byte shadow)
  bool SkipMSan = (IsWrite || NoUum);

  if(NoUum){
  //   errs() << "[Tracking] Skipping MSan check (no sink) for: " << *OrigIns << "\n";
    NumNoUUMLoads++;
  }

  // TypeStoreSize is in # bits
  if(TypeStoreSize == 64){ // 8 bytes
    // here we can read 8 * 2bits = 16 bits = 2 bytes of shadow memory in one go
    ShadowTy = IntegerType::get(*C, 16U);
    ShadowPtrTy = PointerType::get(*C, 16U);
    StoreMask = 0x5555; // b0101010101010101 (ASan-only, 2 byte shadow)
  }
  else if(TypeStoreSize == 128){ // 16 bytes (SSE/AVX)
    // here we can read 16 * 2bits = 32 bits = 4 bytes of shadow memory in one go
    ShadowTy = IntegerType::get(*C, 32U);
    ShadowPtrTy = PointerType::get(*C, 32U);
    StoreMask = 0x55555555; // b01010101010101010101010101010101 (ASan-only, 4 byte shadow)
  }
  Value *ShadowPtr = IRB.CreateIntToPtr(ShadowPtrInt, ShadowPtrTy);
  Value *ShadowValue = IRB.CreateAlignedLoad(ShadowTy, ShadowPtr, Align(ShadowAlign));
  Value *ShadowValueMasked = nullptr;
  if(SkipMSan){
    // select ASan-only bits for stores / safe loads
    ShadowValueMasked = IRB.CreateAnd(ShadowValue, ConstantInt::get(ShadowTy, StoreMask));
  }

  // check if (masked) shadow value is zero (i.e., valid)
  Value *Cmp = ShadowValueMasked ? IRB.CreateIsNotNull(ShadowValueMasked) : IRB.CreateIsNotNull(ShadowValue);

  if (GenSlowPath) {
    // after fast-checking for *shadow==0, for 1 or 2 byte accesses we need to look at individual bits
    // uint8_t* shadow_ptr = (ptr >> 2) + BASE;
    // uint8_t shadow = *shadow_ptr;
    // if(shadow != 0){ // one of the bytes is invalid
    //    bit_offset = (ptr & 0x3) << 1; // eq: (ptr%4)*2
    //    two_bit_val = (shadow >> bit_offset) & 0x3
    //    if(two_bit_val != 0){
    //      error!
    //    }
    // }
    // We use branch weights for the slow path check, to indicate that the slow
    // path is rarely taken. This seems to be the case for SPEC benchmarks.
    Instruction *CheckTerm = SplitBlockAndInsertIfThen(
      Cmp, InsertBefore, false, MDBuilder(*C).createUnlikelyBranchWeights());
    assert(cast<BranchInst>(CheckTerm)->isUnconditional());
    BasicBlock *NextBB = CheckTerm->getSuccessor(0);
    IRB.SetInsertPoint(CheckTerm);
    Value *Cmp2 = createSlowPathCmp(IRB, AddrLong, ShadowValueMasked ? ShadowValueMasked : ShadowValue, TypeStoreSize);
    if (Recover) {
      CrashTerm = SplitBlockAndInsertIfThen(Cmp2, CheckTerm, false);
    } else {
      BasicBlock *CrashBlock =
        BasicBlock::Create(*C, "", NextBB->getParent(), NextBB);
      CrashTerm = new UnreachableInst(*C, CrashBlock);
      BranchInst *NewTerm = BranchInst::Create(CrashBlock, NextBB, Cmp2);
      ReplaceInstWithInst(CheckTerm, NewTerm);
    }
  }
  else{
    CrashTerm = SplitBlockAndInsertIfThen(Cmp, InsertBefore, !Recover);
  }

  Instruction *Crash = generateCrashCode(
    CrashTerm, AddrLong, IsWrite, AccessSizeIndex, SizeArgument, Exp, RTCI);
  if (OrigIns->getDebugLoc())
    Crash->setDebugLoc(OrigIns->getDebugLoc());

  // after ASan's check is done, we can update the MSan shadow metadata
  // if the access was operating on a redzone, it would have already faulted
  // so we are free to override ASan's shadow value at this point, because it must be 0
  // i.e., there is no need to OR the MSan shadow values in, unless its a partial shadow read
  if(IsWrite){
    // reset IRB
    IRB.SetInsertPoint(InsertBefore);

    // 1/2 byte stores we need a partial bit update
    if(GenSlowPath){
      // here we cannot guarantee the complete shadow byte was zero
      // so we AND with the old value to clear the relevant bits

      // TODO: Arm has the "Bit Field Insert" (BFI) instruction
      // TODO: what about a small lookup table where we precompute a lot
      // we just need to extract the offset: ptr & 0x3 and index with it
      // probably we can benchmark this by never setting the 0xaa bits

      uint64_t ClearBitsMask = 0;
      if(TypeStoreSize == 16){ // 2 bytes
        ClearBitsMask = 5; // binary 0101
      }
      else{ // 1 byte
        ClearBitsMask = 1; // binary 01
      }

      // bit_offset = (ptr & 0x3) << 1; // eq: (ptr%4)*2
      Value *PtrOffset = IRB.CreateAnd(AddrLong, ConstantInt::get(IntptrTy, 0x3));
      Value *BitOffset = IRB.CreateShl(PtrOffset, ConstantInt::get(IntptrTy, 0x1));

      // shadow &= ~(ClearBitsMask << (((address & 3) << 1) + 1));
      // aka: shadow = shadow & ~(ClearBitsMask << BitOffset+1)
      BitOffset = IRB.CreateAdd(BitOffset, (ConstantInt::get(IntptrTy, 0x1)));

      Value *InitBitShifted = IRB.CreateShl(ConstantInt::get(IntptrTy, ClearBitsMask), BitOffset);
      // dont use CreateNeg because we want bitwise complement, not arithmetic negation
      Value *MSanMask = IRB.CreateXor(InitBitShifted, ConstantInt::get(IntptrTy, -1));

      MSanMask = IRB.CreateIntCast(MSanMask, ShadowTy, false); // match ShadowTy
      Value *NewShadowByte = IRB.CreateAnd(ShadowValue, MSanMask);
      IRB.CreateAlignedStore(NewShadowByte, ShadowPtr, Align(ShadowAlign));
    }
    // 4/8/16 byte stores we can update complete shadow bytes
    else{
      // clear all shadow bits (ASan bits are already valid here)
      Value *MSanInit = ConstantInt::get(ShadowTy, 0); 
      IRB.CreateAlignedStore(MSanInit, ShadowPtr, Align(ShadowAlign));
    }
  }

#else 
  if (UseCalls && ClOptimizeCallbacks) {
    const ASanAccessInfo AccessInfo(IsWrite, CompileKernel, AccessSizeIndex);
    IRB.CreateIntrinsic(Intrinsic::asan_check_memaccess, {},
                        {IRB.CreatePointerCast(Addr, PtrTy),
                         ConstantInt::get(Int32Ty, AccessInfo.Packed)});
    return;
  }

  Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);
  if (UseCalls) {
    if (Exp == 0)
      RTCI.createRuntimeCall(
          IRB, AsanMemoryAccessCallback[IsWrite][0][AccessSizeIndex], AddrLong);
    else
      RTCI.createRuntimeCall(
          IRB, AsanMemoryAccessCallback[IsWrite][1][AccessSizeIndex],
          {AddrLong, ConstantInt::get(IRB.getInt32Ty(), Exp)});
    return;
  }

  Type *ShadowTy =
      IntegerType::get(*C, std::max(8U, TypeStoreSize >> Mapping.Scale));
  Type *ShadowPtrTy = PointerType::get(*C, 0);
  Value *ShadowPtr = memToShadow(AddrLong, IRB);
  const uint64_t ShadowAlign =
      std::max<uint64_t>(Alignment.valueOrOne().value() >> Mapping.Scale, 1);
  Value *ShadowValue = IRB.CreateAlignedLoad(
      ShadowTy, IRB.CreateIntToPtr(ShadowPtr, ShadowPtrTy), Align(ShadowAlign));

  Value *Cmp = IRB.CreateIsNotNull(ShadowValue);
  size_t Granularity = 1ULL << Mapping.Scale;
  Instruction *CrashTerm = nullptr;

  bool GenSlowPath = (ClAlwaysSlowPath || (TypeStoreSize < 8 * Granularity));

  if (TargetTriple.isAMDGCN()) {
    if (GenSlowPath) {
      auto *Cmp2 = createSlowPathCmp(IRB, AddrLong, ShadowValue, TypeStoreSize);
      Cmp = IRB.CreateAnd(Cmp, Cmp2);
    }
    CrashTerm = genAMDGPUReportBlock(IRB, Cmp, Recover);
  } else if (GenSlowPath) {
    // We use branch weights for the slow path check, to indicate that the slow
    // path is rarely taken. This seems to be the case for SPEC benchmarks.
    Instruction *CheckTerm = SplitBlockAndInsertIfThen(
        Cmp, InsertBefore, false, MDBuilder(*C).createUnlikelyBranchWeights());
    assert(cast<BranchInst>(CheckTerm)->isUnconditional());
    BasicBlock *NextBB = CheckTerm->getSuccessor(0);
    IRB.SetInsertPoint(CheckTerm);
    Value *Cmp2 = createSlowPathCmp(IRB, AddrLong, ShadowValue, TypeStoreSize);
    if (Recover) {
      CrashTerm = SplitBlockAndInsertIfThen(Cmp2, CheckTerm, false);
    } else {
      BasicBlock *CrashBlock =
        BasicBlock::Create(*C, "", NextBB->getParent(), NextBB);
      CrashTerm = new UnreachableInst(*C, CrashBlock);
      BranchInst *NewTerm = BranchInst::Create(CrashBlock, NextBB, Cmp2);
      ReplaceInstWithInst(CheckTerm, NewTerm);
    }
  } else {
    CrashTerm = SplitBlockAndInsertIfThen(Cmp, InsertBefore, !Recover);
  }

  Instruction *Crash = generateCrashCode(
      CrashTerm, AddrLong, IsWrite, AccessSizeIndex, SizeArgument, Exp, RTCI);
  if (OrigIns->getDebugLoc())
    Crash->setDebugLoc(OrigIns->getDebugLoc());
#endif
}

// Instrument unusual size or unusual alignment.
// We can not do it with a single check, so we do 1-byte check for the first
// and the last bytes. We call __asan_report_*_n(addr, real_size) to be able
// to report the actual access size.
void AddressSanitizer::instrumentUnusualSizeOrAlignment(
    Instruction *I, Instruction *InsertBefore, Value *Addr,
    TypeSize TypeStoreSize, bool IsWrite, Value *SizeArgument, bool UseCalls,
    uint32_t Exp, RuntimeCallInserter &RTCI, bool NoUum) {
  InstrumentationIRBuilder IRB(InsertBefore);
  Value *NumBits = IRB.CreateTypeSize(IntptrTy, TypeStoreSize);
  Value *Size = IRB.CreateLShr(NumBits, ConstantInt::get(IntptrTy, 3));
  //errs() << "[ASan] Unusual Size Or Alignment: " << *I << "\n";

  Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);
#if 1 // CombiSan
  // for unusual sizes: use calls for simplicity to initialize MSan...
  // we also need to check these bytes for being valid (ASan+MSan)
  // stores do calls to update the init state (all bytes), and loads do first & last checks like ASan
  if(IsWrite){
    RTCI.createRuntimeCall(IRB, AsanMemoryAccessCallbackSized[IsWrite][0], {AddrLong, Size});
  }
  else{
    Value *SizeMinusOne = IRB.CreateSub(Size, ConstantInt::get(IntptrTy, 1));
    Value *LastByte = IRB.CreateIntToPtr(
        IRB.CreateAdd(AddrLong, SizeMinusOne),
        Addr->getType());
    // do not pass SizeArgument to avoid confusing error generation as if this is an N-byte access
    // on the bad address
    instrumentAddress(I, InsertBefore, Addr, {}, 8, IsWrite, nullptr, false, Exp,
                      RTCI, NoUum);
    instrumentAddress(I, InsertBefore, LastByte, {}, 8, IsWrite, nullptr, false,
                      Exp, RTCI, NoUum);
  }
#else
  if (UseCalls) {
    if (Exp == 0)
      RTCI.createRuntimeCall(IRB, AsanMemoryAccessCallbackSized[IsWrite][0],
                             {AddrLong, Size});
    else
      RTCI.createRuntimeCall(
          IRB, AsanMemoryAccessCallbackSized[IsWrite][1],
          {AddrLong, Size, ConstantInt::get(IRB.getInt32Ty(), Exp)});
  } else {
    Value *SizeMinusOne = IRB.CreateSub(Size, ConstantInt::get(IntptrTy, 1));
    Value *LastByte = IRB.CreateIntToPtr(
        IRB.CreateAdd(AddrLong, SizeMinusOne),
        Addr->getType());
    instrumentAddress(I, InsertBefore, Addr, {}, 8, IsWrite, Size, false, Exp,
                      RTCI);
    instrumentAddress(I, InsertBefore, LastByte, {}, 8, IsWrite, Size, false,
                      Exp, RTCI);
  }
#endif
}

void ModuleAddressSanitizer::poisonOneInitializer(Function &GlobalInit) {
  // Set up the arguments to our poison/unpoison functions.
  IRBuilder<> IRB(&GlobalInit.front(),
                  GlobalInit.front().getFirstInsertionPt());

  // Add a call to poison all external globals before the given function starts.
  Value *ModuleNameAddr =
      ConstantExpr::getPointerCast(getOrCreateModuleName(), IntptrTy);
  IRB.CreateCall(AsanPoisonGlobals, ModuleNameAddr);

  // Add calls to unpoison all globals before each return instruction.
  for (auto &BB : GlobalInit)
    if (ReturnInst *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
      CallInst::Create(AsanUnpoisonGlobals, "", RI->getIterator());
}

void ModuleAddressSanitizer::createInitializerPoisonCalls() {
  GlobalVariable *GV = M.getGlobalVariable("llvm.global_ctors");
  if (!GV)
    return;

  ConstantArray *CA = dyn_cast<ConstantArray>(GV->getInitializer());
  if (!CA)
    return;

  for (Use &OP : CA->operands()) {
    if (isa<ConstantAggregateZero>(OP)) continue;
    ConstantStruct *CS = cast<ConstantStruct>(OP);

    // Must have a function or null ptr.
    if (Function *F = dyn_cast<Function>(CS->getOperand(1))) {
      if (F->getName() == kAsanModuleCtorName) continue;
      auto *Priority = cast<ConstantInt>(CS->getOperand(0));
      // Don't instrument CTORs that will run before asan.module_ctor.
      if (Priority->getLimitedValue() <= GetCtorAndDtorPriority(TargetTriple))
        continue;
      poisonOneInitializer(*F);
    }
  }
}

const GlobalVariable *
ModuleAddressSanitizer::getExcludedAliasedGlobal(const GlobalAlias &GA) const {
  // In case this function should be expanded to include rules that do not just
  // apply when CompileKernel is true, either guard all existing rules with an
  // 'if (CompileKernel) { ... }' or be absolutely sure that all these rules
  // should also apply to user space.
  assert(CompileKernel && "Only expecting to be called when compiling kernel");

  const Constant *C = GA.getAliasee();

  // When compiling the kernel, globals that are aliased by symbols prefixed
  // by "__" are special and cannot be padded with a redzone.
  if (GA.getName().starts_with("__"))
    return dyn_cast<GlobalVariable>(C->stripPointerCastsAndAliases());

  return nullptr;
}

bool ModuleAddressSanitizer::shouldInstrumentGlobal(GlobalVariable *G) const {
  Type *Ty = G->getValueType();
  LLVM_DEBUG(dbgs() << "GLOBAL: " << *G << "\n");

  if (G->hasSanitizerMetadata() && G->getSanitizerMetadata().NoAddress)
    return false;
  if (!Ty->isSized()) return false;
  if (!G->hasInitializer()) return false;
  // Globals in address space 1 and 4 are supported for AMDGPU.
  if (G->getAddressSpace() &&
      !(TargetTriple.isAMDGPU() && !isUnsupportedAMDGPUAddrspace(G)))
    return false;
  if (GlobalWasGeneratedByCompiler(G)) return false; // Our own globals.
  // Two problems with thread-locals:
  //   - The address of the main thread's copy can't be computed at link-time.
  //   - Need to poison all copies, not just the main thread's one.
  if (G->isThreadLocal()) return false;
  // For now, just ignore this Global if the alignment is large.
  if (G->getAlign() && *G->getAlign() > getMinRedzoneSizeForGlobal()) return false;

  // For non-COFF targets, only instrument globals known to be defined by this
  // TU.
  // FIXME: We can instrument comdat globals on ELF if we are using the
  // GC-friendly metadata scheme.
  if (!TargetTriple.isOSBinFormatCOFF()) {
    if (!G->hasExactDefinition() || G->hasComdat())
      return false;
  } else {
    // On COFF, don't instrument non-ODR linkages.
    if (G->isInterposable())
      return false;
    // If the global has AvailableExternally linkage, then it is not in this
    // module, which means it does not need to be instrumented.
    if (G->hasAvailableExternallyLinkage())
      return false;
  }

  // If a comdat is present, it must have a selection kind that implies ODR
  // semantics: no duplicates, any, or exact match.
  if (Comdat *C = G->getComdat()) {
    switch (C->getSelectionKind()) {
    case Comdat::Any:
    case Comdat::ExactMatch:
    case Comdat::NoDeduplicate:
      break;
    case Comdat::Largest:
    case Comdat::SameSize:
      return false;
    }
  }

  if (G->hasSection()) {
    // The kernel uses explicit sections for mostly special global variables
    // that we should not instrument. E.g. the kernel may rely on their layout
    // without redzones, or remove them at link time ("discard.*"), etc.
    if (CompileKernel)
      return false;

    StringRef Section = G->getSection();

    // Globals from llvm.metadata aren't emitted, do not instrument them.
    if (Section == "llvm.metadata") return false;
    // Do not instrument globals from special LLVM sections.
    if (Section.contains("__llvm") || Section.contains("__LLVM"))
      return false;

    // Do not instrument function pointers to initialization and termination
    // routines: dynamic linker will not properly handle redzones.
    if (Section.starts_with(".preinit_array") ||
        Section.starts_with(".init_array") ||
        Section.starts_with(".fini_array")) {
      return false;
    }

    // Do not instrument user-defined sections (with names resembling
    // valid C identifiers)
    if (TargetTriple.isOSBinFormatELF()) {
      if (llvm::all_of(Section,
                       [](char c) { return llvm::isAlnum(c) || c == '_'; }))
        return false;
    }

    // On COFF, if the section name contains '$', it is highly likely that the
    // user is using section sorting to create an array of globals similar to
    // the way initialization callbacks are registered in .init_array and
    // .CRT$XCU. The ATL also registers things in .ATL$__[azm]. Adding redzones
    // to such globals is counterproductive, because the intent is that they
    // will form an array, and out-of-bounds accesses are expected.
    // See https://github.com/google/sanitizers/issues/305
    // and http://msdn.microsoft.com/en-US/en-en/library/bb918180(v=vs.120).aspx
    if (TargetTriple.isOSBinFormatCOFF() && Section.contains('$')) {
      LLVM_DEBUG(dbgs() << "Ignoring global in sorted section (contains '$'): "
                        << *G << "\n");
      return false;
    }

    if (TargetTriple.isOSBinFormatMachO()) {
      StringRef ParsedSegment, ParsedSection;
      unsigned TAA = 0, StubSize = 0;
      bool TAAParsed;
      cantFail(MCSectionMachO::ParseSectionSpecifier(
          Section, ParsedSegment, ParsedSection, TAA, TAAParsed, StubSize));

      // Ignore the globals from the __OBJC section. The ObjC runtime assumes
      // those conform to /usr/lib/objc/runtime.h, so we can't add redzones to
      // them.
      if (ParsedSegment == "__OBJC" ||
          (ParsedSegment == "__DATA" && ParsedSection.starts_with("__objc_"))) {
        LLVM_DEBUG(dbgs() << "Ignoring ObjC runtime global: " << *G << "\n");
        return false;
      }
      // See https://github.com/google/sanitizers/issues/32
      // Constant CFString instances are compiled in the following way:
      //  -- the string buffer is emitted into
      //     __TEXT,__cstring,cstring_literals
      //  -- the constant NSConstantString structure referencing that buffer
      //     is placed into __DATA,__cfstring
      // Therefore there's no point in placing redzones into __DATA,__cfstring.
      // Moreover, it causes the linker to crash on OS X 10.7
      if (ParsedSegment == "__DATA" && ParsedSection == "__cfstring") {
        LLVM_DEBUG(dbgs() << "Ignoring CFString: " << *G << "\n");
        return false;
      }
      // The linker merges the contents of cstring_literals and removes the
      // trailing zeroes.
      if (ParsedSegment == "__TEXT" && (TAA & MachO::S_CSTRING_LITERALS)) {
        LLVM_DEBUG(dbgs() << "Ignoring a cstring literal: " << *G << "\n");
        return false;
      }
    }
  }

  if (CompileKernel) {
    // Globals that prefixed by "__" are special and cannot be padded with a
    // redzone.
    if (G->getName().starts_with("__"))
      return false;
  }

  return true;
}

// On Mach-O platforms, we emit global metadata in a separate section of the
// binary in order to allow the linker to properly dead strip. This is only
// supported on recent versions of ld64.
bool ModuleAddressSanitizer::ShouldUseMachOGlobalsSection() const {
  if (!TargetTriple.isOSBinFormatMachO())
    return false;

  if (TargetTriple.isMacOSX() && !TargetTriple.isMacOSXVersionLT(10, 11))
    return true;
  if (TargetTriple.isiOS() /* or tvOS */ && !TargetTriple.isOSVersionLT(9))
    return true;
  if (TargetTriple.isWatchOS() && !TargetTriple.isOSVersionLT(2))
    return true;
  if (TargetTriple.isDriverKit())
    return true;
  if (TargetTriple.isXROS())
    return true;

  return false;
}

StringRef ModuleAddressSanitizer::getGlobalMetadataSection() const {
  switch (TargetTriple.getObjectFormat()) {
  case Triple::COFF:  return ".ASAN$GL";
  case Triple::ELF:   return "asan_globals";
  case Triple::MachO: return "__DATA,__asan_globals,regular";
  case Triple::Wasm:
  case Triple::GOFF:
  case Triple::SPIRV:
  case Triple::XCOFF:
  case Triple::DXContainer:
    report_fatal_error(
        "ModuleAddressSanitizer not implemented for object file format");
  case Triple::UnknownObjectFormat:
    break;
  }
  llvm_unreachable("unsupported object format");
}

void ModuleAddressSanitizer::initializeCallbacks() {
  IRBuilder<> IRB(*C);

  // Declare our poisoning and unpoisoning functions.
  AsanPoisonGlobals =
      M.getOrInsertFunction(kAsanPoisonGlobalsName, IRB.getVoidTy(), IntptrTy);
  AsanUnpoisonGlobals =
      M.getOrInsertFunction(kAsanUnpoisonGlobalsName, IRB.getVoidTy());

  // Declare functions that register/unregister globals.
  AsanRegisterGlobals = M.getOrInsertFunction(
      kAsanRegisterGlobalsName, IRB.getVoidTy(), IntptrTy, IntptrTy);
  AsanUnregisterGlobals = M.getOrInsertFunction(
      kAsanUnregisterGlobalsName, IRB.getVoidTy(), IntptrTy, IntptrTy);

  // Declare the functions that find globals in a shared object and then invoke
  // the (un)register function on them.
  AsanRegisterImageGlobals = M.getOrInsertFunction(
      kAsanRegisterImageGlobalsName, IRB.getVoidTy(), IntptrTy);
  AsanUnregisterImageGlobals = M.getOrInsertFunction(
      kAsanUnregisterImageGlobalsName, IRB.getVoidTy(), IntptrTy);

  AsanRegisterElfGlobals =
      M.getOrInsertFunction(kAsanRegisterElfGlobalsName, IRB.getVoidTy(),
                            IntptrTy, IntptrTy, IntptrTy);
  AsanUnregisterElfGlobals =
      M.getOrInsertFunction(kAsanUnregisterElfGlobalsName, IRB.getVoidTy(),
                            IntptrTy, IntptrTy, IntptrTy);
}

// Put the metadata and the instrumented global in the same group. This ensures
// that the metadata is discarded if the instrumented global is discarded.
void ModuleAddressSanitizer::SetComdatForGlobalMetadata(
    GlobalVariable *G, GlobalVariable *Metadata, StringRef InternalSuffix) {
  Module &M = *G->getParent();
  Comdat *C = G->getComdat();
  if (!C) {
    if (!G->hasName()) {
      // If G is unnamed, it must be internal. Give it an artificial name
      // so we can put it in a comdat.
      assert(G->hasLocalLinkage());
      G->setName(genName("anon_global"));
    }

    if (!InternalSuffix.empty() && G->hasLocalLinkage()) {
      std::string Name = std::string(G->getName());
      Name += InternalSuffix;
      C = M.getOrInsertComdat(Name);
    } else {
      C = M.getOrInsertComdat(G->getName());
    }

    // Make this IMAGE_COMDAT_SELECT_NODUPLICATES on COFF. Also upgrade private
    // linkage to internal linkage so that a symbol table entry is emitted. This
    // is necessary in order to create the comdat group.
    if (TargetTriple.isOSBinFormatCOFF()) {
      C->setSelectionKind(Comdat::NoDeduplicate);
      if (G->hasPrivateLinkage())
        G->setLinkage(GlobalValue::InternalLinkage);
    }
    G->setComdat(C);
  }

  assert(G->hasComdat());
  Metadata->setComdat(G->getComdat());
}

// Create a separate metadata global and put it in the appropriate ASan
// global registration section.
GlobalVariable *
ModuleAddressSanitizer::CreateMetadataGlobal(Constant *Initializer,
                                             StringRef OriginalName) {
  auto Linkage = TargetTriple.isOSBinFormatMachO()
                     ? GlobalVariable::InternalLinkage
                     : GlobalVariable::PrivateLinkage;
  GlobalVariable *Metadata = new GlobalVariable(
      M, Initializer->getType(), false, Linkage, Initializer,
      Twine("__asan_global_") + GlobalValue::dropLLVMManglingEscape(OriginalName));
  Metadata->setSection(getGlobalMetadataSection());
  // Place metadata in a large section for x86-64 ELF binaries to mitigate
  // relocation pressure.
  setGlobalVariableLargeSection(TargetTriple, *Metadata);
  return Metadata;
}

Instruction *ModuleAddressSanitizer::CreateAsanModuleDtor() {
  AsanDtorFunction = Function::createWithDefaultAttr(
      FunctionType::get(Type::getVoidTy(*C), false),
      GlobalValue::InternalLinkage, 0, kAsanModuleDtorName, &M);
  AsanDtorFunction->addFnAttr(Attribute::NoUnwind);
  // Ensure Dtor cannot be discarded, even if in a comdat.
  appendToUsed(M, {AsanDtorFunction});
  BasicBlock *AsanDtorBB = BasicBlock::Create(*C, "", AsanDtorFunction);

  return ReturnInst::Create(*C, AsanDtorBB);
}

void ModuleAddressSanitizer::InstrumentGlobalsCOFF(
    IRBuilder<> &IRB, ArrayRef<GlobalVariable *> ExtendedGlobals,
    ArrayRef<Constant *> MetadataInitializers) {
  assert(ExtendedGlobals.size() == MetadataInitializers.size());
  auto &DL = M.getDataLayout();

  SmallVector<GlobalValue *, 16> MetadataGlobals(ExtendedGlobals.size());
  for (size_t i = 0; i < ExtendedGlobals.size(); i++) {
    Constant *Initializer = MetadataInitializers[i];
    GlobalVariable *G = ExtendedGlobals[i];
    GlobalVariable *Metadata = CreateMetadataGlobal(Initializer, G->getName());
    MDNode *MD = MDNode::get(M.getContext(), ValueAsMetadata::get(G));
    Metadata->setMetadata(LLVMContext::MD_associated, MD);
    MetadataGlobals[i] = Metadata;

    // The MSVC linker always inserts padding when linking incrementally. We
    // cope with that by aligning each struct to its size, which must be a power
    // of two.
    unsigned SizeOfGlobalStruct = DL.getTypeAllocSize(Initializer->getType());
    assert(isPowerOf2_32(SizeOfGlobalStruct) &&
           "global metadata will not be padded appropriately");
    Metadata->setAlignment(assumeAligned(SizeOfGlobalStruct));

    SetComdatForGlobalMetadata(G, Metadata, "");
  }

  // Update llvm.compiler.used, adding the new metadata globals. This is
  // needed so that during LTO these variables stay alive.
  if (!MetadataGlobals.empty())
    appendToCompilerUsed(M, MetadataGlobals);
}

void ModuleAddressSanitizer::instrumentGlobalsELF(
    IRBuilder<> &IRB, ArrayRef<GlobalVariable *> ExtendedGlobals,
    ArrayRef<Constant *> MetadataInitializers,
    const std::string &UniqueModuleId) {
  assert(ExtendedGlobals.size() == MetadataInitializers.size());

  // Putting globals in a comdat changes the semantic and potentially cause
  // false negative odr violations at link time. If odr indicators are used, we
  // keep the comdat sections, as link time odr violations will be dectected on
  // the odr indicator symbols.
  bool UseComdatForGlobalsGC = UseOdrIndicator && !UniqueModuleId.empty();

  SmallVector<GlobalValue *, 16> MetadataGlobals(ExtendedGlobals.size());
  for (size_t i = 0; i < ExtendedGlobals.size(); i++) {
    GlobalVariable *G = ExtendedGlobals[i];
    GlobalVariable *Metadata =
        CreateMetadataGlobal(MetadataInitializers[i], G->getName());
    MDNode *MD = MDNode::get(M.getContext(), ValueAsMetadata::get(G));
    Metadata->setMetadata(LLVMContext::MD_associated, MD);
    MetadataGlobals[i] = Metadata;

    if (UseComdatForGlobalsGC)
      SetComdatForGlobalMetadata(G, Metadata, UniqueModuleId);
  }

  // Update llvm.compiler.used, adding the new metadata globals. This is
  // needed so that during LTO these variables stay alive.
  if (!MetadataGlobals.empty())
    appendToCompilerUsed(M, MetadataGlobals);

  // RegisteredFlag serves two purposes. First, we can pass it to dladdr()
  // to look up the loaded image that contains it. Second, we can store in it
  // whether registration has already occurred, to prevent duplicate
  // registration.
  //
  // Common linkage ensures that there is only one global per shared library.
  GlobalVariable *RegisteredFlag = new GlobalVariable(
      M, IntptrTy, false, GlobalVariable::CommonLinkage,
      ConstantInt::get(IntptrTy, 0), kAsanGlobalsRegisteredFlagName);
  RegisteredFlag->setVisibility(GlobalVariable::HiddenVisibility);

  // Create start and stop symbols.
  GlobalVariable *StartELFMetadata = new GlobalVariable(
      M, IntptrTy, false, GlobalVariable::ExternalWeakLinkage, nullptr,
      "__start_" + getGlobalMetadataSection());
  StartELFMetadata->setVisibility(GlobalVariable::HiddenVisibility);
  GlobalVariable *StopELFMetadata = new GlobalVariable(
      M, IntptrTy, false, GlobalVariable::ExternalWeakLinkage, nullptr,
      "__stop_" + getGlobalMetadataSection());
  StopELFMetadata->setVisibility(GlobalVariable::HiddenVisibility);

  // Create a call to register the globals with the runtime.
  if (ConstructorKind == AsanCtorKind::Global)
    IRB.CreateCall(AsanRegisterElfGlobals,
                 {IRB.CreatePointerCast(RegisteredFlag, IntptrTy),
                  IRB.CreatePointerCast(StartELFMetadata, IntptrTy),
                  IRB.CreatePointerCast(StopELFMetadata, IntptrTy)});

  // We also need to unregister globals at the end, e.g., when a shared library
  // gets closed.
  if (DestructorKind != AsanDtorKind::None && !MetadataGlobals.empty()) {
    IRBuilder<> IrbDtor(CreateAsanModuleDtor());
    IrbDtor.CreateCall(AsanUnregisterElfGlobals,
                       {IRB.CreatePointerCast(RegisteredFlag, IntptrTy),
                        IRB.CreatePointerCast(StartELFMetadata, IntptrTy),
                        IRB.CreatePointerCast(StopELFMetadata, IntptrTy)});
  }
}

void ModuleAddressSanitizer::InstrumentGlobalsMachO(
    IRBuilder<> &IRB, ArrayRef<GlobalVariable *> ExtendedGlobals,
    ArrayRef<Constant *> MetadataInitializers) {
  assert(ExtendedGlobals.size() == MetadataInitializers.size());

  // On recent Mach-O platforms, use a structure which binds the liveness of
  // the global variable to the metadata struct. Keep the list of "Liveness" GV
  // created to be added to llvm.compiler.used
  StructType *LivenessTy = StructType::get(IntptrTy, IntptrTy);
  SmallVector<GlobalValue *, 16> LivenessGlobals(ExtendedGlobals.size());

  for (size_t i = 0; i < ExtendedGlobals.size(); i++) {
    Constant *Initializer = MetadataInitializers[i];
    GlobalVariable *G = ExtendedGlobals[i];
    GlobalVariable *Metadata = CreateMetadataGlobal(Initializer, G->getName());

    // On recent Mach-O platforms, we emit the global metadata in a way that
    // allows the linker to properly strip dead globals.
    auto LivenessBinder =
        ConstantStruct::get(LivenessTy, Initializer->getAggregateElement(0u),
                            ConstantExpr::getPointerCast(Metadata, IntptrTy));
    GlobalVariable *Liveness = new GlobalVariable(
        M, LivenessTy, false, GlobalVariable::InternalLinkage, LivenessBinder,
        Twine("__asan_binder_") + G->getName());
    Liveness->setSection("__DATA,__asan_liveness,regular,live_support");
    LivenessGlobals[i] = Liveness;
  }

  // Update llvm.compiler.used, adding the new liveness globals. This is
  // needed so that during LTO these variables stay alive. The alternative
  // would be to have the linker handling the LTO symbols, but libLTO
  // current API does not expose access to the section for each symbol.
  if (!LivenessGlobals.empty())
    appendToCompilerUsed(M, LivenessGlobals);

  // RegisteredFlag serves two purposes. First, we can pass it to dladdr()
  // to look up the loaded image that contains it. Second, we can store in it
  // whether registration has already occurred, to prevent duplicate
  // registration.
  //
  // common linkage ensures that there is only one global per shared library.
  GlobalVariable *RegisteredFlag = new GlobalVariable(
      M, IntptrTy, false, GlobalVariable::CommonLinkage,
      ConstantInt::get(IntptrTy, 0), kAsanGlobalsRegisteredFlagName);
  RegisteredFlag->setVisibility(GlobalVariable::HiddenVisibility);

  if (ConstructorKind == AsanCtorKind::Global)
    IRB.CreateCall(AsanRegisterImageGlobals,
                 {IRB.CreatePointerCast(RegisteredFlag, IntptrTy)});

  // We also need to unregister globals at the end, e.g., when a shared library
  // gets closed.
  if (DestructorKind != AsanDtorKind::None) {
    IRBuilder<> IrbDtor(CreateAsanModuleDtor());
    IrbDtor.CreateCall(AsanUnregisterImageGlobals,
                       {IRB.CreatePointerCast(RegisteredFlag, IntptrTy)});
  }
}

void ModuleAddressSanitizer::InstrumentGlobalsWithMetadataArray(
    IRBuilder<> &IRB, ArrayRef<GlobalVariable *> ExtendedGlobals,
    ArrayRef<Constant *> MetadataInitializers) {
  assert(ExtendedGlobals.size() == MetadataInitializers.size());
  unsigned N = ExtendedGlobals.size();
  assert(N > 0);

  // On platforms that don't have a custom metadata section, we emit an array
  // of global metadata structures.
  ArrayType *ArrayOfGlobalStructTy =
      ArrayType::get(MetadataInitializers[0]->getType(), N);
  auto AllGlobals = new GlobalVariable(
      M, ArrayOfGlobalStructTy, false, GlobalVariable::InternalLinkage,
      ConstantArray::get(ArrayOfGlobalStructTy, MetadataInitializers), "");
  if (Mapping.Scale > 3)
    AllGlobals->setAlignment(Align(1ULL << Mapping.Scale));

  if (ConstructorKind == AsanCtorKind::Global)
    IRB.CreateCall(AsanRegisterGlobals,
                 {IRB.CreatePointerCast(AllGlobals, IntptrTy),
                  ConstantInt::get(IntptrTy, N)});

  // We also need to unregister globals at the end, e.g., when a shared library
  // gets closed.
  if (DestructorKind != AsanDtorKind::None) {
    IRBuilder<> IrbDtor(CreateAsanModuleDtor());
    IrbDtor.CreateCall(AsanUnregisterGlobals,
                       {IRB.CreatePointerCast(AllGlobals, IntptrTy),
                        ConstantInt::get(IntptrTy, N)});
  }
}

// This function replaces all global variables with new variables that have
// trailing redzones. It also creates a function that poisons
// redzones and inserts this function into llvm.global_ctors.
// Sets *CtorComdat to true if the global registration code emitted into the
// asan constructor is comdat-compatible.
void ModuleAddressSanitizer::instrumentGlobals(IRBuilder<> &IRB,
                                               bool *CtorComdat) {
  // Build set of globals that are aliased by some GA, where
  // getExcludedAliasedGlobal(GA) returns the relevant GlobalVariable.
  SmallPtrSet<const GlobalVariable *, 16> AliasedGlobalExclusions;
  if (CompileKernel) {
    for (auto &GA : M.aliases()) {
      if (const GlobalVariable *GV = getExcludedAliasedGlobal(GA))
        AliasedGlobalExclusions.insert(GV);
    }
  }

  SmallVector<GlobalVariable *, 16> GlobalsToChange;
  for (auto &G : M.globals()) {
    if (!AliasedGlobalExclusions.count(&G) && shouldInstrumentGlobal(&G))
      GlobalsToChange.push_back(&G);
  }

  size_t n = GlobalsToChange.size();
  auto &DL = M.getDataLayout();

  // A global is described by a structure
  //   size_t beg;
  //   size_t size;
  //   size_t size_with_redzone;
  //   const char *name;
  //   const char *module_name;
  //   size_t has_dynamic_init;
  //   size_t padding_for_windows_msvc_incremental_link;
  //   size_t odr_indicator;
  // We initialize an array of such structures and pass it to a run-time call.
  StructType *GlobalStructTy =
      StructType::get(IntptrTy, IntptrTy, IntptrTy, IntptrTy, IntptrTy,
                      IntptrTy, IntptrTy, IntptrTy);
  SmallVector<GlobalVariable *, 16> NewGlobals(n);
  SmallVector<Constant *, 16> Initializers(n);

  for (size_t i = 0; i < n; i++) {
    GlobalVariable *G = GlobalsToChange[i];

    GlobalValue::SanitizerMetadata MD;
    if (G->hasSanitizerMetadata())
      MD = G->getSanitizerMetadata();

    // The runtime library tries demangling symbol names in the descriptor but
    // functionality like __cxa_demangle may be unavailable (e.g.
    // -static-libstdc++). So we demangle the symbol names here.
    std::string NameForGlobal = G->getName().str();
    GlobalVariable *Name =
        createPrivateGlobalForString(M, llvm::demangle(NameForGlobal),
                                     /*AllowMerging*/ true, genName("global"));

    Type *Ty = G->getValueType();
    const uint64_t SizeInBytes = DL.getTypeAllocSize(Ty);
    const uint64_t RightRedzoneSize = getRedzoneSizeForGlobal(SizeInBytes);
    Type *RightRedZoneTy = ArrayType::get(IRB.getInt8Ty(), RightRedzoneSize);

    StructType *NewTy = StructType::get(Ty, RightRedZoneTy);
    Constant *NewInitializer = ConstantStruct::get(
        NewTy, G->getInitializer(), Constant::getNullValue(RightRedZoneTy));

    // Create a new global variable with enough space for a redzone.
    GlobalValue::LinkageTypes Linkage = G->getLinkage();
    if (G->isConstant() && Linkage == GlobalValue::PrivateLinkage)
      Linkage = GlobalValue::InternalLinkage;
    GlobalVariable *NewGlobal = new GlobalVariable(
        M, NewTy, G->isConstant(), Linkage, NewInitializer, "", G,
        G->getThreadLocalMode(), G->getAddressSpace());
    NewGlobal->copyAttributesFrom(G);
    NewGlobal->setComdat(G->getComdat());
    NewGlobal->setAlignment(Align(getMinRedzoneSizeForGlobal()));
    // Don't fold globals with redzones. ODR violation detector and redzone
    // poisoning implicitly creates a dependence on the global's address, so it
    // is no longer valid for it to be marked unnamed_addr.
    NewGlobal->setUnnamedAddr(GlobalValue::UnnamedAddr::None);

    // Move null-terminated C strings to "__asan_cstring" section on Darwin.
    if (TargetTriple.isOSBinFormatMachO() && !G->hasSection() &&
        G->isConstant()) {
      auto Seq = dyn_cast<ConstantDataSequential>(G->getInitializer());
      if (Seq && Seq->isCString())
        NewGlobal->setSection("__TEXT,__asan_cstring,regular");
    }

    // Transfer the debug info and type metadata.  The payload starts at offset
    // zero so we can copy the metadata over as is.
    NewGlobal->copyMetadata(G, 0);

    Value *Indices2[2];
    Indices2[0] = IRB.getInt32(0);
    Indices2[1] = IRB.getInt32(0);

    G->replaceAllUsesWith(
        ConstantExpr::getGetElementPtr(NewTy, NewGlobal, Indices2, true));
    NewGlobal->takeName(G);
    G->eraseFromParent();
    NewGlobals[i] = NewGlobal;

    Constant *ODRIndicator = ConstantPointerNull::get(PtrTy);
    GlobalValue *InstrumentedGlobal = NewGlobal;

    bool CanUsePrivateAliases =
        TargetTriple.isOSBinFormatELF() || TargetTriple.isOSBinFormatMachO() ||
        TargetTriple.isOSBinFormatWasm();
    if (CanUsePrivateAliases && UsePrivateAlias) {
      // Create local alias for NewGlobal to avoid crash on ODR between
      // instrumented and non-instrumented libraries.
      InstrumentedGlobal =
          GlobalAlias::create(GlobalValue::PrivateLinkage, "", NewGlobal);
    }

    // ODR should not happen for local linkage.
    if (NewGlobal->hasLocalLinkage()) {
      ODRIndicator =
          ConstantExpr::getIntToPtr(ConstantInt::get(IntptrTy, -1), PtrTy);
    } else if (UseOdrIndicator) {
      // With local aliases, we need to provide another externally visible
      // symbol __odr_asan_XXX to detect ODR violation.
      auto *ODRIndicatorSym =
          new GlobalVariable(M, IRB.getInt8Ty(), false, Linkage,
                             Constant::getNullValue(IRB.getInt8Ty()),
                             kODRGenPrefix + NameForGlobal, nullptr,
                             NewGlobal->getThreadLocalMode());

      // Set meaningful attributes for indicator symbol.
      ODRIndicatorSym->setVisibility(NewGlobal->getVisibility());
      ODRIndicatorSym->setDLLStorageClass(NewGlobal->getDLLStorageClass());
      ODRIndicatorSym->setAlignment(Align(1));
      ODRIndicator = ODRIndicatorSym;
    }

    Constant *Initializer = ConstantStruct::get(
        GlobalStructTy,
        ConstantExpr::getPointerCast(InstrumentedGlobal, IntptrTy),       // beg
        ConstantInt::get(IntptrTy, SizeInBytes),                          // size
        ConstantInt::get(IntptrTy, SizeInBytes + RightRedzoneSize),       // size_with_redzone
        ConstantExpr::getPointerCast(Name, IntptrTy),                     // name
        ConstantExpr::getPointerCast(getOrCreateModuleName(), IntptrTy),  // module_name
        ConstantInt::get(IntptrTy, MD.IsDynInit),                         // has_dynamic_init
        Constant::getNullValue(IntptrTy),                                 // gcc_location
        ConstantExpr::getPointerCast(ODRIndicator, IntptrTy));            // odr_indicator

    LLVM_DEBUG(dbgs() << "NEW GLOBAL: " << *NewGlobal << "\n");

    Initializers[i] = Initializer;
  }

  // Add instrumented globals to llvm.compiler.used list to avoid LTO from
  // ConstantMerge'ing them.
  SmallVector<GlobalValue *, 16> GlobalsToAddToUsedList;
  for (size_t i = 0; i < n; i++) {
    GlobalVariable *G = NewGlobals[i];
    if (G->getName().empty()) continue;
    GlobalsToAddToUsedList.push_back(G);
  }
  appendToCompilerUsed(M, ArrayRef<GlobalValue *>(GlobalsToAddToUsedList));

  if (UseGlobalsGC && TargetTriple.isOSBinFormatELF()) {
    // Use COMDAT and register globals even if n == 0 to ensure that (a) the
    // linkage unit will only have one module constructor, and (b) the register
    // function will be called. The module destructor is not created when n ==
    // 0.
    *CtorComdat = true;
    instrumentGlobalsELF(IRB, NewGlobals, Initializers, getUniqueModuleId(&M));
  } else if (n == 0) {
    // When UseGlobalsGC is false, COMDAT can still be used if n == 0, because
    // all compile units will have identical module constructor/destructor.
    *CtorComdat = TargetTriple.isOSBinFormatELF();
  } else {
    *CtorComdat = false;
    if (UseGlobalsGC && TargetTriple.isOSBinFormatCOFF()) {
      InstrumentGlobalsCOFF(IRB, NewGlobals, Initializers);
    } else if (UseGlobalsGC && ShouldUseMachOGlobalsSection()) {
      InstrumentGlobalsMachO(IRB, NewGlobals, Initializers);
    } else {
      InstrumentGlobalsWithMetadataArray(IRB, NewGlobals, Initializers);
    }
  }

  // Create calls for poisoning before initializers run and unpoisoning after.
  if (ClInitializers)
    createInitializerPoisonCalls();

  LLVM_DEBUG(dbgs() << M);
}

uint64_t
ModuleAddressSanitizer::getRedzoneSizeForGlobal(uint64_t SizeInBytes) const {
  constexpr uint64_t kMaxRZ = 1 << 18;
  const uint64_t MinRZ = getMinRedzoneSizeForGlobal();

  uint64_t RZ = 0;
  if (SizeInBytes <= MinRZ / 2) {
    // Reduce redzone size for small size objects, e.g. int, char[1]. MinRZ is
    // at least 32 bytes, optimize when SizeInBytes is less than or equal to
    // half of MinRZ.
    RZ = MinRZ - SizeInBytes;
  } else {
    // Calculate RZ, where MinRZ <= RZ <= MaxRZ, and RZ ~ 1/4 * SizeInBytes.
    RZ = std::clamp((SizeInBytes / MinRZ / 4) * MinRZ, MinRZ, kMaxRZ);

    // Round up to multiple of MinRZ.
    if (SizeInBytes % MinRZ)
      RZ += MinRZ - (SizeInBytes % MinRZ);
  }

  assert((RZ + SizeInBytes) % MinRZ == 0);

  return RZ;
}

int ModuleAddressSanitizer::GetAsanVersion() const {
  int LongSize = M.getDataLayout().getPointerSizeInBits();
  bool isAndroid = Triple(M.getTargetTriple()).isAndroid();
  int Version = 8;
  // 32-bit Android is one version ahead because of the switch to dynamic
  // shadow.
  Version += (LongSize == 32 && isAndroid);
  return Version;
}

GlobalVariable *ModuleAddressSanitizer::getOrCreateModuleName() {
  if (!ModuleName) {
    // We shouldn't merge same module names, as this string serves as unique
    // module ID in runtime.
    ModuleName =
        createPrivateGlobalForString(M, M.getModuleIdentifier(),
                                     /*AllowMerging*/ false, genName("module"));
  }
  return ModuleName;
}

bool ModuleAddressSanitizer::instrumentModule() {
  initializeCallbacks();

  // Create a module constructor. A destructor is created lazily because not all
  // platforms, and not all modules need it.
  if (ConstructorKind == AsanCtorKind::Global) {
    if (CompileKernel) {
      // The kernel always builds with its own runtime, and therefore does not
      // need the init and version check calls.
      AsanCtorFunction = createSanitizerCtor(M, kAsanModuleCtorName);
    } else {
      std::string AsanVersion = std::to_string(GetAsanVersion());
      std::string VersionCheckName =
          InsertVersionCheck ? (kAsanVersionCheckNamePrefix + AsanVersion) : "";
      std::tie(AsanCtorFunction, std::ignore) =
          createSanitizerCtorAndInitFunctions(
              M, kAsanModuleCtorName, kAsanInitName, /*InitArgTypes=*/{},
              /*InitArgs=*/{}, VersionCheckName);
    }
  }

  bool CtorComdat = true;
  if (ClGlobals) {
    assert(AsanCtorFunction || ConstructorKind == AsanCtorKind::None);
    if (AsanCtorFunction) {
      IRBuilder<> IRB(AsanCtorFunction->getEntryBlock().getTerminator());
      instrumentGlobals(IRB, &CtorComdat);
    } else {
      IRBuilder<> IRB(*C);
      instrumentGlobals(IRB, &CtorComdat);
    }
  }

  const uint64_t Priority = GetCtorAndDtorPriority(TargetTriple);

  // Put the constructor and destructor in comdat if both
  // (1) global instrumentation is not TU-specific
  // (2) target is ELF.
  if (UseCtorComdat && TargetTriple.isOSBinFormatELF() && CtorComdat) {
    if (AsanCtorFunction) {
      AsanCtorFunction->setComdat(M.getOrInsertComdat(kAsanModuleCtorName));
      appendToGlobalCtors(M, AsanCtorFunction, Priority, AsanCtorFunction);
    }
    if (AsanDtorFunction) {
      AsanDtorFunction->setComdat(M.getOrInsertComdat(kAsanModuleDtorName));
      appendToGlobalDtors(M, AsanDtorFunction, Priority, AsanDtorFunction);
    }
  } else {
    if (AsanCtorFunction)
      appendToGlobalCtors(M, AsanCtorFunction, Priority);
    if (AsanDtorFunction)
      appendToGlobalDtors(M, AsanDtorFunction, Priority);
  }

  return true;
}

void AddressSanitizer::initializeCallbacks(const TargetLibraryInfo *TLI) {
  IRBuilder<> IRB(*C);
  // Create __asan_report* callbacks.
  // IsWrite, TypeSize and Exp are encoded in the function name.
  for (int Exp = 0; Exp < 2; Exp++) {
    for (size_t AccessIsWrite = 0; AccessIsWrite <= 1; AccessIsWrite++) {
      const std::string TypeStr = AccessIsWrite ? "store" : "load";
      const std::string ExpStr = Exp ? "exp_" : "";
      const std::string EndingStr = Recover ? "_noabort" : "";

      SmallVector<Type *, 3> Args2 = {IntptrTy, IntptrTy};
      SmallVector<Type *, 2> Args1{1, IntptrTy};
      AttributeList AL2;
      AttributeList AL1;
      if (Exp) {
        Type *ExpType = Type::getInt32Ty(*C);
        Args2.push_back(ExpType);
        Args1.push_back(ExpType);
        if (auto AK = TLI->getExtAttrForI32Param(false)) {
          AL2 = AL2.addParamAttribute(*C, 2, AK);
          AL1 = AL1.addParamAttribute(*C, 1, AK);
        }
      }
      AsanErrorCallbackSized[AccessIsWrite][Exp] = M.getOrInsertFunction(
          kAsanReportErrorTemplate + ExpStr + TypeStr + "_n" + EndingStr,
          FunctionType::get(IRB.getVoidTy(), Args2, false), AL2);

      AsanMemoryAccessCallbackSized[AccessIsWrite][Exp] = M.getOrInsertFunction(
          ClMemoryAccessCallbackPrefix + ExpStr + TypeStr + "N" + EndingStr,
          FunctionType::get(IRB.getVoidTy(), Args2, false), AL2);

      for (size_t AccessSizeIndex = 0; AccessSizeIndex < kNumberOfAccessSizes;
           AccessSizeIndex++) {
        const std::string Suffix = TypeStr + itostr(1ULL << AccessSizeIndex);
        AsanErrorCallback[AccessIsWrite][Exp][AccessSizeIndex] =
            M.getOrInsertFunction(
                kAsanReportErrorTemplate + ExpStr + Suffix + EndingStr,
                FunctionType::get(IRB.getVoidTy(), Args1, false), AL1);

        AsanMemoryAccessCallback[AccessIsWrite][Exp][AccessSizeIndex] =
            M.getOrInsertFunction(
                ClMemoryAccessCallbackPrefix + ExpStr + Suffix + EndingStr,
                FunctionType::get(IRB.getVoidTy(), Args1, false), AL1);
      }
    }
  }

  const std::string MemIntrinCallbackPrefix =
      (CompileKernel && !ClKasanMemIntrinCallbackPrefix)
          ? std::string("")
          : ClMemoryAccessCallbackPrefix;
  AsanMemmove = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memmove",
                                      PtrTy, PtrTy, PtrTy, IntptrTy);
  AsanMemcpy = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memcpy", PtrTy,
                                     PtrTy, PtrTy, IntptrTy);
  AsanMemset = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memset",
                                     TLI->getAttrList(C, {1}, /*Signed=*/false),
                                     PtrTy, PtrTy, IRB.getInt32Ty(), IntptrTy);

  AsanHandleNoReturnFunc =
      M.getOrInsertFunction(kAsanHandleNoReturnName, IRB.getVoidTy());

  AsanPtrCmpFunction =
      M.getOrInsertFunction(kAsanPtrCmp, IRB.getVoidTy(), IntptrTy, IntptrTy);
  AsanPtrSubFunction =
      M.getOrInsertFunction(kAsanPtrSub, IRB.getVoidTy(), IntptrTy, IntptrTy);
  if (Mapping.InGlobal)
    AsanShadowGlobal = M.getOrInsertGlobal("__asan_shadow",
                                           ArrayType::get(IRB.getInt8Ty(), 0));

  AMDGPUAddressShared =
      M.getOrInsertFunction(kAMDGPUAddressSharedName, IRB.getInt1Ty(), PtrTy);
  AMDGPUAddressPrivate =
      M.getOrInsertFunction(kAMDGPUAddressPrivateName, IRB.getInt1Ty(), PtrTy);

  CombiSanInit = M.getOrInsertFunction("__combisan_initialize", IRB.getVoidTy(), IntptrTy, IntptrTy);
}

bool AddressSanitizer::maybeInsertAsanInitAtFunctionEntry(Function &F) {
  // For each NSObject descendant having a +load method, this method is invoked
  // by the ObjC runtime before any of the static constructors is called.
  // Therefore we need to instrument such methods with a call to __asan_init
  // at the beginning in order to initialize our runtime before any access to
  // the shadow memory.
  // We cannot just ignore these methods, because they may call other
  // instrumented functions.
  if (F.getName().contains(" load]")) {
    FunctionCallee AsanInitFunction =
        declareSanitizerInitFunction(*F.getParent(), kAsanInitName, {});
    IRBuilder<> IRB(&F.front(), F.front().begin());
    IRB.CreateCall(AsanInitFunction, {});
    return true;
  }
  return false;
}

bool AddressSanitizer::maybeInsertDynamicShadowAtFunctionEntry(Function &F) {
  // Generate code only when dynamic addressing is needed.
  if (Mapping.Offset != kDynamicShadowSentinel)
    return false;

  IRBuilder<> IRB(&F.front().front());
  if (Mapping.InGlobal) {
    if (ClWithIfuncSuppressRemat) {
      // An empty inline asm with input reg == output reg.
      // An opaque pointer-to-int cast, basically.
      InlineAsm *Asm = InlineAsm::get(
          FunctionType::get(IntptrTy, {AsanShadowGlobal->getType()}, false),
          StringRef(""), StringRef("=r,0"),
          /*hasSideEffects=*/false);
      LocalDynamicShadow =
          IRB.CreateCall(Asm, {AsanShadowGlobal}, ".asan.shadow");
    } else {
      LocalDynamicShadow =
          IRB.CreatePointerCast(AsanShadowGlobal, IntptrTy, ".asan.shadow");
    }
  } else {
    Value *GlobalDynamicAddress = F.getParent()->getOrInsertGlobal(
        kAsanShadowMemoryDynamicAddress, IntptrTy);
    LocalDynamicShadow = IRB.CreateLoad(IntptrTy, GlobalDynamicAddress);
  }
  return true;
}

void AddressSanitizer::markEscapedLocalAllocas(Function &F) {
  // Find the one possible call to llvm.localescape and pre-mark allocas passed
  // to it as uninteresting. This assumes we haven't started processing allocas
  // yet. This check is done up front because iterating the use list in
  // isInterestingAlloca would be algorithmically slower.
  assert(ProcessedAllocas.empty() && "must process localescape before allocas");

  // Try to get the declaration of llvm.localescape. If it's not in the module,
  // we can exit early.
  if (!F.getParent()->getFunction("llvm.localescape")) return;

  // Look for a call to llvm.localescape call in the entry block. It can't be in
  // any other block.
  for (Instruction &I : F.getEntryBlock()) {
    IntrinsicInst *II = dyn_cast<IntrinsicInst>(&I);
    if (II && II->getIntrinsicID() == Intrinsic::localescape) {
      // We found a call. Mark all the allocas passed in as uninteresting.
      for (Value *Arg : II->args()) {
        AllocaInst *AI = dyn_cast<AllocaInst>(Arg->stripPointerCasts());
        assert(AI && AI->isStaticAlloca() &&
               "non-static alloca arg to localescape");
        ProcessedAllocas[AI] = false;
      }
      break;
    }
  }
}

bool AddressSanitizer::suppressInstrumentationSiteForDebug(int &Instrumented) {
  bool ShouldInstrument =
      ClDebugMin < 0 || ClDebugMax < 0 ||
      (Instrumented >= ClDebugMin && Instrumented <= ClDebugMax);
  Instrumented++;
  return !ShouldInstrument;
}

bool AddressSanitizer::instrumentFunction(Function &F,
                                          const TargetLibraryInfo *TLI) {
  if (F.empty())
    return false;
  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage) return false;
  if (!ClDebugFunc.empty() && ClDebugFunc == F.getName()) return false;
  if (F.getName().starts_with("__asan_")) return false;
  if (F.isPresplitCoroutine())
    return false;

  bool FunctionModified = false;

  // Do not apply any instrumentation for naked functions.
  if (F.hasFnAttribute(Attribute::Naked))
    return FunctionModified;

  // If needed, insert __asan_init before checking for SanitizeAddress attr.
  // This function needs to be called even if the function body is not
  // instrumented.
  if (maybeInsertAsanInitAtFunctionEntry(F))
    FunctionModified = true;

  // Leave if the function doesn't need instrumentation.
  if (!F.hasFnAttribute(Attribute::SanitizeAddress)) return FunctionModified;

  if (F.hasFnAttribute(Attribute::DisableSanitizerInstrumentation))
    return FunctionModified;

  LLVM_DEBUG(dbgs() << "ASAN instrumenting:\n" << F << "\n");

  initializeCallbacks(TLI);

  FunctionStateRAII CleanupObj(this);

  RuntimeCallInserter RTCI(F);

  FunctionModified |= maybeInsertDynamicShadowAtFunctionEntry(F);

  // We can't instrument allocas used with llvm.localescape. Only static allocas
  // can be passed to that intrinsic.
  markEscapedLocalAllocas(F);

  // We want to instrument every address only once per basic block (unless there
  // are calls between uses).
  SmallPtrSet<Value *, 16> TempsToInstrument;
  SmallPtrSet<Value *, 16> TempsSafeToInstrument;
  SmallVector<InterestingMemoryOperand, 16> OperandsToInstrument;
  SmallVector<MemIntrinsic *, 16> IntrinToInstrument;
  SmallVector<Instruction *, 8> NoReturnCalls;
  SmallVector<BasicBlock *, 16> AllBlocks;
  SmallVector<Instruction *, 16> PointerComparisonsOrSubtracts;

  // CombiSan: track safe accesses for MSan
  SmallVector<InterestingMemoryOperand, 16> SafeOperandsToInstrument;
  // CombiSan: track constructors
  SmallVector<CallBase *, 16> ConstructorCalls;
  // CombiSan: allocas to skip because they are constructed by C++/other
  std::set<AllocaInst *> ConstructorAllocas;
  // CombiSan: program allocations (i.e. not external library)
  SmallVector<CallBase *, 16> ProgramAllocs;
  // CombiSan: indirect calls potentially allocating
  SmallVector<CallBase *, 16> IndirectCalls;

  // Fill the set of memory operations to instrument.
  for (auto &BB : F) {
    AllBlocks.push_back(&BB);
    TempsToInstrument.clear();
    TempsSafeToInstrument.clear();
    int NumInsnsPerBB = 0;
    for (auto &Inst : BB) {
      if (LooksLikeCodeInBug11395(&Inst)) return false;
      // Skip instructions inserted by another instrumentation.
      if (Inst.hasMetadata(LLVMContext::MD_nosanitize))
        continue;
      SmallVector<InterestingMemoryOperand, 1> InterestingOperands;
      SmallVector<InterestingMemoryOperand, 1> SafeInterestingOperands;
      getInterestingMemoryOperands(&Inst, InterestingOperands, SafeInterestingOperands);

      if (!SafeInterestingOperands.empty()) {
        for (auto &Operand : SafeInterestingOperands) {
          if (ClOpt && ClOptSameTemp) {
            Value *Ptr = Operand.getPtr();
            // If we have a mask, skip instrumentation if we've already
            // instrumented the full object. But don't add to TempsSafeToInstrument
            // because we might get another load/store with a different mask.
            if (Operand.MaybeMask) {
              if (TempsSafeToInstrument.count(Ptr))
                continue; // We've seen this (whole) temp in the current BB.
            } else {
              if (!TempsSafeToInstrument.insert(Ptr).second)
                continue; // We've seen this temp in the current BB.
            }
          }
          if(Operand.IsWrite) // stores only
            SafeOperandsToInstrument.push_back(Operand);
        }
      }

      if (!InterestingOperands.empty()) {
        for (auto &Operand : InterestingOperands) {
          if (ClOpt && ClOptSameTemp) {
            Value *Ptr = Operand.getPtr();
            // If we have a mask, skip instrumentation if we've already
            // instrumented the full object. But don't add to TempsToInstrument
            // because we might get another load/store with a different mask.
            if (Operand.MaybeMask) {
              if (TempsToInstrument.count(Ptr))
                continue; // We've seen this (whole) temp in the current BB.
            } else {
              if (!TempsToInstrument.insert(Ptr).second)
                continue; // We've seen this temp in the current BB.
            }
          }
          OperandsToInstrument.push_back(Operand);
          NumInsnsPerBB++;
        }
      } else if (((ClInvalidPointerPairs || ClInvalidPointerCmp) &&
                  isInterestingPointerComparison(&Inst)) ||
                 ((ClInvalidPointerPairs || ClInvalidPointerSub) &&
                  isInterestingPointerSubtraction(&Inst))) {
        PointerComparisonsOrSubtracts.push_back(&Inst);
      } else if (MemIntrinsic *MI = dyn_cast<MemIntrinsic>(&Inst)) {
        // ok, take it.
        IntrinToInstrument.push_back(MI);
        NumInsnsPerBB++;
      } else if(AllocaInst *AI = dyn_cast<AllocaInst>(&Inst)) {
        Type *TAI = AI->getAllocatedType();
        if (auto *StructT = llvm::dyn_cast<llvm::StructType>(TAI)) {
          if(StructT->hasName()){
            llvm::StringRef StructName = StructT->getName();
            if(StructName.contains("std::")){
              // errs() << "StdlibAlloca: " << *AI << "\n";
              // this does not work for structures that internally contain data like std::string
              // because it may cause missing uninitialized loads
              //ConstructorAllocas.insert(AI);
            }
          }
        }

      } else {
         if (auto *CB = dyn_cast<CallBase>(&Inst)) {

          // CombiSan: check for call va_start (consider corresponding alloca initialized)
          if (auto *intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(&Inst)) {
            if(intrinsic->getIntrinsicID() == llvm::Intrinsic::vastart){
              ConstructorCalls.push_back(CB); 
            }
          }

          Function *calledFunc = CB->getCalledFunction();
          if (calledFunc && !Inst.isDebugOrPseudoInst()){
            // CombiSan: program allocations (malloc/new/etc)
            if(calledFunc->hasName()){
              std::string funcName = calledFunc->getName().str();
              auto it = ProgramAllocMap.find(funcName);
              if(it != ProgramAllocMap.end()){ // contained
                ProgramAllocs.push_back(CB);
              }
            }

            // CombiSan: constructors
            llvm::ItaniumPartialDemangler D;
            bool err = D.partialDemangle(calledFunc->getName().data());
            if(!err){ // e.g. not mangled
              size_t demangled_size = 80; // realloced if too small
              char *demangled_cstr = static_cast<char *>(std::malloc(demangled_size));
              demangled_cstr = D.finishDemangle(demangled_cstr, &demangled_size);
              if(D.isCtorOrDtor()){
                // CB could still be a destructor
                // we do not want to include destructors, because they should set
                // the shadow memory for ASan to deallocated for UAF etc
                // check for std:: to filter stdlib, avoid instrumenting normal classes.
                if (!std::strchr(demangled_cstr, '~') && strstr(demangled_cstr, "std::")) {
                  // errs() << "CB: " << *CB << "\n";
                  // errs() << "Demangle: " << demangled_cstr << "\n";
                  // errs() << "is constructor!\n";
                  ConstructorCalls.push_back(CB); 
                }
              }
            }
          }
          else if(CB->isIndirectCall() && !CB->isInlineAsm()){
            auto isPosixMemalignLike = [](CallBase *CB) -> bool {
              if (!CB->getType()->isIntegerTy(32))
                return false;
              if (CB->arg_size() != 3)
                return false;
              Type *Arg0Ty = CB->getArgOperand(0)->getType();
              Type *Arg1Ty = CB->getArgOperand(1)->getType();
              Type *Arg2Ty = CB->getArgOperand(2)->getType();
              return Arg0Ty->isPointerTy() && Arg1Ty->isIntegerTy(64) && Arg2Ty->isIntegerTy(64);
            };

            // standard allocators return a pointer (TODO: we can narrow down the args even more)
            // posix_memalign: int result with ptr, size_t, size_t args
            if(isPosixMemalignLike(CB) || CB->getType()->isPointerTy()){
              errs() << "Interesting indirect call (maybe alloc): " << *CB << "\n";
              IndirectCalls.push_back(CB);
            }
          }

          // A call inside BB.
          TempsToInstrument.clear();
          if (CB->doesNotReturn())
            NoReturnCalls.push_back(CB);
        }
        if (CallInst *CI = dyn_cast<CallInst>(&Inst))
          maybeMarkSanitizerLibraryCallNoBuiltin(CI, TLI);
      }
      if (NumInsnsPerBB >= ClMaxInsnsToInstrumentPerBB) break;
    }
  }

  bool UseCalls = (InstrumentationWithCallsThreshold >= 0 &&
                   OperandsToInstrument.size() + IntrinToInstrument.size() >
                       (unsigned)InstrumentationWithCallsThreshold);
  const DataLayout &DL = F.getDataLayout();
  ObjectSizeOffsetVisitor ObjSizeVis(DL, TLI, F.getContext());


  // Static "taint" Analysis:
  // for all uses of loaded values
  // see if they end up in MSan sinks: conditional branch, system call and pointer dereference
  // if the loaded value is stored/called: give up
  // calls: maybe safe if onlyReadsMemory? and not a syscall?
  // if there is provably no UUM, do not check MSan bits -- this reduces false violations
  // bonus: if ASan deems this load provably safe, we can skip instrumentation altogether
  analyzeUUMs(OperandsToInstrument);
  analyzeUUMs(SafeOperandsToInstrument);
  
  // find allocation sites of constructors to be initialized
  collectConstructorSites(ConstructorCalls, ConstructorAllocas, TLI);

  // replace program allocations with asan malloc that sets to uninitialized
  // we do this to make sure external mallocs take the overloaded asan_malloc
  // which does not set the object to uninitialized (since we do not observe the stores there)
  replaceProgramAllocs(ProgramAllocs);

  instrumentIndirectCalls(IndirectCalls);

  // Instrument.
  int NumInstrumented = 0;
  for (auto &Operand : OperandsToInstrument) {
    if (!suppressInstrumentationSiteForDebug(NumInstrumented))
      instrumentMop(ObjSizeVis, Operand, UseCalls,
                    F.getDataLayout(), RTCI, SafeOperandsToInstrument);
    FunctionModified = true;
  }

  for (auto &Operand : SafeOperandsToInstrument) {
    if (!suppressInstrumentationSiteForDebug(NumInstrumented))
      instrumentSafeMop(ObjSizeVis, Operand, UseCalls,
                    F.getDataLayout(), RTCI);
    FunctionModified = true;
  }

  for (auto *Inst : IntrinToInstrument) {
    if (!suppressInstrumentationSiteForDebug(NumInstrumented))
      instrumentMemIntrinsic(Inst, RTCI);
    FunctionModified = true;
  }

  FunctionStackPoisoner FSP(F, *this, RTCI, ConstructorAllocas);
  bool ChangedStack = FSP.runOnFunction();

  // We must unpoison the stack before NoReturn calls (throw, _exit, etc).
  // See e.g. https://github.com/google/sanitizers/issues/37
  for (auto *CI : NoReturnCalls) {
    IRBuilder<> IRB(CI);
    RTCI.createRuntimeCall(IRB, AsanHandleNoReturnFunc, {});
  }

  for (auto *Inst : PointerComparisonsOrSubtracts) {
    instrumentPointerComparisonOrSubtraction(Inst, RTCI);
    FunctionModified = true;
  }

  if (ChangedStack || !NoReturnCalls.empty())
    FunctionModified = true;

  LLVM_DEBUG(dbgs() << "ASAN done instrumenting: " << FunctionModified << " "
                    << F << "\n");

  return FunctionModified;
}

// Workaround for bug 11395: we don't want to instrument stack in functions
// with large assembly blobs (32-bit only), otherwise reg alloc may crash.
// FIXME: remove once the bug 11395 is fixed.
bool AddressSanitizer::LooksLikeCodeInBug11395(Instruction *I) {
  if (LongSize != 32) return false;
  CallInst *CI = dyn_cast<CallInst>(I);
  if (!CI || !CI->isInlineAsm()) return false;
  if (CI->arg_size() <= 5)
    return false;
  // We have inline assembly with quite a few arguments.
  return true;
}

void FunctionStackPoisoner::initializeCallbacks(Module &M) {
  IRBuilder<> IRB(*C);
  if (ASan.UseAfterReturn == AsanDetectStackUseAfterReturnMode::Always ||
      ASan.UseAfterReturn == AsanDetectStackUseAfterReturnMode::Runtime) {
    const char *MallocNameTemplate =
        ASan.UseAfterReturn == AsanDetectStackUseAfterReturnMode::Always
            ? kAsanStackMallocAlwaysNameTemplate
            : kAsanStackMallocNameTemplate;
    for (int Index = 0; Index <= kMaxAsanStackMallocSizeClass; Index++) {
      std::string Suffix = itostr(Index);
      AsanStackMallocFunc[Index] = M.getOrInsertFunction(
          MallocNameTemplate + Suffix, IntptrTy, IntptrTy);
      AsanStackFreeFunc[Index] =
          M.getOrInsertFunction(kAsanStackFreeNameTemplate + Suffix,
                                IRB.getVoidTy(), IntptrTy, IntptrTy);
    }
  }
  if (ASan.UseAfterScope) {
    AsanPoisonStackMemoryFunc = M.getOrInsertFunction(
        kAsanPoisonStackMemoryName, IRB.getVoidTy(), IntptrTy, IntptrTy);
    AsanUnpoisonStackMemoryFunc = M.getOrInsertFunction(
        kAsanUnpoisonStackMemoryName, IRB.getVoidTy(), IntptrTy, IntptrTy);
  }

  for (size_t Val : {0x00,0x6A,0x5A,0x56,0xAA,0x40,0x50,0x54,0x55}) {
    std::ostringstream Name;
    Name << kAsanSetShadowPrefix;
    Name << std::setw(2) << std::setfill('0') << std::hex << Val;
    AsanSetShadowFunc[Val] =
        M.getOrInsertFunction(Name.str(), IRB.getVoidTy(), IntptrTy, IntptrTy);
  }

  AsanAllocaPoisonFunc = M.getOrInsertFunction(
      kAsanAllocaPoison, IRB.getVoidTy(), IntptrTy, IntptrTy);
  AsanAllocasUnpoisonFunc = M.getOrInsertFunction(
      kAsanAllocasUnpoison, IRB.getVoidTy(), IntptrTy, IntptrTy);
}

void FunctionStackPoisoner::copyToShadowInline(ArrayRef<uint8_t> ShadowMask,
                                               ArrayRef<uint8_t> ShadowBytes,
                                               size_t Begin, size_t End,
                                               IRBuilder<> &IRB,
                                               Value *ShadowBase) {
  if (Begin >= End)
    return;

  const size_t LargestStoreSizeInBytes =
      std::min<size_t>(sizeof(uint64_t), ASan.LongSize / 8);

  const bool IsLittleEndian = F.getDataLayout().isLittleEndian();

  // Poison given range in shadow using larges store size with out leading and
  // trailing zeros in ShadowMask. Zeros never change, so they need neither
  // poisoning nor up-poisoning. Still we don't mind if some of them get into a
  // middle of a store.
  for (size_t i = Begin; i < End;) {
    if (!ShadowMask[i]) {
      assert(!ShadowBytes[i]);
      ++i;
      continue;
    }

    size_t StoreSizeInBytes = LargestStoreSizeInBytes;
    // Fit store size into the range.
    while (StoreSizeInBytes > End - i)
      StoreSizeInBytes /= 2;

    // Minimize store size by trimming trailing zeros.
    for (size_t j = StoreSizeInBytes - 1; j && !ShadowMask[i + j]; --j) {
      while (j <= StoreSizeInBytes / 2)
        StoreSizeInBytes /= 2;
    }

    uint64_t Val = 0;
    for (size_t j = 0; j < StoreSizeInBytes; j++) {
      if (IsLittleEndian)
        Val |= (uint64_t)ShadowBytes[i + j] << (8 * j);
      else
        Val = (Val << 8) | ShadowBytes[i + j];
    }
    Value *Ptr = IRB.CreateAdd(ShadowBase, ConstantInt::get(IntptrTy, i));
    Value *Poison = IRB.getIntN(StoreSizeInBytes * 8, Val);
    IRB.CreateAlignedStore(
        Poison, IRB.CreateIntToPtr(Ptr, PointerType::getUnqual(Poison->getContext())),
        Align(1));

    i += StoreSizeInBytes;
  }
}

void FunctionStackPoisoner::copyToShadow(ArrayRef<uint8_t> ShadowMask,
                                         ArrayRef<uint8_t> ShadowBytes,
                                         IRBuilder<> &IRB, Value *ShadowBase) {
  copyToShadow(ShadowMask, ShadowBytes, 0, ShadowMask.size(), IRB, ShadowBase);
}

void FunctionStackPoisoner::copyToShadow(ArrayRef<uint8_t> ShadowMask,
                                         ArrayRef<uint8_t> ShadowBytes,
                                         size_t Begin, size_t End,
                                         IRBuilder<> &IRB, Value *ShadowBase) {
  assert(ShadowMask.size() == ShadowBytes.size());
  size_t Done = Begin;
  for (size_t i = Begin, j = Begin + 1; i < End; i = j++) {
    if (!ShadowMask[i]) {
      assert(!ShadowBytes[i]);
      continue;
    }
    uint8_t Val = ShadowBytes[i];
    if (!AsanSetShadowFunc[Val])
      continue;

    // Skip same values.
    for (; j < End && ShadowMask[j] && Val == ShadowBytes[j]; ++j) {
    }

    if (j - i >= ASan.MaxInlinePoisoningSize) {
      copyToShadowInline(ShadowMask, ShadowBytes, Done, i, IRB, ShadowBase);
      RTCI.createRuntimeCall(
          IRB, AsanSetShadowFunc[Val],
          {IRB.CreateAdd(ShadowBase, ConstantInt::get(IntptrTy, i)),
           ConstantInt::get(IntptrTy, j - i)});
      Done = j;
    }
  }

  copyToShadowInline(ShadowMask, ShadowBytes, Done, End, IRB, ShadowBase);
}

// Fake stack allocator (asan_fake_stack.h) has 11 size classes
// for every power of 2 from kMinStackMallocSize to kMaxAsanStackMallocSizeClass
static int StackMallocSizeClass(uint64_t LocalStackSize) {
  assert(LocalStackSize <= kMaxStackMallocSize);
  uint64_t MaxSize = kMinStackMallocSize;
  for (int i = 0;; i++, MaxSize *= 2)
    if (LocalStackSize <= MaxSize) return i;
  llvm_unreachable("impossible LocalStackSize");
}

void FunctionStackPoisoner::copyArgsPassedByValToAllocas() {
  Instruction *CopyInsertPoint = &F.front().front();
  if (CopyInsertPoint == ASan.LocalDynamicShadow) {
    // Insert after the dynamic shadow location is determined
    CopyInsertPoint = CopyInsertPoint->getNextNode();
    assert(CopyInsertPoint);
  }
  IRBuilder<> IRB(CopyInsertPoint);
  const DataLayout &DL = F.getDataLayout();
  for (Argument &Arg : F.args()) {
    if (Arg.hasByValAttr()) {
      Type *Ty = Arg.getParamByValType();
      const Align Alignment =
          DL.getValueOrABITypeAlignment(Arg.getParamAlign(), Ty);

      AllocaInst *AI = IRB.CreateAlloca(
          Ty, nullptr,
          (Arg.hasName() ? Arg.getName() : "Arg" + Twine(Arg.getArgNo())) +
              ".byval");
      AI->setAlignment(Alignment);
      Arg.replaceAllUsesWith(AI);

      uint64_t AllocSize = DL.getTypeAllocSize(Ty);

      // CombiSan: we need to propagate the init state to the byval alloca
      // use asan_memcpy which already does this transfer (memcpy intrinsic does not)
      // IRB.CreateMemCpy(AI, Alignment, &Arg, Alignment, AllocSize);
      IRB.CreateCall(ASan.AsanMemcpy, {AI, (Value*)(&Arg), ConstantInt::get(IRB.getInt64Ty(), AllocSize)});
    }
  }
}

PHINode *FunctionStackPoisoner::createPHI(IRBuilder<> &IRB, Value *Cond,
                                          Value *ValueIfTrue,
                                          Instruction *ThenTerm,
                                          Value *ValueIfFalse) {
  PHINode *PHI = IRB.CreatePHI(IntptrTy, 2);
  BasicBlock *CondBlock = cast<Instruction>(Cond)->getParent();
  PHI->addIncoming(ValueIfFalse, CondBlock);
  BasicBlock *ThenBlock = ThenTerm->getParent();
  PHI->addIncoming(ValueIfTrue, ThenBlock);
  return PHI;
}

Value *FunctionStackPoisoner::createAllocaForLayout(
    IRBuilder<> &IRB, const ASanStackFrameLayout &L, bool Dynamic) {
  AllocaInst *Alloca;
  if (Dynamic) {
    Alloca = IRB.CreateAlloca(IRB.getInt8Ty(),
                              ConstantInt::get(IRB.getInt64Ty(), L.FrameSize),
                              "MyAlloca");
  } else {
    Alloca = IRB.CreateAlloca(ArrayType::get(IRB.getInt8Ty(), L.FrameSize),
                              nullptr, "MyAlloca");
    assert(Alloca->isStaticAlloca());
  }
  assert((ClRealignStack & (ClRealignStack - 1)) == 0);
  uint64_t FrameAlignment = std::max(L.FrameAlignment, uint64_t(ClRealignStack));
  Alloca->setAlignment(Align(FrameAlignment));
  return IRB.CreatePointerCast(Alloca, IntptrTy);
}

void FunctionStackPoisoner::createDynamicAllocasInitStorage() {
  BasicBlock &FirstBB = *F.begin();
  IRBuilder<> IRB(dyn_cast<Instruction>(FirstBB.begin()));
  DynamicAllocaLayout = IRB.CreateAlloca(IntptrTy, nullptr);
  IRB.CreateStore(Constant::getNullValue(IntptrTy), DynamicAllocaLayout);
  DynamicAllocaLayout->setAlignment(Align(32));
}

void FunctionStackPoisoner::processDynamicAllocas() {
  if (!ClInstrumentDynamicAllocas || DynamicAllocaVec.empty()) {
    assert(DynamicAllocaPoisonCallVec.empty());
    return;
  }

  // Insert poison calls for lifetime intrinsics for dynamic allocas.
  for (const auto &APC : DynamicAllocaPoisonCallVec) {
    assert(APC.InsBefore);
    assert(APC.AI);
    assert(ASan.isInterestingAlloca(*APC.AI));
    assert(!APC.AI->isStaticAlloca());

    IRBuilder<> IRB(APC.InsBefore);
    poisonAlloca(APC.AI, APC.Size, IRB, APC.DoPoison);
    // Dynamic allocas will be unpoisoned unconditionally below in
    // unpoisonDynamicAllocas.
    // Flag that we need unpoison static allocas.
  }

  // Handle dynamic allocas.
  createDynamicAllocasInitStorage();
  for (auto &AI : DynamicAllocaVec)
    handleDynamicAllocaCall(AI);
  unpoisonDynamicAllocas();
}

/// Collect instructions in the entry block after \p InsBefore which initialize
/// permanent storage for a function argument. These instructions must remain in
/// the entry block so that uninitialized values do not appear in backtraces. An
/// added benefit is that this conserves spill slots. This does not move stores
/// before instrumented / "interesting" allocas.
static void findStoresToUninstrumentedArgAllocas(
    AddressSanitizer &ASan, Instruction &InsBefore,
    SmallVectorImpl<Instruction *> &InitInsts) {
  Instruction *Start = InsBefore.getNextNonDebugInstruction();
  for (Instruction *It = Start; It; It = It->getNextNonDebugInstruction()) {
    // Argument initialization looks like:
    // 1) store <Argument>, <Alloca> OR
    // 2) <CastArgument> = cast <Argument> to ...
    //    store <CastArgument> to <Alloca>
    // Do not consider any other kind of instruction.
    //
    // Note: This covers all known cases, but may not be exhaustive. An
    // alternative to pattern-matching stores is to DFS over all Argument uses:
    // this might be more general, but is probably much more complicated.
    if (isa<AllocaInst>(It) || isa<CastInst>(It))
      continue;
    if (auto *Store = dyn_cast<StoreInst>(It)) {
      // The store destination must be an alloca that isn't interesting for
      // ASan to instrument. These are moved up before InsBefore, and they're
      // not interesting because allocas for arguments can be mem2reg'd.
      auto *Alloca = dyn_cast<AllocaInst>(Store->getPointerOperand());
      if (!Alloca || ASan.isInterestingAlloca(*Alloca))
        continue;

      Value *Val = Store->getValueOperand();
      bool IsDirectArgInit = isa<Argument>(Val);
      bool IsArgInitViaCast =
          isa<CastInst>(Val) &&
          isa<Argument>(cast<CastInst>(Val)->getOperand(0)) &&
          // Check that the cast appears directly before the store. Otherwise
          // moving the cast before InsBefore may break the IR.
          Val == It->getPrevNonDebugInstruction();
      bool IsArgInit = IsDirectArgInit || IsArgInitViaCast;
      if (!IsArgInit)
        continue;

      if (IsArgInitViaCast)
        InitInsts.push_back(cast<Instruction>(Val));
      InitInsts.push_back(Store);
      continue;
    }

    // Do not reorder past unknown instructions: argument initialization should
    // only involve casts and stores.
    return;
  }
}

void FunctionStackPoisoner::processStaticAllocas() {

  // CombiSan: mark the safe allocas as uninitialized
  // XXX: do we also need to clean these up from shadow memory?
  // I guess there is a possibility it never gets initialized, and then the stack space gets reused.
  // we should look at lifetime start/ends
  uint64_t Granularity = 1ULL << Mapping.Scale;
  // errs() << "SafeAllocas size: " << SafeAllocas.size() << "\n";
  for(auto *AI : SafeAllocas){

    // TODO: handle non static allocas
    if(!AI->isStaticAlloca()) continue;

    IRBuilder<> IRB(AI->getNextNode());

    // we need to make sure the start aligns with Granularity (?)
    // I think this is always the case for a stack variable anyway
    if(AI->getAlign().value() < Granularity){
      AI->setAlignment(Align(Granularity));
    }

    // Poison the stack red zones at the entry.
    Value *AIShadowPtr = ASan.memToShadow(IRB.CreatePtrToInt(AI, IntptrTy), IRB);

    TypeSize AllocaSize = ASan.getAllocaSizeInBytes(*AI);

    // errs() << "SafeAlloca  " << *AI << " Size: " << AllocaSize << " ShadowPtr " << *AIShadowPtr << "\n";

    SmallVector<uint8_t, 64> UninitBytes;
    UninitBytes.resize(AllocaSize / Granularity, kCombiMSanUn); // uninit 4b blocks
    UninitBytes.resize(UninitBytes.size() + AllocaSize / Granularity, 0);

    const uint64_t valid_bytes = AllocaSize % Granularity;
    if (valid_bytes){ // zero implies all four bytes in the last granule are valid
      // these objects do not have redzones,
      // so we should not set them to have partial redzones, either.
      UninitBytes.push_back(lookUninitNoRz[valid_bytes]);
    }

    copyToShadow(UninitBytes, UninitBytes, IRB, AIShadowPtr);
  }

  if (AllocaVec.empty() ) { // && SafeAllocas.empty()
    assert(StaticAllocaPoisonCallVec.empty());
    return;
  }

  int StackMallocIdx = -1;
  DebugLoc EntryDebugLocation;
  if (auto SP = F.getSubprogram())
    EntryDebugLocation =
        DILocation::get(SP->getContext(), SP->getScopeLine(), 0, SP);

  Instruction *InsBefore = AllocaVec[0];
  IRBuilder<> IRB(InsBefore);

  // Make sure non-instrumented allocas stay in the entry block. Otherwise,
  // debug info is broken, because only entry-block allocas are treated as
  // regular stack slots.
  auto InsBeforeB = InsBefore->getParent();
  assert(InsBeforeB == &F.getEntryBlock());
  for (auto *AI : StaticAllocasToMoveUp)
    if (AI->getParent() == InsBeforeB)
      AI->moveBefore(InsBefore->getIterator());

  // Move stores of arguments into entry-block allocas as well. This prevents
  // extra stack slots from being generated (to house the argument values until
  // they can be stored into the allocas). This also prevents uninitialized
  // values from being shown in backtraces.
  SmallVector<Instruction *, 8> ArgInitInsts;
  findStoresToUninstrumentedArgAllocas(ASan, *InsBefore, ArgInitInsts);
  for (Instruction *ArgInitInst : ArgInitInsts)
    ArgInitInst->moveBefore(InsBefore->getIterator());

  // If we have a call to llvm.localescape, keep it in the entry block.
  if (LocalEscapeCall)
    LocalEscapeCall->moveBefore(InsBefore->getIterator());

  SmallVector<ASanStackVariableDescription, 16> SVD;
  SVD.reserve(AllocaVec.size());
  for (AllocaInst *AI : AllocaVec) {
    // ConstructorAllocas need redzones but no MSan uninit state
    // because the memory gets initialized externally (e.g. in libc++)
    bool CombiSanCtorAlloca = false;
    if(ConstructorAllocas.count(AI)) CombiSanCtorAlloca = true;
    ASanStackVariableDescription D = {AI->getName().data(),
                                      ASan.getAllocaSizeInBytes(*AI),
                                      0,
                                      AI->getAlign().value(),
                                      AI,
                                      0,
                                      0, CombiSanCtorAlloca};
    SVD.push_back(D);
  }

  // Minimal header size (left redzone) is 4 pointers,
  // i.e. 32 bytes on 64-bit platforms and 16 bytes in 32-bit platforms.
  uint64_t MinHeaderSize = std::max((uint64_t)ASan.LongSize / 2, Granularity);
  const ASanStackFrameLayout &L =
      ComputeASanStackFrameLayout(SVD, Granularity, MinHeaderSize);

  // Build AllocaToSVDMap for ASanStackVariableDescription lookup.
  DenseMap<const AllocaInst *, ASanStackVariableDescription *> AllocaToSVDMap;
  for (auto &Desc : SVD)
    AllocaToSVDMap[Desc.AI] = &Desc;

  // Update SVD with information from lifetime intrinsics.
  for (const auto &APC : StaticAllocaPoisonCallVec) {
    assert(APC.InsBefore);
    assert(APC.AI);
    assert(ASan.isInterestingAlloca(*APC.AI));
    assert(APC.AI->isStaticAlloca());

    ASanStackVariableDescription &Desc = *AllocaToSVDMap[APC.AI];
    Desc.LifetimeSize = Desc.Size;
    if (const DILocation *FnLoc = EntryDebugLocation.get()) {
      if (const DILocation *LifetimeLoc = APC.InsBefore->getDebugLoc().get()) {
        if (LifetimeLoc->getFile() == FnLoc->getFile())
          if (unsigned Line = LifetimeLoc->getLine())
            Desc.Line = std::min(Desc.Line ? Desc.Line : Line, Line);
      }
    }
  }

  auto DescriptionString = ComputeASanStackFrameDescription(SVD);
  LLVM_DEBUG(dbgs() << DescriptionString << " --- " << L.FrameSize << "\n");
  uint64_t LocalStackSize = L.FrameSize;
  bool DoStackMalloc =
      ASan.UseAfterReturn != AsanDetectStackUseAfterReturnMode::Never &&
      !ASan.CompileKernel && LocalStackSize <= kMaxStackMallocSize;
  bool DoDynamicAlloca = ClDynamicAllocaStack;
  // Don't do dynamic alloca or stack malloc if:
  // 1) There is inline asm: too often it makes assumptions on which registers
  //    are available.
  // 2) There is a returns_twice call (typically setjmp), which is
  //    optimization-hostile, and doesn't play well with introduced indirect
  //    register-relative calculation of local variable addresses.
  DoDynamicAlloca &= !HasInlineAsm && !HasReturnsTwiceCall;
  DoStackMalloc &= !HasInlineAsm && !HasReturnsTwiceCall;

  Value *StaticAlloca =
      DoDynamicAlloca ? nullptr : createAllocaForLayout(IRB, L, false);

  Value *FakeStack;
  Value *LocalStackBase;
  Value *LocalStackBaseAlloca;
  uint8_t DIExprFlags = DIExpression::ApplyOffset;

  if (DoStackMalloc) {
    LocalStackBaseAlloca =
        IRB.CreateAlloca(IntptrTy, nullptr, "asan_local_stack_base");
    if (ASan.UseAfterReturn == AsanDetectStackUseAfterReturnMode::Runtime) {
      // void *FakeStack = __asan_option_detect_stack_use_after_return
      //     ? __asan_stack_malloc_N(LocalStackSize)
      //     : nullptr;
      // void *LocalStackBase = (FakeStack) ? FakeStack :
      //                        alloca(LocalStackSize);
      Constant *OptionDetectUseAfterReturn = F.getParent()->getOrInsertGlobal(
          kAsanOptionDetectUseAfterReturn, IRB.getInt32Ty());
      Value *UseAfterReturnIsEnabled = IRB.CreateICmpNE(
          IRB.CreateLoad(IRB.getInt32Ty(), OptionDetectUseAfterReturn),
          Constant::getNullValue(IRB.getInt32Ty()));
      Instruction *Term =
          SplitBlockAndInsertIfThen(UseAfterReturnIsEnabled, InsBefore, false);
      IRBuilder<> IRBIf(Term);
      StackMallocIdx = StackMallocSizeClass(LocalStackSize);
      assert(StackMallocIdx <= kMaxAsanStackMallocSizeClass);
      Value *FakeStackValue =
          RTCI.createRuntimeCall(IRBIf, AsanStackMallocFunc[StackMallocIdx],
                                 ConstantInt::get(IntptrTy, LocalStackSize));
      IRB.SetInsertPoint(InsBefore);
      FakeStack = createPHI(IRB, UseAfterReturnIsEnabled, FakeStackValue, Term,
                            ConstantInt::get(IntptrTy, 0));
    } else {
      // assert(ASan.UseAfterReturn == AsanDetectStackUseAfterReturnMode:Always)
      // void *FakeStack = __asan_stack_malloc_N(LocalStackSize);
      // void *LocalStackBase = (FakeStack) ? FakeStack :
      //                        alloca(LocalStackSize);
      StackMallocIdx = StackMallocSizeClass(LocalStackSize);
      FakeStack =
          RTCI.createRuntimeCall(IRB, AsanStackMallocFunc[StackMallocIdx],
                                 ConstantInt::get(IntptrTy, LocalStackSize));
    }
    Value *NoFakeStack =
        IRB.CreateICmpEQ(FakeStack, Constant::getNullValue(IntptrTy));
    Instruction *Term =
        SplitBlockAndInsertIfThen(NoFakeStack, InsBefore, false);
    IRBuilder<> IRBIf(Term);
    Value *AllocaValue =
        DoDynamicAlloca ? createAllocaForLayout(IRBIf, L, true) : StaticAlloca;

    IRB.SetInsertPoint(InsBefore);
    LocalStackBase = createPHI(IRB, NoFakeStack, AllocaValue, Term, FakeStack);
    IRB.CreateStore(LocalStackBase, LocalStackBaseAlloca);
    DIExprFlags |= DIExpression::DerefBefore;
  } else {
    // void *FakeStack = nullptr;
    // void *LocalStackBase = alloca(LocalStackSize);
    FakeStack = ConstantInt::get(IntptrTy, 0);
    LocalStackBase =
        DoDynamicAlloca ? createAllocaForLayout(IRB, L, true) : StaticAlloca;
    LocalStackBaseAlloca = LocalStackBase;
  }

  // It shouldn't matter whether we pass an `alloca` or a `ptrtoint` as the
  // dbg.declare address opereand, but passing a `ptrtoint` seems to confuse
  // later passes and can result in dropped variable coverage in debug info.
  Value *LocalStackBaseAllocaPtr =
      isa<PtrToIntInst>(LocalStackBaseAlloca)
          ? cast<PtrToIntInst>(LocalStackBaseAlloca)->getPointerOperand()
          : LocalStackBaseAlloca;
  assert(isa<AllocaInst>(LocalStackBaseAllocaPtr) &&
         "Variable descriptions relative to ASan stack base will be dropped");

  // Replace Alloca instructions with base+offset.
  for (const auto &Desc : SVD) {
    AllocaInst *AI = Desc.AI;
    replaceDbgDeclare(AI, LocalStackBaseAllocaPtr, DIB, DIExprFlags,
                      Desc.Offset);
    Value *NewAllocaPtr = IRB.CreateIntToPtr(
        IRB.CreateAdd(LocalStackBase, ConstantInt::get(IntptrTy, Desc.Offset)),
        AI->getType());
    AI->replaceAllUsesWith(NewAllocaPtr);
  }

  // The left-most redzone has enough space for at least 4 pointers.
  // Write the Magic value to redzone[0].
  Value *BasePlus0 = IRB.CreateIntToPtr(LocalStackBase, IntptrPtrTy);
  IRB.CreateStore(ConstantInt::get(IntptrTy, kCurrentStackFrameMagic),
                  BasePlus0);
  // Write the frame description constant to redzone[1].
  Value *BasePlus1 = IRB.CreateIntToPtr(
      IRB.CreateAdd(LocalStackBase,
                    ConstantInt::get(IntptrTy, ASan.LongSize / 8)),
      IntptrPtrTy);
  GlobalVariable *StackDescriptionGlobal =
      createPrivateGlobalForString(*F.getParent(), DescriptionString,
                                   /*AllowMerging*/ true, genName("stack"));
  Value *Description = IRB.CreatePointerCast(StackDescriptionGlobal, IntptrTy);
  IRB.CreateStore(Description, BasePlus1);
  // Write the PC to redzone[2].
  Value *BasePlus2 = IRB.CreateIntToPtr(
      IRB.CreateAdd(LocalStackBase,
                    ConstantInt::get(IntptrTy, 2 * ASan.LongSize / 8)),
      IntptrPtrTy);
  IRB.CreateStore(IRB.CreatePointerCast(&F, IntptrTy), BasePlus2);

  const auto &ShadowAfterScope = GetShadowBytesAfterScope(SVD, L);

  // Poison the stack red zones at the entry.
  Value *ShadowBase = ASan.memToShadow(LocalStackBase, IRB);
  // As mask we must use most poisoned case: red zones and after scope.
  // As bytes we can use either the same or just red zones only.
  // CombiSan: Stack #1: poison the stack red zones (upon function entry)
  // CombiSan: Here we have to mark MSan uninitialized (?)

  copyToShadow(ShadowAfterScope, ShadowAfterScope, IRB, ShadowBase);

  if (!StaticAllocaPoisonCallVec.empty()) {
#if 1 // CombiSan: InScope shadow contains uninitialized MSan bits
    // XXX: maybe we should strip lifetime markers, considering
    // there will be much more shadow storing pressure now...?
    // but then use-after-scope may not be detectable.
    const auto &ShadowInScope = GetShadowBytesUninitialized(SVD, L);
#else
    const auto &ShadowInScope = GetShadowBytes(SVD, L);
#endif
    // Poison static allocas near lifetime intrinsics.
    for (const auto &APC : StaticAllocaPoisonCallVec) {
      const ASanStackVariableDescription &Desc = *AllocaToSVDMap[APC.AI];
      assert(Desc.Offset % L.Granularity == 0);
      size_t Begin = Desc.Offset / L.Granularity;
      size_t End = Begin + (APC.Size + L.Granularity - 1) / L.Granularity;

      IRBuilder<> IRB(APC.InsBefore);
      // CombiSan: Stack #2: poison upon lifetime markers (scoping): DoPoison == true for lifetime end
      // CombiSan: ShadowInScope contains MSan uninitialization
      copyToShadow(ShadowAfterScope,
                   APC.DoPoison ? ShadowAfterScope : ShadowInScope, Begin, End,
                   IRB, ShadowBase);
    }
  }

  SmallVector<uint8_t, 64> ShadowClean(ShadowAfterScope.size(), 0);
  SmallVector<uint8_t, 64> ShadowAfterReturn;

  // (Un)poison the stack before all ret instructions.
  for (Instruction *Ret : RetVec) {
    IRBuilder<> IRBRet(Ret);
    // Mark the current frame as retired.
    IRBRet.CreateStore(ConstantInt::get(IntptrTy, kRetiredStackFrameMagic),
                       BasePlus0);
    if (DoStackMalloc) {
      assert(StackMallocIdx >= 0);
      // if FakeStack != 0  // LocalStackBase == FakeStack
      //     // In use-after-return mode, poison the whole stack frame.
      //     if StackMallocIdx <= 4
      //         // For small sizes inline the whole thing:
      //         memset(ShadowBase, kAsanStackAfterReturnMagic, ShadowSize);
      //         **SavedFlagPtr(FakeStack) = 0
      //     else
      //         __asan_stack_free_N(FakeStack, LocalStackSize)
      // else
      //     <This is not a fake stack; unpoison the redzones>
      Value *Cmp =
          IRBRet.CreateICmpNE(FakeStack, Constant::getNullValue(IntptrTy));
      Instruction *ThenTerm, *ElseTerm;
      SplitBlockAndInsertIfThenElse(Cmp, Ret, &ThenTerm, &ElseTerm);

      IRBuilder<> IRBPoison(ThenTerm);
      if (ASan.MaxInlinePoisoningSize != 0 && StackMallocIdx <= 4) {
        int ClassSize = kMinStackMallocSize << StackMallocIdx;
#if 1 // CombiSan: use-after-return uses shadow 0x55 (fully invalid)
        ShadowAfterReturn.resize(ClassSize / L.Granularity, kCombiASanRZ);
#else
        ShadowAfterReturn.resize(ClassSize / L.Granularity,
                                 kAsanStackUseAfterReturnMagic);
#endif
        // CombiSan: Stack #3: The function returns (exits), poison the whole stack frame
        copyToShadow(ShadowAfterReturn, ShadowAfterReturn, IRBPoison,
                     ShadowBase);
        Value *SavedFlagPtrPtr = IRBPoison.CreateAdd(
            FakeStack,
            ConstantInt::get(IntptrTy, ClassSize - ASan.LongSize / 8));
        Value *SavedFlagPtr = IRBPoison.CreateLoad(
            IntptrTy, IRBPoison.CreateIntToPtr(SavedFlagPtrPtr, IntptrPtrTy));
        IRBPoison.CreateStore(
            Constant::getNullValue(IRBPoison.getInt8Ty()),
            IRBPoison.CreateIntToPtr(SavedFlagPtr, IRBPoison.getPtrTy()));
      } else {
        // For larger frames call __asan_stack_free_*.
        RTCI.createRuntimeCall(
            IRBPoison, AsanStackFreeFunc[StackMallocIdx],
            {FakeStack, ConstantInt::get(IntptrTy, LocalStackSize)});
      }

      IRBuilder<> IRBElse(ElseTerm);
      // CombiSan: Stack #4: Not using "fake stack": unpoison the redzones (rezones=0x00)
      copyToShadow(ShadowAfterScope, ShadowClean, IRBElse, ShadowBase);
    } else {
      // CombiSan: Stack #5: We cannot use malloc for the stack: unpoison here (redzones=0x00)
      copyToShadow(ShadowAfterScope, ShadowClean, IRBRet, ShadowBase);
    }
  }

  // We are done. Remove the old unused alloca instructions.
  for (auto *AI : AllocaVec)
    AI->eraseFromParent();
}

void FunctionStackPoisoner::poisonAlloca(Value *V, uint64_t Size,
                                         IRBuilder<> &IRB, bool DoPoison) {
  // For now just insert the call to ASan runtime.
  Value *AddrArg = IRB.CreatePointerCast(V, IntptrTy);
  Value *SizeArg = ConstantInt::get(IntptrTy, Size);
  RTCI.createRuntimeCall(
      IRB, DoPoison ? AsanPoisonStackMemoryFunc : AsanUnpoisonStackMemoryFunc,
      {AddrArg, SizeArg});
}

// Handling llvm.lifetime intrinsics for a given %alloca:
// (1) collect all llvm.lifetime.xxx(%size, %value) describing the alloca.
// (2) if %size is constant, poison memory for llvm.lifetime.end (to detect
//     invalid accesses) and unpoison it for llvm.lifetime.start (the memory
//     could be poisoned by previous llvm.lifetime.end instruction, as the
//     variable may go in and out of scope several times, e.g. in loops).
// (3) if we poisoned at least one %alloca in a function,
//     unpoison the whole stack frame at function exit.
void FunctionStackPoisoner::handleDynamicAllocaCall(AllocaInst *AI) {
  IRBuilder<> IRB(AI);

  const Align Alignment = std::max(Align(kAllocaRzSize), AI->getAlign());
  const uint64_t AllocaRedzoneMask = kAllocaRzSize - 1;

  Value *Zero = Constant::getNullValue(IntptrTy);
  Value *AllocaRzSize = ConstantInt::get(IntptrTy, kAllocaRzSize);
  Value *AllocaRzMask = ConstantInt::get(IntptrTy, AllocaRedzoneMask);

  // Since we need to extend alloca with additional memory to locate
  // redzones, and OldSize is number of allocated blocks with
  // ElementSize size, get allocated memory size in bytes by
  // OldSize * ElementSize.
  const unsigned ElementSize =
      F.getDataLayout().getTypeAllocSize(AI->getAllocatedType());
  Value *OldSize =
      IRB.CreateMul(IRB.CreateIntCast(AI->getArraySize(), IntptrTy, false),
                    ConstantInt::get(IntptrTy, ElementSize));

  // PartialSize = OldSize % 32
  Value *PartialSize = IRB.CreateAnd(OldSize, AllocaRzMask);

  // Misalign = kAllocaRzSize - PartialSize;
  Value *Misalign = IRB.CreateSub(AllocaRzSize, PartialSize);

  // PartialPadding = Misalign != kAllocaRzSize ? Misalign : 0;
  Value *Cond = IRB.CreateICmpNE(Misalign, AllocaRzSize);
  Value *PartialPadding = IRB.CreateSelect(Cond, Misalign, Zero);

  // AdditionalChunkSize = Alignment + PartialPadding + kAllocaRzSize
  // Alignment is added to locate left redzone, PartialPadding for possible
  // partial redzone and kAllocaRzSize for right redzone respectively.
  Value *AdditionalChunkSize = IRB.CreateAdd(
      ConstantInt::get(IntptrTy, Alignment.value() + kAllocaRzSize),
      PartialPadding);

  Value *NewSize = IRB.CreateAdd(OldSize, AdditionalChunkSize);

  // Insert new alloca with new NewSize and Alignment params.
  AllocaInst *NewAlloca = IRB.CreateAlloca(IRB.getInt8Ty(), NewSize);
  NewAlloca->setAlignment(Alignment);

  // NewAddress = Address + Alignment
  Value *NewAddress =
      IRB.CreateAdd(IRB.CreatePtrToInt(NewAlloca, IntptrTy),
                    ConstantInt::get(IntptrTy, Alignment.value()));

  // Insert __asan_alloca_poison call for new created alloca.
  RTCI.createRuntimeCall(IRB, AsanAllocaPoisonFunc, {NewAddress, OldSize});

  // Store the last alloca's address to DynamicAllocaLayout. We'll need this
  // for unpoisoning stuff.
  IRB.CreateStore(IRB.CreatePtrToInt(NewAlloca, IntptrTy), DynamicAllocaLayout);

  Value *NewAddressPtr = IRB.CreateIntToPtr(NewAddress, AI->getType());

  // Replace all uses of AddessReturnedByAlloca with NewAddressPtr.
  AI->replaceAllUsesWith(NewAddressPtr);

  // We are done. Erase old alloca from parent.
  AI->eraseFromParent();
}

// isSafeAccess returns true if Addr is always inbounds with respect to its
// base object. For example, it is a field access or an array access with
// constant inbounds index.
bool AddressSanitizer::isSafeAccess(ObjectSizeOffsetVisitor &ObjSizeVis,
                                    Value *Addr, TypeSize TypeStoreSize) const {
  if (TypeStoreSize.isScalable())
    // TODO: We can use vscale_range to convert a scalable value to an
    // upper bound on the access size.
    return false;

  SizeOffsetAPInt SizeOffset = ObjSizeVis.compute(Addr);
  if (!SizeOffset.bothKnown())
    return false;

  uint64_t Size = SizeOffset.Size.getZExtValue();
  int64_t Offset = SizeOffset.Offset.getSExtValue();

  // Three checks are required to ensure safety:
  // . Offset >= 0  (since the offset is given from the base ptr)
  // . Size >= Offset  (unsigned)
  // . Size - Offset >= NeededSize  (unsigned)
  return Offset >= 0 && Size >= uint64_t(Offset) &&
         Size - uint64_t(Offset) >= TypeStoreSize / 8;
}
