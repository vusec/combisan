//===-- asan_internal.h -----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// ASan-private header which defines various general utilities.
//===----------------------------------------------------------------------===//
#ifndef ASAN_INTERNAL_H
#define ASAN_INTERNAL_H

#include "asan_flags.h"
#include "asan_interface_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#  error \
      "The AddressSanitizer run-time should not be instrumented by AddressSanitizer"
#endif

// Build-time configuration options.

// If set, asan will intercept C++ exception api call(s).
#ifndef ASAN_HAS_EXCEPTIONS
#  define ASAN_HAS_EXCEPTIONS 1
#endif

// If set, values like allocator chunk size, as well as defaults for some flags
// will be changed towards less memory overhead.
#ifndef ASAN_LOW_MEMORY
#  if SANITIZER_IOS || SANITIZER_ANDROID
#    define ASAN_LOW_MEMORY 1
#  else
#    define ASAN_LOW_MEMORY 0
#  endif
#endif

#ifndef ASAN_DYNAMIC
#  ifdef PIC
#    define ASAN_DYNAMIC 1
#  else
#    define ASAN_DYNAMIC 0
#  endif
#endif

// All internal functions in asan reside inside the __asan namespace
// to avoid namespace collisions with the user programs.
// Separate namespace also makes it simpler to distinguish the asan run-time
// functions from the instrumented user code in a profile.
namespace __asan {

class AsanThread;
using __sanitizer::StackTrace;

void AsanInitFromRtl();
bool TryAsanInitFromRtl();

// asan_win.cpp
void InitializePlatformExceptionHandlers();
// Returns whether an address is a valid allocated system heap block.
// 'addr' must point to the beginning of the block.
bool IsSystemHeapAddress(uptr addr);

// asan_rtl.cpp
void PrintAddressSpaceLayout();
void NORETURN ShowStatsAndAbort();

// asan_shadow_setup.cpp
void InitializeShadowMemory();

// asan_malloc_linux.cpp / asan_malloc_mac.cpp
void ReplaceSystemMalloc();

// asan_linux.cpp / asan_mac.cpp / asan_win.cpp
uptr FindDynamicShadowStart();
void AsanCheckDynamicRTPrereqs();
void AsanCheckIncompatibleRT();

// Unpoisons platform-specific stacks.
// Returns true if all stacks have been unpoisoned.
bool PlatformUnpoisonStacks();

// asan_rtl.cpp
// Unpoison a region containing a stack.
// Performs a sanity check and warns if the bounds don't look right.
// The warning contains the type string to identify the stack type.
void UnpoisonStack(uptr bottom, uptr top, const char *type);

// asan_thread.cpp
AsanThread *CreateMainThread();

// Support function for __asan_(un)register_image_globals. Searches for the
// loaded image containing `needle' and then enumerates all global metadata
// structures declared in that image, applying `op' (e.g.,
// __asan_(un)register_globals) to them.
typedef void (*globals_op_fptr)(__asan_global *, uptr);
void AsanApplyToGlobals(globals_op_fptr op, const void *needle);

void AsanOnDeadlySignal(int, void *siginfo, void *context);

void SignContextStack(void *context);
void ReadContextStack(void *context, uptr *stack, uptr *ssize);
void StopInitOrderChecking();

// Wrapper for TLS/TSD.
void AsanTSDInit(void (*destructor)(void *tsd));
void *AsanTSDGet();
void AsanTSDSet(void *tsd);
void PlatformTSDDtor(void *tsd);

void AppendToErrorMessageBuffer(const char *buffer);

void *AsanDlSymNext(const char *sym);

// Returns `true` iff most of ASan init process should be skipped due to the
// ASan library being loaded via `dlopen()`. Platforms may perform any
// `dlopen()` specific initialization inside this function.
bool HandleDlopenInit();

void InstallAtExitCheckLeaks();
void InstallAtForkHandler();

#define ASAN_ON_ERROR() \
  if (&__asan_on_error) \
  __asan_on_error()

bool AsanInited();
extern bool replace_intrin_cached;
extern void (*death_callback)(void);
// These magic values are written to shadow for better error
// reporting.
const int kAsanHeapLeftRedzoneMagic = 0xfa;
const int kAsanHeapFreeMagic = 0xfd;
const int kAsanStackLeftRedzoneMagic = 0xf1;
const int kAsanStackMidRedzoneMagic = 0xf2;
const int kAsanStackRightRedzoneMagic = 0xf3;
const int kAsanStackAfterReturnMagic = 0xf5;
const int kAsanInitializationOrderMagic = 0xf6;
const int kAsanUserPoisonedMemoryMagic = 0xf7;
const int kAsanContiguousContainerOOBMagic = 0xfc;
const int kAsanStackUseAfterScopeMagic = 0xf8;
const int kAsanGlobalRedzoneMagic = 0xf9;
const int kAsanInternalHeapMagic = 0xfe;
const int kAsanArrayCookieMagic = 0xac; // CombiSan: still in use
const int kAsanIntraObjectRedzone = 0xbb;
const int kAsanAllocaLeftMagic = 0xca;
const int kAsanAllocaRightMagic = 0xcb;

static const uptr kCurrentStackFrameMagic = 0x41B58AB3;
static const uptr kRetiredStackFrameMagic = 0x45E0360E;

// CombiSan shadow values
const int kCombiASanRZ = 0x55;  // invalid (complete redzone)
const int kCombiASan13 = 0x54;  // 1 valid 3 invalid: (01) (01) (01) (00)
const int kCombiASan22 = 0x50;  // 2 valid 2 invalid: (01) (01) (00) (00)
const int kCombiASan31 = 0x40;  // 3 valid 1 invalid: (01) (00) (00) (00)

#ifdef COMBISAN_BENCH_LOWER
// lower bound benchmark: MSan bits are initialized to zero
// lower bound because this promotes zero-page dedup and possibly other optimizations
const unsigned long long kCombiMSanUn8B = 0x00;
const int kCombiMSanUn = 0x00;
const int kCombiMSan13 = kCombiASan13;
const int kCombiMSan22 = kCombiASan22;
const int kCombiMSan31 = kCombiASan31;
#else
const unsigned long long kCombiMSanUn8B = 0xAAAAAAAAAAAAAAAAULL;
const int kCombiMSanUn = 0xAA;  // fully valid-uninit (no redzone)
const int kCombiMSan13 = 0x56;  // 1 valid-uninit 3 redzone: (01) (01) (01) (10)
const int kCombiMSan22 = 0x5A;  // 2 valid-uninit 2 redzone: (01) (01) (10) (10)
const int kCombiMSan31 = 0x6A;  // 3 valid-uninit 1 redzone: (01) (10) (10) (10)
#endif

// partial MSan: (created by individual validation stores)
const int kCombiMSanValid13 = 0xA8;  // 1 valid 3 uninit: (10) (10) (10) (00)
const int kCombiMSanValid22 = 0xA0;  // 2 valid 2 uninit: (10) (10) (00) (00)
const int kCombiMSanValid31 = 0x80;  // 3 valid 1 uninit: (10) (00) (00) (00)


// CombiSan masks
const unsigned char kCombiSelectASan = 0x55;  // mask off MSan's bits, only select ASan
const unsigned long long kCombiSelectASan8B = 0x5555555555555555ULL;  // mask off MSan's bits, only select ASan

#ifdef COMBISAN_PROFILING
// CombiSan profiling
#define MSAN_MAX_MAP 1048576
extern u64 MSanViolationCnt;
extern u64 MSanMappy[MSAN_MAX_MAP];
#endif

// /* Environment variable used to pass COMBISAN SHM ID to the called program. */
// #define COMBISAN_SHM_ENV_VAR "__COMBISAN_AFL_SHM_ID"

// // combisan area to communicate violations
// extern u8*combisan_area_ptr;

// // map size
// #define AFL_MAP_SIZE_POW2 16
// #define AFL_MAP_SIZE (1U << AFL_MAP_SIZE_POW2)

}  // namespace __asan

#endif  // ASAN_INTERNAL_H
