//===- ASanStackFrameLayout.h - ComputeASanStackFrameLayout -----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This header defines ComputeASanStackFrameLayout and auxiliary data structs.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_TRANSFORMS_UTILS_ASANSTACKFRAMELAYOUT_H
#define LLVM_TRANSFORMS_UTILS_ASANSTACKFRAMELAYOUT_H
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"

namespace llvm {

class AllocaInst;

// CombiSan performance lower bound: MSan bits are always set to zero
// #define COMBISAN_BENCH_LOWER

// These magic constants should be the same as in
// in asan_internal.h from ASan runtime in compiler-rt.
static const int kAsanStackLeftRedzoneMagic = 0xf1;
static const int kAsanStackMidRedzoneMagic = 0xf2;
static const int kAsanStackRightRedzoneMagic = 0xf3;
static const int kAsanStackUseAfterReturnMagic = 0xf5;
static const int kAsanStackUseAfterScopeMagic = 0xf8;

static const int kCombiASanRZ = 0x55;  // invalid (complete redzone)
static const int kCombiASan13 = 0x54;  // 1 valid 3 invalid: (01) (01) (01) (00)
static const int kCombiASan22 = 0x50;  // 2 valid 2 invalid: (01) (01) (00) (00)
static const int kCombiASan31 = 0x40;  // 3 valid 1 invalid: (01) (00) (00) (00)

#ifdef COMBISAN_BENCH_LOWER
// lower bound benchmark: MSan bits are initialized to zero
// lower bound because this promotes zero-page dedup and possibly other optimizations
const int kCombiMSanUn = 0x00;
const int kCombiMSan13 = kCombiASan13;
const int kCombiMSan22 = kCombiASan22;
const int kCombiMSan31 = kCombiASan31;
static const int kCombiMSanValid13 = 0x00;
static const int kCombiMSanValid22 = 0x00;
static const int kCombiMSanValid31 = 0x00;
#else
static const int kCombiMSanUn = 0xAA;  // fully valid, but uninitialized
static const int kCombiMSan13 = 0x56;  // 1 valid 3 invalid: (01) (01) (01) (10)
static const int kCombiMSan22 = 0x5A;  // 2 valid 2 invalid: (01) (01) (10) (10)
static const int kCombiMSan31 = 0x6A;  // 3 valid 1 invalid: (01) (10) (10) (10)
// partial MSan (special case for safe objects that do not have redzones)
static const int kCombiMSanValid13 = 0xA8;  // 1 valid 3 uninit: (10) (10) (10) (00)
static const int kCombiMSanValid22 = 0xA0;  // 2 valid 2 uninit: (10) (10) (00) (00)
static const int kCombiMSanValid31 = 0x80;  // 3 valid 1 uninit: (10) (00) (00) (00)
#endif

static const uint8_t lookupRedzone[4] = {0x00, kCombiASan13, kCombiASan22, kCombiASan31};
static const uint8_t lookupUninit[4] = {kCombiASanRZ, kCombiMSan13, kCombiMSan22, kCombiMSan31};
static const uint8_t lookUninitNoRz[4] = {kCombiMSanUn, kCombiMSanValid13, kCombiMSanValid22, kCombiMSanValid31};

// Input/output data struct for ComputeASanStackFrameLayout.
struct ASanStackVariableDescription {
  const char *Name;    // Name of the variable that will be displayed by asan
                       // if a stack-related bug is reported.
  uint64_t Size;       // Size of the variable in bytes.
  size_t LifetimeSize; // Size in bytes to use for lifetime analysis check.
                       // Will be rounded up to Granularity.
  uint64_t Alignment;  // Alignment of the variable (power of 2).
  AllocaInst *AI;      // The actual AllocaInst.
  size_t Offset;       // Offset from the beginning of the frame;
                       // set by ComputeASanStackFrameLayout.
  unsigned Line;       // Line number.
  bool CombiSanCtorAlloca; // alloca used as C++ constructor memory
};

// Output data struct for ComputeASanStackFrameLayout.
struct ASanStackFrameLayout {
  uint64_t Granularity;     // Shadow granularity.
  uint64_t FrameAlignment;  // Alignment for the entire frame.
  uint64_t FrameSize;       // Size of the frame in bytes.
};

ASanStackFrameLayout ComputeASanStackFrameLayout(
    // The array of stack variables. The elements may get reordered and changed.
    SmallVectorImpl<ASanStackVariableDescription> &Vars,
    // AddressSanitizer's shadow granularity. Usually 8, may also be 16, 32, 64.
    uint64_t Granularity,
    // The minimal size of the left-most redzone (header).
    // At least 4 pointer sizes, power of 2, and >= Granularity.
    // The resulting FrameSize should be multiple of MinHeaderSize.
    uint64_t MinHeaderSize);

// Compute frame description, see DescribeAddressIfStack in ASan runtime.
SmallString<64> ComputeASanStackFrameDescription(
    const SmallVectorImpl<ASanStackVariableDescription> &Vars);

// Returns shadow bytes with marked red zones. This shadow represents the state
// if the stack frame when all local variables are inside of the own scope.
SmallVector<uint8_t, 64>
GetShadowBytes(const SmallVectorImpl<ASanStackVariableDescription> &Vars,
               const ASanStackFrameLayout &Layout);

// Returns shadow bytes with marked red zones. This shadow represents the state
// if the stack frame when all local variables are inside of the own scope,
// but uninitialized for the partially valid granules (MSan).
SmallVector<uint8_t, 64>
GetRedzonesUninitialized(const SmallVectorImpl<ASanStackVariableDescription> &Vars,
               const ASanStackFrameLayout &Layout);

// Returns shadow bytes with marked red zones and after scope. This shadow
// represents the state if the stack frame when all local variables are inside
// of the own scope, but uninitialized (MSan).
SmallVector<uint8_t, 64> GetShadowBytesUninitialized(
  // The array of stack variables. The elements may get reordered and changed.
  const SmallVectorImpl<ASanStackVariableDescription> &Vars,
  const ASanStackFrameLayout &Layout);

// Returns shadow bytes with marked red zones and after scope. This shadow
// represents the state if the stack frame when all local variables are outside
// of the own scope.
SmallVector<uint8_t, 64> GetShadowBytesAfterScope(
    // The array of stack variables. The elements may get reordered and changed.
    const SmallVectorImpl<ASanStackVariableDescription> &Vars,
    const ASanStackFrameLayout &Layout);

} // llvm namespace

#endif  // LLVM_TRANSFORMS_UTILS_ASANSTACKFRAMELAYOUT_H
