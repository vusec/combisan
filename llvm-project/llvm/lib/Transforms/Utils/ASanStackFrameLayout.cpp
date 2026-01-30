//===-- ASanStackFrameLayout.cpp - helper for AddressSanitizer ------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Definition of ComputeASanStackFrameLayout (see ASanStackFrameLayout.h).
//
//===----------------------------------------------------------------------===//
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>

namespace llvm {

// We sort the stack variables by alignment (largest first) to minimize
// unnecessary large gaps due to alignment.
// It is tempting to also sort variables by size so that larger variables
// have larger redzones at both ends. But reordering will make report analysis
// harder, especially when temporary unnamed variables are present.
// So, until we can provide more information (type, line number, etc)
// for the stack variables we avoid reordering them too much.
static inline bool CompareVars(const ASanStackVariableDescription &a,
                               const ASanStackVariableDescription &b) {
  return a.Alignment > b.Alignment;
}

// We also force minimal alignment for all vars to kMinAlignment so that vars
// with e.g. alignment 1 and alignment 16 do not get reordered by CompareVars.
static const uint64_t kMinAlignment = 16;

// We want to add a full redzone after every variable.
// The larger the variable Size the larger is the redzone.
// The resulting frame size is a multiple of Alignment.
static uint64_t VarAndRedzoneSize(uint64_t Size, uint64_t Granularity,
                                  uint64_t Alignment) {
  uint64_t Res = 0;
  if (Size <= 4)  Res = 16;
  else if (Size <= 16) Res = 32;
  else if (Size <= 128) Res = Size + 32;
  else if (Size <= 512) Res = Size + 64;
  else if (Size <= 4096) Res = Size + 128;
  else                   Res = Size + 256;
  return alignTo(std::max(Res, 2 * Granularity), Alignment);
}

ASanStackFrameLayout
ComputeASanStackFrameLayout(SmallVectorImpl<ASanStackVariableDescription> &Vars,
                            uint64_t Granularity, uint64_t MinHeaderSize) {
  assert(Granularity >= 8 && Granularity <= 64 &&
         (Granularity & (Granularity - 1)) == 0);
  assert(MinHeaderSize >= 16 && (MinHeaderSize & (MinHeaderSize - 1)) == 0 &&
         MinHeaderSize >= Granularity);
  const size_t NumVars = Vars.size();
  assert(NumVars > 0);
  for (size_t i = 0; i < NumVars; i++)
    Vars[i].Alignment = std::max(Vars[i].Alignment, kMinAlignment);

  llvm::stable_sort(Vars, CompareVars);

  ASanStackFrameLayout Layout;
  Layout.Granularity = Granularity;
  Layout.FrameAlignment = std::max(Granularity, Vars[0].Alignment);
  uint64_t Offset =
      std::max(std::max(MinHeaderSize, Granularity), Vars[0].Alignment);
  assert((Offset % Granularity) == 0);
  for (size_t i = 0; i < NumVars; i++) {
    bool IsLast = i == NumVars - 1;
    uint64_t Alignment = std::max(Granularity, Vars[i].Alignment);
    (void)Alignment;  // Used only in asserts.
    uint64_t Size = Vars[i].Size;
    assert((Alignment & (Alignment - 1)) == 0);
    assert(Layout.FrameAlignment >= Alignment);
    assert((Offset % Alignment) == 0);
    assert(Size > 0);
    uint64_t NextAlignment =
        IsLast ? Granularity : std::max(Granularity, Vars[i + 1].Alignment);
    uint64_t SizeWithRedzone =
        VarAndRedzoneSize(Size, Granularity, NextAlignment);
    Vars[i].Offset = Offset;
    Offset += SizeWithRedzone;
  }
  if (Offset % MinHeaderSize) {
    Offset += MinHeaderSize - (Offset % MinHeaderSize);
  }
  Layout.FrameSize = Offset;
  assert((Layout.FrameSize % MinHeaderSize) == 0);
  return Layout;
}

SmallString<64> ComputeASanStackFrameDescription(
    const SmallVectorImpl<ASanStackVariableDescription> &Vars) {
  SmallString<2048> StackDescriptionStorage;
  raw_svector_ostream StackDescription(StackDescriptionStorage);
  StackDescription << Vars.size();

  for (const auto &Var : Vars) {
    std::string Name = Var.Name;
    if (Var.Line) {
      Name += ":";
      Name += to_string(Var.Line);
    }
    StackDescription << " " << Var.Offset << " " << Var.Size << " "
                     << Name.size() << " " << Name;
  }
  return StackDescription.str();
}

SmallVector<uint8_t, 64>
GetShadowBytes(const SmallVectorImpl<ASanStackVariableDescription> &Vars,
               const ASanStackFrameLayout &Layout) {
  assert(Vars.size() > 0);
  SmallVector<uint8_t, 64> SB;
  SB.clear();
  const uint64_t Granularity = Layout.Granularity;

  // for this call we do not consider MSan uninitialization,
  // because this is used for use-after-scope
  // such bugs we want to identify as ASan-originating
  // uint8_t lookup[4] = {0x00, 0x54, 0x50, 0x40};

  // CombiSan: f1 --> 0x55 (4 fully invalid bytes)
  SB.resize(Vars[0].Offset / Granularity, kCombiASanRZ); // was kAsanStackLeftRedzoneMagic
  for (const auto &Var : Vars) {
    // CombiSan: f2 --> 0x55 (4 fully invalid bytes)
    SB.resize(Var.Offset / Granularity, kCombiASanRZ); // was kAsanStackMidRedzoneMagic

    SB.resize(SB.size() + Var.Size / Granularity, 0);
    // CombiSan: here we insert the "remaining distance to redzone" in valid bytes
    // normally, ASan adds size % granularity so e.g.:
    // for a 14 byte object to reach the 16 byte alignment it needs 0x02 (12 + 2 valid bytes)
    // for a 15 byte object to reach the 16 byte alignment it needs 0x03 (12 + 3 valid bytes)
    // for CombiSan we need the number of valid bytes to be represented by the shadow bits
#if 1 // CombiSan
    const uint64_t valid_bytes = Var.Size % Granularity;
    if (valid_bytes){ // zero implies all four bytes in the last granule are valid
      SB.push_back(lookupRedzone[valid_bytes]);
    }
#else
    if (Var.Size % Granularity)
      SB.push_back(Var.Size % Granularity);
#endif
  }
  // CombiSan: f3 --> 0x55 (4 fully invalid bytes)
  SB.resize(Layout.FrameSize / Granularity, kCombiASanRZ); // was kAsanStackRightRedzoneMagic
  return SB;
}

// CombiSan: Partially valid redzones require uninitialized state
SmallVector<uint8_t, 64>
GetRedzonesUninitialized(const SmallVectorImpl<ASanStackVariableDescription> &Vars,
               const ASanStackFrameLayout &Layout) {
  assert(Vars.size() > 0);
  SmallVector<uint8_t, 64> SB;
  SB.clear();
  const uint64_t Granularity = Layout.Granularity;

  // uint8_t lookup[4] = {0x55, 0x56, 0x5A, 0x6A};

  // CombiSan: f1 --> 0x55 (4 fully invalid bytes)
  SB.resize(Vars[0].Offset / Granularity, kCombiASanRZ); // was kAsanStackLeftRedzoneMagic
  for (const auto &Var : Vars) {
    // CombiSan: f2 --> 0x55 (4 fully invalid bytes)
    SB.resize(Var.Offset / Granularity, kCombiASanRZ); // was kAsanStackMidRedzoneMagic

    SB.resize(SB.size() + Var.Size / Granularity, 0);
    // CombiSan: here we insert the "remaining distance to redzone" in valid bytes
    // normally, ASan adds size % granularity so e.g.:
    // for a 14 byte object to reach the 16 byte alignment it needs 0x02 (12 + 2 valid bytes)
    // for a 15 byte object to reach the 16 byte alignment it needs 0x03 (12 + 3 valid bytes)
    // for CombiSan we need the number of valid bytes to be represented by the shadow bits
    // here: the valid bytes are marked as uninitialized for MSan
    const uint64_t valid_bytes = Var.Size % Granularity;
    if (valid_bytes){ // zero implies all four bytes in the last granule are valid
      if(Var.CombiSanCtorAlloca)
        SB.push_back(lookupRedzone[valid_bytes]);
      else
        SB.push_back(lookupUninit[valid_bytes]);
    }

  }
  // CombiSan: f3 --> 0x55 (4 fully invalid bytes)
  SB.resize(Layout.FrameSize / Granularity, kCombiASanRZ); // was kAsanStackRightRedzoneMagic
  return SB;
}


// CombiSan: Stack object with uninitialized state (MSan)
SmallVector<uint8_t, 64> GetShadowBytesUninitialized(
    const SmallVectorImpl<ASanStackVariableDescription> &Vars,
    const ASanStackFrameLayout &Layout) {
  SmallVector<uint8_t, 64> SB = GetRedzonesUninitialized(Vars, Layout);
  const uint64_t Granularity = Layout.Granularity;

  // CombiSan: the original GetShadowBytesAfterScope code marks the entire
  // object as kAsanStackUseAfterScopeMagic without accounting for partial
  // validity, because it is going out of scope anyway
  // we need to stop before any partial granules are overwritten.

  for (const auto &Var : Vars) {
    assert(Var.LifetimeSize <= Var.Size);
    const uint64_t LifetimeShadowSize = (Var.LifetimeSize) / Granularity; // dont align up
    const uint64_t Offset = Var.Offset / Granularity;

    // CombiSan: uninitialized 0xAA
    int poison = kCombiMSanUn;
    if(Var.CombiSanCtorAlloca) poison = 0; // no uninit state for ctor allocas
    std::fill(SB.begin() + Offset, SB.begin() + Offset + LifetimeShadowSize, poison);
  }
  return SB;
}

SmallVector<uint8_t, 64> GetShadowBytesAfterScope(
    const SmallVectorImpl<ASanStackVariableDescription> &Vars,
    const ASanStackFrameLayout &Layout) {
  SmallVector<uint8_t, 64> SB = GetRedzonesUninitialized(Vars, Layout);
  const uint64_t Granularity = Layout.Granularity;

  for (const auto &Var : Vars) {
    assert(Var.LifetimeSize <= Var.Size);
    const uint64_t LifetimeShadowSize =
        (Var.LifetimeSize + Granularity - 1) / Granularity;
    const uint64_t Offset = Var.Offset / Granularity;
#if 1 // CombiSan: use-after-scope uses shadow 0x55 (fully invalid)
    std::fill(SB.begin() + Offset, SB.begin() + Offset + LifetimeShadowSize,
              kCombiASanRZ); // was kAsanStackUseAfterScopeMagic
#else
    std::fill(SB.begin() + Offset, SB.begin() + Offset + LifetimeShadowSize,
              kAsanStackUseAfterScopeMagic);
#endif

#ifndef COMBISAN_BENCH_LOWER
    // make sure not to apply this block of code if kCombiMSanUn=0x00 (COMBISAN_BENCH_LOWER)
    // because it will trip over if(!ShadowMask[i]) checks in copyToShadow()
    // the following fill() is relevant for setting set dynamic allocas to uninitialized 
    // when they do not have start/end lifetime markers

    // CombiSan: uninitialized 0xAA
    uint64_t ShadowSize = LifetimeShadowSize;
    if(LifetimeShadowSize == 0){ // no lifetime markers, no size known (for dyn allocas with constant size)
      ShadowSize = (Var.Size) / Granularity;  // dont align up

      int poison = kCombiMSanUn;
      if(Var.CombiSanCtorAlloca) poison = 0; // no uninit state for ctor allocas
      std::fill(SB.begin() + Offset, SB.begin() + Offset + ShadowSize, poison);
    }
#endif
  }

  return SB;
}

} // llvm namespace
