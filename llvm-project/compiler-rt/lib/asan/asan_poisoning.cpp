//===-- asan_poisoning.cpp ------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Shadow memory poisoning by ASan RTL and by user application.
//===----------------------------------------------------------------------===//

#include "asan_poisoning.h"

#include "asan/asan_mapping.h"
#include "asan_report.h"
#include "asan_stack.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_interface_internal.h"
#include "sanitizer_common/sanitizer_libc.h"

namespace __asan {

static atomic_uint8_t can_poison_memory;

void SetCanPoisonMemory(bool value) {
  atomic_store(&can_poison_memory, value, memory_order_release);
}

bool CanPoisonMemory() {
  return atomic_load(&can_poison_memory, memory_order_acquire);
}

void PoisonShadow(uptr addr, uptr size, u8 value) {
  if (value && !CanPoisonMemory()) return;
  CHECK(AddrIsAlignedByGranularity(addr));
  CHECK(AddrIsInMem(addr));
  CHECK(AddrIsAlignedByGranularity(addr + size));
  CHECK(AddrIsInMem(addr + size - ASAN_SHADOW_GRANULARITY));
  CHECK(REAL(memset));
  FastPoisonShadow(addr, size, value);
}

void PoisonShadowPartialRightRedzone(uptr addr,
                                     uptr size,
                                     uptr redzone_size,
                                     u8 value) {
  if (!CanPoisonMemory()) return;
  CHECK(AddrIsAlignedByGranularity(addr));
  CHECK(AddrIsInMem(addr));
  FastPoisonShadowPartialRightRedzone(addr, size, redzone_size, value);
}

struct ShadowSegmentEndpoint {
  u8 *chunk;
  s8 offset;  // in [0, ASAN_SHADOW_GRANULARITY)
  s8 value;  // = *chunk;

  explicit ShadowSegmentEndpoint(uptr address) {
    chunk = (u8*)MemToShadow(address);
    offset = address & (ASAN_SHADOW_GRANULARITY - 1);
    value = *chunk;
  }
};

void AsanPoisonOrUnpoisonIntraObjectRedzone(uptr ptr, uptr size, bool poison) {
  uptr end = ptr + size;
  if (Verbosity()) {
    Printf("__asan_%spoison_intra_object_redzone [%p,%p) %zd\n",
           poison ? "" : "un", (void *)ptr, (void *)end, size);
    if (Verbosity() >= 2)
      PRINT_CURRENT_STACK();
  }
  CHECK(size);
  CHECK_LE(size, 4096);
  CHECK(IsAligned(end, ASAN_SHADOW_GRANULARITY));
  if (!IsAligned(ptr, ASAN_SHADOW_GRANULARITY)) {
#if 1 // CombiSan: intra-obj partial redzone
    *(u8 *)MemToShadow(ptr) = poison ? LookupPartial[static_cast<u8>(ptr % ASAN_SHADOW_GRANULARITY)] : 0;
#else
    *(u8 *)MemToShadow(ptr) = poison ? static_cast<u8>(ptr % ASAN_SHADOW_GRANULARITY) : 0;
#endif
    ptr |= ASAN_SHADOW_GRANULARITY - 1;
    ptr++;
  }
  for (; ptr < end; ptr += ASAN_SHADOW_GRANULARITY)
    *(u8*)MemToShadow(ptr) = poison ? kCombiASanRZ : 0; // was kAsanIntraObjectRedzone
}

}  // namespace __asan

// ---------------------- Interface ---------------- {{{1
using namespace __asan;

// Current implementation of __asan_(un)poison_memory_region doesn't check
// that user program (un)poisons the memory it owns. It poisons memory
// conservatively, and unpoisons progressively to make sure asan shadow
// mapping invariant is preserved (see detailed mapping description here:
// https://github.com/google/sanitizers/wiki/AddressSanitizerAlgorithm).
//
// * if user asks to poison region [left, right), the program poisons
// at least [left, AlignDown(right)).
// * if user asks to unpoison region [left, right), the program unpoisons
// at most [AlignDown(left), right).
void __asan_poison_memory_region(void const volatile *addr, uptr size) {
  if (!flags()->allow_user_poisoning || size == 0) return;

#if 1 // CombiSan
  // poison bytes until the start is aligned
  uptr beg_aln_up = RoundUpTo((uptr)addr, ASAN_SHADOW_GRANULARITY);
  uptr beg_delta = beg_aln_up - (uptr)addr;

  if(beg_delta){
    u8 *shadow = (u8 *)MemToShadow((uptr)addr); // rounds down
    if(beg_delta < size){
      // there are 'beg_delta' bytes that need to be poisoned in the previous granule
      // so (4-delta) valid bytes followed by (delta) invalid bytes
      *shadow = LookupPartial[ASAN_SHADOW_GRANULARITY-beg_delta];
      size -= beg_delta; // we already poisoned beg_delta bytes
    }
    else{
      // sub-granule size: size <= beg_delta, so only poison 'size' bytes
      uptr beg_aln_down = RoundDownTo((uptr)addr, ASAN_SHADOW_GRANULARITY);
      uptr beg_offset = (uptr)addr - beg_aln_down;

      // granule: 'beg_offset' valid bytes, 'size' invalid bytes, '4-size' valid bytes
      u8 partial = 0;
      for (u8 i = beg_offset; i < beg_offset+size; i++) {
        partial |= (1 << (i * 2));  // set only the ASan bit
      }

      *shadow = partial;
      return;
    }
  }

  uptr aligned_size = size & ~(ASAN_SHADOW_GRANULARITY - 1);
  FastPoisonShadow(beg_aln_up, aligned_size, kCombiASanRZ); // redzone

  // like ASan, only poison up to AlignDown(right) -- skip block below

  // uptr end_delta = size - aligned_size;
  // if(end_delta){
  //   // there are 'end_delta' bytes left to poison in the last granule
  //   u8 *shadow = (u8 *)MemToShadow((uptr)beg_aln_up+aligned_size);
  //   *shadow = LookupPartial[end_delta];
  // }
#else

  uptr beg_addr = (uptr)addr;
  uptr end_addr = beg_addr + size;
  VPrintf(3, "Trying to poison memory region [%p, %p)\n", (void *)beg_addr,
          (void *)end_addr);

  ShadowSegmentEndpoint beg(beg_addr);
  ShadowSegmentEndpoint end(end_addr);
  if (beg.chunk == end.chunk) {
    CHECK_LT(beg.offset, end.offset);
    s8 value = beg.value;
    CHECK_EQ(value, end.value);
    // We can only poison memory if the byte in end.offset is unaddressable.
    // No need to re-poison memory if it is poisoned already.
    if (value > 0 && value <= end.offset) {
      if (beg.offset > 0) {
        *beg.chunk = Min(value, beg.offset);
      } else {
        *beg.chunk = kAsanUserPoisonedMemoryMagic;
      }
    }
    return;
  }
  CHECK_LT(beg.chunk, end.chunk);
  if (beg.offset > 0) {
    // Mark bytes from beg.offset as unaddressable.
    if (beg.value == 0) {
      *beg.chunk = beg.offset;
    } else {
      *beg.chunk = Min(beg.value, beg.offset);
    }
    beg.chunk++;
  }
  REAL(memset)(beg.chunk, kAsanUserPoisonedMemoryMagic, end.chunk - beg.chunk);
  // Poison if byte in end.offset is unaddressable.
  if (end.value > 0 && end.value <= end.offset) {
    *end.chunk = kAsanUserPoisonedMemoryMagic;
  }
#endif
}

// N=1, clear lower 2 bits: 11111100
// N=2, clear lower 4 bits: 11110000
// N=3, clear lower 6 bits: 11000000
static const u8 CombiSanUnpoison[4] = {0x00, 0xFC, 0xF0, 0xC0};

void __asan_unpoison_memory_region(void const volatile *addr, uptr size) {
  if (!flags()->allow_user_poisoning || size == 0) return;
#if 1 // CombiSan

  // align down the left side (like ASan originally) for unpoisoning
  uptr beg_aln_down = RoundDownTo((uptr)addr, ASAN_SHADOW_GRANULARITY);
  size += (uptr)addr - beg_aln_down; // include those extra bytes in the size to unpoison

  uptr aligned_size = size & ~(ASAN_SHADOW_GRANULARITY - 1);
  FastPoisonShadow(beg_aln_down, aligned_size, 0); // unpoison XXX: set to uninit?

  // partial end to unpoison
  uptr end_delta = size - aligned_size;
  if(end_delta){
    // there are 'end_delta' bytes left to unpoison in the last granule
    u8 *shadow = (u8 *)MemToShadow((uptr)beg_aln_down+aligned_size);
    *shadow &= CombiSanUnpoison[end_delta];
  }
#else
  uptr beg_addr = (uptr)addr;
  uptr end_addr = beg_addr + size;
  VPrintf(3, "Trying to unpoison memory region [%p, %p)\n", (void *)beg_addr,
          (void *)end_addr);
  ShadowSegmentEndpoint beg(beg_addr);
  ShadowSegmentEndpoint end(end_addr);
  if (beg.chunk == end.chunk) {
    CHECK_LT(beg.offset, end.offset);
    s8 value = beg.value;
    CHECK_EQ(value, end.value);
    // We unpoison memory bytes up to enbytes up to end.offset if it is not
    // unpoisoned already.
    if (value != 0) {
      *beg.chunk = Max(value, end.offset);
    }
    return;
  }
  CHECK_LT(beg.chunk, end.chunk);
  REAL(memset)(beg.chunk, 0, end.chunk - beg.chunk);
  if (end.offset > 0 && end.value != 0) {
    *end.chunk = Max(end.value, end.offset);
  }
#endif
}

int __asan_address_is_poisoned(void const volatile *addr) {
  return __asan::AddressIsPoisoned((uptr)addr);
}

uptr __asan_region_is_poisoned(uptr beg, uptr size) {
  if (!size)
    return 0;

  uptr end = beg + size;
  if (!AddrIsInMem(beg))
    return beg;
  if (!AddrIsInMem(end))
    return end;
  CHECK_LT(beg, end);
  uptr aligned_b = RoundUpTo(beg, ASAN_SHADOW_GRANULARITY);
  uptr aligned_e = RoundDownTo(end, ASAN_SHADOW_GRANULARITY);
  uptr shadow_beg = MemToShadow(aligned_b);
  uptr shadow_end = MemToShadow(aligned_e);
  // First check the first and the last application bytes,
  // then check the ASAN_SHADOW_GRANULARITY-aligned region by calling
  // mem_is_zero on the corresponding shadow.
  if (!__asan::AddressIsPoisoned(beg) && !__asan::AddressIsPoisoned(end - 1) &&
      (shadow_end <= shadow_beg ||
       __sanitizer::mem_is_zero((const char *)shadow_beg,
                                shadow_end - shadow_beg)))
    return 0;
  // The fast check failed, so we have a poisoned byte somewhere.
  // Find it slowly.
  for (; beg < end; beg++)
    if (__asan::AddressIsPoisoned(beg))
      return beg;
  UNREACHABLE("mem_is_zero returned false, but poisoned byte was not found");
  return 0;
}

// Check ASan bits
uptr __asan_region_is_poisoned_masked(uptr beg, uptr size) {
  if (!size)
    return 0;

  uptr end = beg + size;
  if (!AddrIsInMem(beg))
    return beg;
  if (!AddrIsInMem(end))
    return end;
  CHECK_LT(beg, end);
  uptr aligned_b = RoundUpTo(beg, ASAN_SHADOW_GRANULARITY);
  uptr aligned_e = RoundDownTo(end, ASAN_SHADOW_GRANULARITY);
  uptr shadow_beg = MemToShadow(aligned_b);
  uptr shadow_end = MemToShadow(aligned_e);
  // First check the first and the last application bytes,
  // then check the ASAN_SHADOW_GRANULARITY-aligned region by calling
  // mem_is_zero on the corresponding shadow.
  if (!__asan::AddressIsPoisonedMasked(beg) && !__asan::AddressIsPoisonedMasked(end - 1) &&
      (shadow_end <= shadow_beg ||
       __sanitizer::mem_is_zero_masked((const char *)shadow_beg,
                                shadow_end - shadow_beg)))
    return 0;
  // The fast check failed, so we have a poisoned byte somewhere.
  // Find it slowly.
  for (; beg < end; beg++)
    if (__asan::AddressIsPoisonedMasked(beg))
      return beg;
  UNREACHABLE("mem_is_zero returned false, but poisoned byte was not found");
  return 0;
}

// CombiSan: check ASan bits and also update shadow memory to initialized here
uptr __asan_region_chk_poisoned_set_init(uptr beg, uptr size) {
  if (!size)
    return 0;

  uptr pend = beg + size;
  if (!AddrIsInMem(beg))
    return beg;
  if (!AddrIsInMem(pend))
    return pend;
  CHECK_LT(beg, pend);
  uptr aligned_b = RoundUpTo(beg, ASAN_SHADOW_GRANULARITY);
  uptr aligned_e = RoundDownTo(pend, ASAN_SHADOW_GRANULARITY);
  uptr shadow_beg = MemToShadow(aligned_b);
  uptr shadow_end = MemToShadow(aligned_e);

  // Printf("--------dump:--------\n");
  // Printf("__asan_region_chk_poisoned_set_init: beg %p\n", beg);
  // Printf("__asan_region_chk_poisoned_set_init: size %p\n", size);
  // Printf("__asan_region_chk_poisoned_set_init: pend %p\n", pend);
  // Printf("__asan_region_chk_poisoned_set_init: aligned_b %p\n", aligned_b);
  // Printf("__asan_region_chk_poisoned_set_init: aligned_e %p\n", aligned_e);

  
  // ASan rounds up to shadow granularity for convenient checks
  // but it also emits checks on the first and last bytes to make sure
  // the rounding/alignment does not cause bugs to be missed
  // like a partial overflowing memset

  // so for CombiSan we emit a 1-byte ADDR check on start + end
  // and then check some 1-byte SHADOW checks to align to 8 bytes
  // then we start reading 8-bytes of SHADOW memory per chunk

  // shadow_end <= shadow_beg:  small and/or unaligned. check the bytes individually
  // to avoid reversed alignment where end < beg
  if(shadow_end <= shadow_beg){
    for(const char* curb = (const char*)beg; curb < (const char*)pend; curb++){
      if (__asan::AddressIsPoisonedMaskAndInit((uptr)curb)){
        return (uptr)curb;
      }
    }
    return 0;
  }

  // First check the first and the last application bytes (and update initialization)
  for(const char* firstb = (const char*)beg; firstb <= (const char*)aligned_b; firstb++){
    // Printf("__asan_region_chk_poisoned_set_init: firstb %p\n", firstb);
    if (__asan::AddressIsPoisonedMaskAndInit((uptr)firstb)){
      // Printf("Firstb bad: %p\n", firstb);
      return (uptr)firstb;
    }
  }
  for(const char* lastb = (const char*)aligned_e; lastb < (const char*)pend; lastb++){
    // Printf("__asan_region_chk_poisoned_set_init: lastb %p\n", lastb);
    if (__asan::AddressIsPoisonedMaskAndInit((uptr)lastb)){
      // Printf("Lastb bad: %p\n", lastb);
      return (uptr)lastb;
    }
  }

  // then check+init the ASAN_SHADOW_GRANULARITY-aligned region

  // Check and update in the same loop
  const char *end = (const char *)shadow_beg + (shadow_end-shadow_beg);
  // Printf("shadow_beg %p, size %lu, shadow_end %p\n", shadow_beg, shadow_end-shadow_beg, end);

  u32 *aligned_beg = (u32 *)RoundUpTo((uptr)shadow_beg, sizeof(u32));
  u32 *aligned_end = (u32 *)RoundDownTo((uptr)end, sizeof(u32));
  // Printf("--aligned loop-- aligned_beg %p aligned_end %p\n", aligned_beg, aligned_end);
  uptr all = 0;
  // this one can be async on 'all' because we know it has to be an ASan bug if any
  // Prologue.
  for (char *mem = (char *)shadow_beg; mem < (char*)aligned_beg && mem < end; mem++){
    // Printf("Prologue set: mem %p (%p) VAL %x\n", mem, ShadowToMem((uptr)mem), *mem);

    all |= *mem & kCombiSelectASan; // only select ASan bits
    *mem = 0; // init MSan
  }
  // Aligned loop.
  for (; aligned_beg < aligned_end; aligned_beg++){
    // Printf("Aligned loop set: aligned_beg %p (%p) VAL %x\n", aligned_beg, ShadowToMem((uptr)aligned_beg), *aligned_beg);

    all |= *aligned_beg & kCombiSelectASan8B; // only select ASan bits
    *aligned_beg = 0; // init MSan
  }
  // Epilogue.
  if ((char *)aligned_end >= (const char *)shadow_beg) {
    for (char *mem = (char *)aligned_end; mem < end; mem++){
      // Printf("Epilogue set: aligned_beg %p (%p) VAL %x\n", mem, ShadowToMem((uptr)mem), *mem);
      all |= *mem & kCombiSelectASan;
      *mem = 0;
    }
  }

  // if(all){
  //   Printf("All bad: %p\n", pend);
  // }
  
  // note that this is async-ish, it overrides possible redzones
  // return end app pointer if invalid (not completely accurate)
  return all == 0 ? 0 : pend;
}

// CombiSan: check ASan bits and also update shadow memory to initialized here
uptr __asan_region_copy(uptr from, uptr to, uptr size) {
  if (!size)
    return 0;

  uptr from_end = from + size;
  uptr to_end = to + size;

  if (!AddrIsInMem(from) || !AddrIsInMem(from_end))
    return from;
  if (!AddrIsInMem(to) || !AddrIsInMem(to_end))
    return to;
  CHECK_LT(from, from_end);
  CHECK_LT(to, to_end);

  // its hard to guarantee that the two pointers will sync in alignment...
  // we need to perform multiple actions:
  // 1) all accesses to 'from' should be valid
  // 2) all accesses to 'to' should be valid
  // 3) we want to copy the MSan init state afterwards

  /*
    TODO: I think we can improve the aligned loops
    we can go back to 8-byte pointers, we just need to align properly
    to ensure that the last block is not 4 bytes, that one we can do with 1 or 4 byte copies 
  */

  if((from & 3) == (to & 3)){ // equal alignment
    // Prologue
    uptr aligned_f = RoundUpTo(from, ASAN_SHADOW_GRANULARITY);
    uptr aligned_fe = RoundDownTo(from_end, ASAN_SHADOW_GRANULARITY);
    uptr shadow_f = MemToShadow(aligned_f);
    uptr shadow_fe = MemToShadow(aligned_fe);

    uptr aligned_t = RoundUpTo(to, ASAN_SHADOW_GRANULARITY);
    uptr aligned_te = RoundDownTo(to_end, ASAN_SHADOW_GRANULARITY);
    uptr shadow_t = MemToShadow(aligned_t);

    // Printf("--------dump:--------\n");
    // Printf("__asan_region_copy: from %p\n", from);
    // Printf("__asan_region_copy: to %p\n", to);
    // Printf("__asan_region_copy: size %lu\n", size);
    // Printf("__asan_region_copy: aligned_f %p\n", aligned_f);
    // Printf("__asan_region_copy: aligned_fe %p\n", aligned_fe);
    // Printf("__asan_region_copy: shadow_f %p\n", shadow_f);
    // Printf("__asan_region_copy: shadow_fe %p\n", shadow_fe);

    // Printf("__asan_region_copy: aligned_t %p\n", aligned_t);
    // Printf("__asan_region_copy: aligned_te %p\n", aligned_te);
    // Printf("__asan_region_copy: shadow_t %p\n", shadow_t);

    const char* _to = (const char*)to;

    // if the aligned start is greater than the aligned end
    // it means this is a tiny operation that caused the alignment to reverse
    if(aligned_f > aligned_fe){
      for(char* _from = (char*)from; _from < (const char*)from_end; _from++){
        if (__asan::AddressCopyAndCheckAligned((uptr)_from, (uptr)_to)){
          return (uptr)_from;
        }
        _to++;
      }
      return 0;
    }

    // Prologue (single bytes)
    for(char* _from = (char*)from; _from < (const char*)aligned_f; _from++){
      // Printf("__asan_region_copy pro-1b: _from %p\n", _from);
      if (__asan::AddressCopyAndCheckAligned((uptr)_from, (uptr)_to)){
        // Printf("Prologue bad: %p\n", _from);
        return (uptr)_from;
      }
      _to++;
    }

    // Aligned loop
    uptr all = 0;
    // this one can also check async because it is an ASan bug for sure, if any
    char* shadowto = (char*)shadow_t;
    for(char* shadowfrom = (char*)shadow_f; shadowfrom < (char*)shadow_fe; shadowfrom++){
      
      // gather ASan bits, copy all bits
      u8 source = *shadowfrom;
      all |= source & 0x55; // only select ASan bits
      all |= (*shadowto) & 0x55; // only select ASan bits
      // we can copy all bits because if ASan bits were set, a violation will be raised anyway
      *shadowto = source;

      // Printf("CopyAlign: from %p to %p source %x\n", ShadowToMem((uptr)shadowfrom), ShadowToMem((uptr)shadowto), source);

      shadowto++;
    }

    // check if any of ASan bits were set
    if(all){
      // return end as faulting pointer (not completely accurate)
      // Printf("Aligned bad: %p\n", from);
      return to_end;
    }

    // Epilogue (single bytes)
    _to = (char*)aligned_te;
    for(const char* _from = (const char*)aligned_fe; _from < (const char*)from_end; _from++){
      // Printf("__asan_region_copy epi-1b: _from %p\n", _from);
      if (__asan::AddressCopyAndCheckAligned((uptr)_from, (uptr)_to)){
        // Printf("Epilogue bad: %p\n", _from);
        return (uptr)_from;
      }
      _to++;
    }
  }
  else{
    // no equal alignment, copy per 2 bits (TODO: can this be optimized?)
    // Printf("No equal alignment: slow copy\n");
    const char* _to = (const char*)to;
    for(char* _from = (char*)from; _from < (const char*)from_end; _from++){
      // Printf("__asan_region_copy slow-1b: _from %p\n", _from);
      if (__asan::AddressCopyAndCheckUnaligned((uptr)_from, (uptr)_to)){
        // Printf("Unaligned bad: %p\n", _to);
        return (uptr)_to;
      }
      _to++;
    }
  }

  return 0;
}

// CombiSan: copy MSan's initialization state, no checks (e.g. for realloc's memcpy)
uptr __asan_region_copy_nochk(uptr from, uptr to, uptr size) {
  if (!size)
    return 0;

  uptr from_end = from + size;
  uptr to_end = to + size;

  if (!AddrIsInMem(from) || !AddrIsInMem(from_end))
    return from;
  if (!AddrIsInMem(to) || !AddrIsInMem(to_end))
    return to;
  CHECK_LT(from, from_end);
  CHECK_LT(to, to_end);

  if((from & 3) == (to & 3)){ // equal alignment
    // Prologue
    uptr aligned_f = RoundUpTo(from, ASAN_SHADOW_GRANULARITY);
    uptr aligned_fe = RoundDownTo(from_end, ASAN_SHADOW_GRANULARITY);
    uptr shadow_f = MemToShadow(aligned_f);
    uptr shadow_fe = MemToShadow(aligned_fe);

    uptr aligned_t = RoundUpTo(to, ASAN_SHADOW_GRANULARITY);
    uptr aligned_te = RoundDownTo(to_end, ASAN_SHADOW_GRANULARITY);
    uptr shadow_t = MemToShadow(aligned_t);

    const char* _to = (const char*)to;

    // if the aligned start is greater than the aligned end
    // it means this is a tiny operation that caused the alignment to reverse
    if(aligned_f > aligned_fe){
      for(char* _from = (char*)from; _from < (const char*)from_end; _from++){
        __asan::AddressCopyAligned((uptr)_from, (uptr)_to);
        _to++;
      }
      return 0;
    }

    // Prologue (single bytes)
    for(char* _from = (char*)from; _from < (const char*)aligned_f; _from++){
      __asan::AddressCopyAligned((uptr)_from, (uptr)_to);
       _to++;
    }

    // Aligned loop
    char* shadowto = (char*)shadow_t;
    for(char* shadowfrom = (char*)shadow_f; shadowfrom < (char*)shadow_fe; shadowfrom++){
      u8 source = *shadowfrom;
      // XXX: double check, but here we know we do not cross redzones, so we just copy
      *shadowto = source;
      shadowto++;
    }

    // Epilogue (single bytes)
    _to = (char*)aligned_te;
    for(const char* _from = (const char*)aligned_fe; _from < (const char*)from_end; _from++){
      __asan::AddressCopyAligned((uptr)_from, (uptr)_to);
      _to++;
    }
  }
  else{
    // no equal alignment, copy per 2 bits (TODO: can this be optimized?)
    const char* _to = (const char*)to;
    for(char* _from = (char*)from; _from < (const char*)from_end; _from++){
      __asan::AddressCopyUnaligned((uptr)_from, (uptr)_to);
      _to++;
    }
  }

  return 0;
}

#define CHECK_SMALL_REGION(p, size, isWrite)                  \
  do {                                                        \
    uptr __p = reinterpret_cast<uptr>(p);                     \
    uptr __size = size;                                       \
    if (UNLIKELY(__asan::AddressIsPoisoned(__p) ||            \
        __asan::AddressIsPoisoned(__p + __size - 1))) {       \
      GET_CURRENT_PC_BP_SP;                                   \
      uptr __bad = __asan_region_is_poisoned(__p, __size);    \
      __asan_report_error(pc, bp, sp, __bad, isWrite, __size, 0);\
    }                                                         \
  } while (false)


extern "C" SANITIZER_INTERFACE_ATTRIBUTE
u16 __sanitizer_unaligned_load16(const uu16 *p) {
  CHECK_SMALL_REGION(p, sizeof(*p), false);
  return *p;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
u32 __sanitizer_unaligned_load32(const uu32 *p) {
  CHECK_SMALL_REGION(p, sizeof(*p), false);
  return *p;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
u64 __sanitizer_unaligned_load64(const uu64 *p) {
  CHECK_SMALL_REGION(p, sizeof(*p), false);
  return *p;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store16(uu16 *p, u16 x) {
  CHECK_SMALL_REGION(p, sizeof(*p), true);
  *p = x;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store32(uu32 *p, u32 x) {
  CHECK_SMALL_REGION(p, sizeof(*p), true);
  *p = x;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store64(uu64 *p, u64 x) {
  CHECK_SMALL_REGION(p, sizeof(*p), true);
  *p = x;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __asan_poison_cxx_array_cookie(uptr p) {
  if (SANITIZER_WORDSIZE != 64) return;
  if (!flags()->poison_array_cookie) return;
  uptr s = MEM_TO_SHADOW(p);
  // CombiSan: since the cxx array cookie is checked explicitly here
  // and not in load/store I suppose this is fine since its non-zero?
  *reinterpret_cast<u8*>(s) = kAsanArrayCookieMagic;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
uptr __asan_load_cxx_array_cookie(uptr *p) {
  if (SANITIZER_WORDSIZE != 64) return *p;
  if (!flags()->poison_array_cookie) return *p;
  uptr s = MEM_TO_SHADOW(reinterpret_cast<uptr>(p));
  u8 sval = *reinterpret_cast<u8*>(s);
  if (sval == kAsanArrayCookieMagic) return *p;
  // If sval is not kAsanArrayCookieMagic it can only be freed memory,
  // which means that we are going to get double-free. So, return 0 to avoid
  // infinite loop of destructors. We don't want to report a double-free here
  // though, so print a warning just in case.
  // CHECK_EQ(sval, kAsanHeapFreeMagic);
#if 1 // CombiSan C++ cookie
  if (sval == kCombiASanRZ) {
#else
  if (sval == kAsanHeapFreeMagic) {
#endif
    Report("AddressSanitizer: loaded array cookie from free-d memory; "
           "expect a double-free report\n");
    return 0;
  }
  // The cookie may remain unpoisoned if e.g. it comes from a custom
  // operator new defined inside a class.
  return *p;
}

// This is a simplified version of __asan_(un)poison_memory_region, which
// assumes that left border of region to be poisoned is properly aligned.
static void PoisonAlignedStackMemory(uptr addr, uptr size, bool do_poison) {

  // if do_poison is true, this is a lifetime-end
  // if do_poison is false, it starts lifetime and needs MSan Uninit.

  if (size == 0) return;
  uptr aligned_size = size & ~(ASAN_SHADOW_GRANULARITY - 1);
  // Printf("PoisonAlignedStackMemory addr %p size %lu do_poison %d\n", addr, size, do_poison);
  PoisonShadow(addr, aligned_size,
               do_poison ? kCombiASanRZ : kCombiMSanUn); // was kAsanStackUseAfterScopeMagic
  if (size == aligned_size)
    return;

  // possible partial redzone/uninit
  uptr valid_bytes_last_granule = size - aligned_size;
  u8 *shadow = (u8 *)MemToShadow(addr + aligned_size);
  *shadow = do_poison ? LookupPartial[valid_bytes_last_granule] : LookupPartialUninit[valid_bytes_last_granule];
}

void __asan_set_shadow_00(uptr addr, uptr size) {
  REAL(memset)((void *)addr, 0, size);
}
void __asan_set_shadow_6a(uptr addr, uptr size) {
  REAL(memset)((void *)addr, 0x6a, size);
}
void __asan_set_shadow_5a(uptr addr, uptr size) {
  REAL(memset)((void *)addr, 0x5a, size);
}
void __asan_set_shadow_56(uptr addr, uptr size) {
  REAL(memset)((void *)addr, 0x56, size);
}
void __asan_set_shadow_aa(uptr addr, uptr size) {
  REAL(memset)((void *)addr, 0xaa, size);
}
void __asan_set_shadow_40(uptr addr, uptr size) {
  REAL(memset)((void *)addr, 0x40, size);
}
void __asan_set_shadow_50(uptr addr, uptr size) {
  REAL(memset)((void *)addr, 0x50, size);
}
void __asan_set_shadow_54(uptr addr, uptr size) {
  REAL(memset)((void *)addr, 0x54, size);
}
void __asan_set_shadow_55(uptr addr, uptr size) {
  REAL(memset)((void *)addr, 0x55, size);
}

// void __asan_set_shadow_00(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0, size);
// }

// void __asan_set_shadow_01(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0x01, size);
// }

// void __asan_set_shadow_02(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0x02, size);
// }

// void __asan_set_shadow_03(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0x03, size);
// }

// void __asan_set_shadow_04(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0x04, size);
// }

// void __asan_set_shadow_05(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0x05, size);
// }

// void __asan_set_shadow_06(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0x06, size);
// }

// void __asan_set_shadow_07(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0x07, size);
// }

// void __asan_set_shadow_f1(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0xf1, size);
// }

// void __asan_set_shadow_f2(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0xf2, size);
// }

// void __asan_set_shadow_f3(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0xf3, size);
// }

// void __asan_set_shadow_f5(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0xf5, size);
// }

// void __asan_set_shadow_f8(uptr addr, uptr size) {
//   REAL(memset)((void *)addr, 0xf8, size);
// }

void __asan_poison_stack_memory(uptr addr, uptr size) {
  VReport(1, "poisoning: %p %zx\n", (void *)addr, size);
  PoisonAlignedStackMemory(addr, size, true);
}

void __asan_unpoison_stack_memory(uptr addr, uptr size) {
  VReport(1, "unpoisoning: %p %zx\n", (void *)addr, size);
  PoisonAlignedStackMemory(addr, size, false);
}

static void FixUnalignedStorage(uptr storage_beg, uptr storage_end,
                                uptr &old_beg, uptr &old_end, uptr &new_beg,
                                uptr &new_end) {
  constexpr uptr granularity = ASAN_SHADOW_GRANULARITY;
  if (UNLIKELY(!AddrIsAlignedByGranularity(storage_end))) {
    uptr end_down = RoundDownTo(storage_end, granularity);
    // Ignore the last unaligned granule if the storage is followed by
    // unpoisoned byte, because we can't poison the prefix anyway. Don't call
    // AddressIsPoisoned at all if container changes does not affect the last
    // granule at all.
    if ((((old_end != new_end) && Max(old_end, new_end) > end_down) ||
         ((old_beg != new_beg) && Max(old_beg, new_beg) > end_down)) &&
#if 1 // CombiSan
        !AddressIsPoisonedMasked(storage_end)) {
#else
        !AddressIsPoisoned(storage_end)) {
#endif
      old_beg = Min(end_down, old_beg);
      old_end = Min(end_down, old_end);
      new_beg = Min(end_down, new_beg);
      new_end = Min(end_down, new_end);
    }
  }

  // Handle misaligned begin and cut it off.
  if (UNLIKELY(!AddrIsAlignedByGranularity(storage_beg))) {
    uptr beg_up = RoundUpTo(storage_beg, granularity);
    // The first unaligned granule needs special handling only if we had bytes
    // there before and will have none after.
    if ((new_beg == new_end || new_beg >= beg_up) && old_beg != old_end &&
        old_beg < beg_up) {
      // Keep granule prefix outside of the storage unpoisoned.
      uptr beg_down = RoundDownTo(storage_beg, granularity);
#if 1 // CombiSan: partial validity of containers
      *(u8 *)MemToShadow(beg_down) = LookupPartial[storage_beg - beg_down];
#else
      *(u8 *)MemToShadow(beg_down) = storage_beg - beg_down;
#endif
      old_beg = Max(beg_up, old_beg);
      old_end = Max(beg_up, old_end);
      new_beg = Max(beg_up, new_beg);
      new_end = Max(beg_up, new_end);
    }
  }
}

void __sanitizer_annotate_contiguous_container(const void *beg_p,
                                               const void *end_p,
                                               const void *old_mid_p,
                                               const void *new_mid_p) {
  if (!flags()->detect_container_overflow)
    return;
  VPrintf(3, "contiguous_container: %p %p %p %p\n", beg_p, end_p, old_mid_p,
          new_mid_p);
  uptr storage_beg = reinterpret_cast<uptr>(beg_p);
  uptr storage_end = reinterpret_cast<uptr>(end_p);
  uptr old_end = reinterpret_cast<uptr>(old_mid_p);
  uptr new_end = reinterpret_cast<uptr>(new_mid_p);
  uptr old_beg = storage_beg;
  uptr new_beg = storage_beg;
  uptr granularity = ASAN_SHADOW_GRANULARITY;
  if (!(storage_beg <= old_end && storage_beg <= new_end &&
        old_end <= storage_end && new_end <= storage_end)) {
    GET_STACK_TRACE_FATAL_HERE;
    ReportBadParamsToAnnotateContiguousContainer(storage_beg, storage_end,
                                                 old_end, new_end, &stack);
  }
  CHECK_LE(storage_end - storage_beg,
           FIRST_32_SECOND_64(1UL << 30, 1ULL << 40));  // Sanity check.

  if (old_end == new_end)
    return;  // Nothing to do here.

  FixUnalignedStorage(storage_beg, storage_end, old_beg, old_end, new_beg,
                      new_end);

  uptr a = RoundDownTo(Min(old_end, new_end), granularity);
  uptr c = RoundUpTo(Max(old_end, new_end), granularity);
  uptr d1 = RoundDownTo(old_end, granularity);
  // uptr d2 = RoundUpTo(old_mid, granularity);
  // Currently we should be in this state:
  // [a, d1) is good, [d2, c) is bad, [d1, d2) is partially good.
  // Make a quick sanity check that we are indeed in this state.
  //
  // FIXME: Two of these three checks are disabled until we fix
  // https://github.com/google/sanitizers/issues/258.
  // if (d1 != d2)
  //  DCHECK_EQ(*(u8*)MemToShadow(d1), old_mid - d1);
  //
  // NOTE: curly brackets for the "if" below to silence a MSVC warning.
  if (a + granularity <= d1) {
    DCHECK_EQ(*(u8 *)MemToShadow(a), 0);
  }
  // if (d2 + granularity <= c && c <= end)
  //   DCHECK_EQ(*(u8 *)MemToShadow(c - granularity),
  //            kAsanContiguousContainerOOBMagic);

  uptr b1 = RoundDownTo(new_end, granularity);
  uptr b2 = RoundUpTo(new_end, granularity);
  // New state:
  // [a, b1) is good, [b2, c) is bad, [b1, b2) is partially good.
  if (b1 > a)
    PoisonShadow(a, b1 - a, 0);
  else if (c > b2)
    PoisonShadow(b2, c - b2, kCombiASanRZ); // was kAsanContiguousContainerOOBMagic
  if (b1 != b2) {
    CHECK_EQ(b2 - b1, granularity);
#if 1 // CombiSan: partial validity of containers
    *(u8 *)MemToShadow(b1) = LookupPartial[static_cast<u8>(new_end - b1)];
#else
    *(u8 *)MemToShadow(b1) = static_cast<u8>(new_end - b1);
#endif

  }
}

// Annotates a double ended contiguous memory area like std::deque's chunk.
// It allows detecting buggy accesses to allocated but not used begining
// or end items of such a container.
void __sanitizer_annotate_double_ended_contiguous_container(
    const void *storage_beg_p, const void *storage_end_p,
    const void *old_container_beg_p, const void *old_container_end_p,
    const void *new_container_beg_p, const void *new_container_end_p) {
  if (!flags()->detect_container_overflow)
    return;

  VPrintf(3, "contiguous_container: %p %p %p %p %p %p\n", storage_beg_p,
          storage_end_p, old_container_beg_p, old_container_end_p,
          new_container_beg_p, new_container_end_p);

  uptr storage_beg = reinterpret_cast<uptr>(storage_beg_p);
  uptr storage_end = reinterpret_cast<uptr>(storage_end_p);
  uptr old_beg = reinterpret_cast<uptr>(old_container_beg_p);
  uptr old_end = reinterpret_cast<uptr>(old_container_end_p);
  uptr new_beg = reinterpret_cast<uptr>(new_container_beg_p);
  uptr new_end = reinterpret_cast<uptr>(new_container_end_p);

  constexpr uptr granularity = ASAN_SHADOW_GRANULARITY;

  if (!(old_beg <= old_end && new_beg <= new_end) ||
      !(storage_beg <= new_beg && new_end <= storage_end) ||
      !(storage_beg <= old_beg && old_end <= storage_end)) {
    GET_STACK_TRACE_FATAL_HERE;
    ReportBadParamsToAnnotateDoubleEndedContiguousContainer(
        storage_beg, storage_end, old_beg, old_end, new_beg, new_end, &stack);
  }
  CHECK_LE(storage_end - storage_beg,
           FIRST_32_SECOND_64(1UL << 30, 1ULL << 40));  // Sanity check.

  if ((old_beg == old_end && new_beg == new_end) ||
      (old_beg == new_beg && old_end == new_end))
    return;  // Nothing to do here.

  FixUnalignedStorage(storage_beg, storage_end, old_beg, old_end, new_beg,
                      new_end);

  // Handle non-intersecting new/old containers separately have simpler
  // intersecting case.
  if (old_beg == old_end || new_beg == new_end || new_end <= old_beg ||
      old_end <= new_beg) {
    if (old_beg != old_end) {
      // Poisoning the old container.
      uptr a = RoundDownTo(old_beg, granularity);
      uptr b = RoundUpTo(old_end, granularity);
      PoisonShadow(a, b - a, kCombiASanRZ); // was kAsanContiguousContainerOOBMagic
    }

    if (new_beg != new_end) {
      // Unpoisoning the new container.
      uptr a = RoundDownTo(new_beg, granularity);
      uptr b = RoundDownTo(new_end, granularity);
      PoisonShadow(a, b - a, 0);
      if (!AddrIsAlignedByGranularity(new_end))
#if 1 // CombiSan: partial validity of containers
        *(u8 *)MemToShadow(b) = LookupPartial[static_cast<u8>(new_end - b)];
#else
        *(u8 *)MemToShadow(b) = static_cast<u8>(new_end - b);
#endif
    }

    return;
  }

  // Intersection of old and new containers is not empty.
  CHECK_LT(new_beg, old_end);
  CHECK_GT(new_end, old_beg);

  if (new_beg < old_beg) {
    // Round down because we can't poison prefixes.
    uptr a = RoundDownTo(new_beg, granularity);
    // Round down and ignore the [c, old_beg) as its state defined by unchanged
    // [old_beg, old_end).
    uptr c = RoundDownTo(old_beg, granularity);
    PoisonShadow(a, c - a, 0);
  } else if (new_beg > old_beg) {
    // Round down and poison [a, old_beg) because it was unpoisoned only as a
    // prefix.
    uptr a = RoundDownTo(old_beg, granularity);
    // Round down and ignore the [c, new_beg) as its state defined by unchanged
    // [new_beg, old_end).
    uptr c = RoundDownTo(new_beg, granularity);

    PoisonShadow(a, c - a, kCombiASanRZ); // was kAsanContiguousContainerOOBMagic
  }

  if (new_end > old_end) {
    // Round down to poison the prefix.
    uptr a = RoundDownTo(old_end, granularity);
    // Round down and handle remainder below.
    uptr c = RoundDownTo(new_end, granularity);
    PoisonShadow(a, c - a, 0);
    if (!AddrIsAlignedByGranularity(new_end))
#if 1 // CombiSan: partial validity of containers
      *(u8 *)MemToShadow(c) = LookupPartial[static_cast<u8>(new_end - c)];
#else
      *(u8 *)MemToShadow(c) = static_cast<u8>(new_end - c);
#endif
  } else if (new_end < old_end) {
    // Round up and handle remained below.
    uptr a2 = RoundUpTo(new_end, granularity);
    // Round up to poison entire granule as we had nothing in [old_end, c2).
    uptr c2 = RoundUpTo(old_end, granularity);
    PoisonShadow(a2, c2 - a2, kCombiASanRZ); // was kAsanContiguousContainerOOBMagic

    if (!AddrIsAlignedByGranularity(new_end)) {
      uptr a = RoundDownTo(new_end, granularity);
#if 1 // CombiSan: partial validity of containers
      *(u8 *)MemToShadow(a) = LookupPartial[static_cast<u8>(new_end - a)];
#else
      *(u8 *)MemToShadow(a) = static_cast<u8>(new_end - a);

#endif
    }
  }
}

// Marks the specified number of bytes in a granule as accessible or
// poisones the whole granule with kAsanContiguousContainerOOBMagic value.
static void SetContainerGranule(uptr ptr, u8 n) {
  constexpr uptr granularity = ASAN_SHADOW_GRANULARITY;
#if 1 // CombiSan: partial validity of containers
  u8 s = (n == granularity) ? 0 : LookupPartial[n]; // LookupPartial[0] == 0x55 (fully invalid)
#else
  u8 s = (n == granularity) ? 0 : (n ? n : kAsanContiguousContainerOOBMagic);
#endif
  *(u8 *)MemToShadow(ptr) = s;
}

// Performs a byte-by-byte copy of ASan annotations (shadow memory values).
// Result may be different due to ASan limitations, but result cannot lead
// to false positives (more memory than requested may get unpoisoned).
static void SlowCopyContainerAnnotations(uptr src_beg, uptr src_end,
                                         uptr dst_beg, uptr dst_end) {
  constexpr uptr granularity = ASAN_SHADOW_GRANULARITY;
  uptr dst_end_down = RoundDownTo(dst_end, granularity);
  uptr src_ptr = src_beg;
  uptr dst_ptr = dst_beg;

  while (dst_ptr < dst_end) {
    uptr granule_beg = RoundDownTo(dst_ptr, granularity);
    uptr granule_end = granule_beg + granularity;
    uptr unpoisoned_bytes = 0;

    uptr end = Min(granule_end, dst_end);
    for (; dst_ptr != end; ++dst_ptr, ++src_ptr)
#if 1 // CombiSan
      if (!AddressIsPoisonedMasked(src_ptr))
#else
      if (!AddressIsPoisoned(src_ptr))
#endif
        unpoisoned_bytes = dst_ptr - granule_beg + 1;

    if (dst_ptr == dst_end && dst_end != dst_end_down &&
#if 1 // CombiSan
        !AddressIsPoisonedMasked(dst_end)
#else
        !AddressIsPoisoned(dst_end)
#endif
    )
      continue;

    if (unpoisoned_bytes != 0 || granule_beg >= dst_beg)
      SetContainerGranule(granule_beg, unpoisoned_bytes);
#if 1 // CombiSan
    else if (!AddressIsPoisonedMasked(dst_beg))
#else
    else if (!AddressIsPoisoned(dst_beg))
#endif
      SetContainerGranule(granule_beg, dst_beg - granule_beg);
  }
}

// Performs a byte-by-byte copy of ASan annotations (shadow memory values),
// going through bytes in reversed order, but not reversing annotations.
// Result may be different due to ASan limitations, but result cannot lead
// to false positives (more memory than requested may get unpoisoned).
static void SlowReversedCopyContainerAnnotations(uptr src_beg, uptr src_end,
                                                 uptr dst_beg, uptr dst_end) {
  constexpr uptr granularity = ASAN_SHADOW_GRANULARITY;
  uptr dst_end_down = RoundDownTo(dst_end, granularity);
  uptr src_ptr = src_end;
  uptr dst_ptr = dst_end;

  while (dst_ptr > dst_beg) {
    uptr granule_beg = RoundDownTo(dst_ptr - 1, granularity);
    uptr unpoisoned_bytes = 0;

    uptr end = Max(granule_beg, dst_beg);
    for (; dst_ptr != end; --dst_ptr, --src_ptr)
#if 1 // CombiSan
      if (unpoisoned_bytes == 0 && !AddressIsPoisonedMasked(src_ptr - 1))
#else
      if (unpoisoned_bytes == 0 && !AddressIsPoisoned(src_ptr - 1))
#endif
        unpoisoned_bytes = dst_ptr - granule_beg;
#if 1 // CombiSan
    if (dst_ptr >= dst_end_down && !AddressIsPoisonedMasked(dst_end))
#else
    if (dst_ptr >= dst_end_down && !AddressIsPoisoned(dst_end))
#endif
      continue;

    if (granule_beg == dst_ptr || unpoisoned_bytes != 0)
      SetContainerGranule(granule_beg, unpoisoned_bytes);
#if 1 // CombiSan
    else if (!AddressIsPoisonedMasked(dst_beg))
#else
    else if (!AddressIsPoisoned(dst_beg))
#endif
      SetContainerGranule(granule_beg, dst_beg - granule_beg);
  }
}

// A helper function for __sanitizer_copy_contiguous_container_annotations,
// has assumption about begin and end of the container.
// Should not be used stand alone.
static void CopyContainerFirstGranuleAnnotation(uptr src_beg, uptr dst_beg) {
  constexpr uptr granularity = ASAN_SHADOW_GRANULARITY;
  // First granule
  uptr src_beg_down = RoundDownTo(src_beg, granularity);
  uptr dst_beg_down = RoundDownTo(dst_beg, granularity);
  if (dst_beg_down == dst_beg)
    return;
#if 1 // CombiSan
  if (!AddressIsPoisonedMasked(src_beg))
#else
  if (!AddressIsPoisoned(src_beg))

#endif
    *(u8 *)MemToShadow(dst_beg_down) = *(u8 *)MemToShadow(src_beg_down);
#if 1 // CombiSan
  else if (!AddressIsPoisonedMasked(dst_beg))
#else
  else if (!AddressIsPoisoned(dst_beg))
#endif
    SetContainerGranule(dst_beg_down, dst_beg - dst_beg_down);
}

// A helper function for __sanitizer_copy_contiguous_container_annotations,
// has assumption about begin and end of the container.
// Should not be used stand alone.
static void CopyContainerLastGranuleAnnotation(uptr src_end, uptr dst_end) {
  constexpr uptr granularity = ASAN_SHADOW_GRANULARITY;
  // Last granule
  uptr src_end_down = RoundDownTo(src_end, granularity);
  uptr dst_end_down = RoundDownTo(dst_end, granularity);
#if 1 // CombiSan
  if (dst_end_down == dst_end || !AddressIsPoisonedMasked(dst_end))
#else
  if (dst_end_down == dst_end || !AddressIsPoisoned(dst_end))
#endif
    return;
#if 1 // CombiSan
  if (AddressIsPoisonedMasked(src_end))
#else
  if (AddressIsPoisoned(src_end))
#endif
    *(u8 *)MemToShadow(dst_end_down) = *(u8 *)MemToShadow(src_end_down);
  else
    SetContainerGranule(dst_end_down, src_end - src_end_down);
}

// This function copies ASan memory annotations (poisoned/unpoisoned states)
// from one buffer to another.
// It's main purpose is to help with relocating trivially relocatable objects,
// which memory may be poisoned, without calling copy constructor.
// However, it does not move memory content itself, only annotations.
// If the buffers aren't aligned (the distance between buffers isn't
// granule-aligned)
//     // src_beg % granularity != dst_beg % granularity
// the function handles this by going byte by byte, slowing down performance.
// The old buffer annotations are not removed. If necessary,
// user can unpoison old buffer with __asan_unpoison_memory_region.
void __sanitizer_copy_contiguous_container_annotations(const void *src_beg_p,
                                                       const void *src_end_p,
                                                       const void *dst_beg_p,
                                                       const void *dst_end_p) {
  if (!flags()->detect_container_overflow)
    return;

  VPrintf(3, "contiguous_container_src: %p %p\n", src_beg_p, src_end_p);
  VPrintf(3, "contiguous_container_dst: %p %p\n", dst_beg_p, dst_end_p);

  uptr src_beg = reinterpret_cast<uptr>(src_beg_p);
  uptr src_end = reinterpret_cast<uptr>(src_end_p);
  uptr dst_beg = reinterpret_cast<uptr>(dst_beg_p);
  uptr dst_end = reinterpret_cast<uptr>(dst_end_p);

  constexpr uptr granularity = ASAN_SHADOW_GRANULARITY;

  if (src_beg > src_end || (dst_end - dst_beg) != (src_end - src_beg)) {
    GET_STACK_TRACE_FATAL_HERE;
    ReportBadParamsToCopyContiguousContainerAnnotations(
        src_beg, src_end, dst_beg, dst_end, &stack);
  }

  if (src_beg == src_end || src_beg == dst_beg)
    return;
  // Due to support for overlapping buffers, we may have to copy elements
  // in reversed order, when destination buffer starts in the middle of
  // the source buffer (or shares first granule with it).
  //
  // When buffers are not granule-aligned (or distance between them,
  // to be specific), annotatios have to be copied byte by byte.
  //
  // The only remaining edge cases involve edge granules,
  // when the container starts or ends within a granule.
  uptr src_beg_up = RoundUpTo(src_beg, granularity);
  uptr src_end_up = RoundUpTo(src_end, granularity);
  bool copy_in_reversed_order = src_beg < dst_beg && dst_beg <= src_end_up;
  if (src_beg % granularity != dst_beg % granularity ||
      RoundDownTo(dst_end - 1, granularity) <= dst_beg) {
    if (copy_in_reversed_order)
      SlowReversedCopyContainerAnnotations(src_beg, src_end, dst_beg, dst_end);
    else
      SlowCopyContainerAnnotations(src_beg, src_end, dst_beg, dst_end);
    return;
  }

  // As buffers are granule-aligned, we can just copy annotations of granules
  // from the middle.
  uptr dst_beg_up = RoundUpTo(dst_beg, granularity);
  uptr dst_end_down = RoundDownTo(dst_end, granularity);
  if (copy_in_reversed_order)
    CopyContainerLastGranuleAnnotation(src_end, dst_end);
  else
    CopyContainerFirstGranuleAnnotation(src_beg, dst_beg);

  if (dst_beg_up < dst_end_down) {
    internal_memmove((u8 *)MemToShadow(dst_beg_up),
                     (u8 *)MemToShadow(src_beg_up),
                     (dst_end_down - dst_beg_up) / granularity);
  }

  if (copy_in_reversed_order)
    CopyContainerFirstGranuleAnnotation(src_beg, dst_beg);
  else
    CopyContainerLastGranuleAnnotation(src_end, dst_end);
}

static const void *FindBadAddress(uptr begin, uptr end, bool poisoned) {
  CHECK_LE(begin, end);
  constexpr uptr kMaxRangeToCheck = 32;
  if (end - begin > kMaxRangeToCheck * 2) {
    if (auto *bad = FindBadAddress(begin, begin + kMaxRangeToCheck, poisoned))
      return bad;
    if (auto *bad = FindBadAddress(end - kMaxRangeToCheck, end, poisoned))
      return bad;
  }

  for (uptr i = begin; i < end; ++i)
#if 1 // CombiSan
    if (AddressIsPoisonedMasked(i) != poisoned)
#else
    if (AddressIsPoisoned(i) != poisoned)
#endif
      return reinterpret_cast<const void *>(i);
  return nullptr;
}

const void *__sanitizer_contiguous_container_find_bad_address(
    const void *beg_p, const void *mid_p, const void *end_p) {
  if (!flags()->detect_container_overflow)
    return nullptr;
  uptr granularity = ASAN_SHADOW_GRANULARITY;
  uptr beg = reinterpret_cast<uptr>(beg_p);
  uptr end = reinterpret_cast<uptr>(end_p);
  uptr mid = reinterpret_cast<uptr>(mid_p);
  CHECK_LE(beg, mid);
  CHECK_LE(mid, end);
  // If the byte after the storage is unpoisoned, everything in the granule
  // before must stay unpoisoned.
#if 1 // CombiSan
  uptr annotations_end =
      (!AddrIsAlignedByGranularity(end) && !AddressIsPoisonedMasked(end))
          ? RoundDownTo(end, granularity)
          : end;
#else
  uptr annotations_end =
      (!AddrIsAlignedByGranularity(end) && !AddressIsPoisoned(end))
          ? RoundDownTo(end, granularity)
          : end;
#endif
  beg = Min(beg, annotations_end);
  mid = Min(mid, annotations_end);
  if (auto *bad = FindBadAddress(beg, mid, false))
    return bad;
  if (auto *bad = FindBadAddress(mid, annotations_end, true))
    return bad;
  return FindBadAddress(annotations_end, end, false);
}

int __sanitizer_verify_contiguous_container(const void *beg_p,
                                            const void *mid_p,
                                            const void *end_p) {
  return __sanitizer_contiguous_container_find_bad_address(beg_p, mid_p,
                                                           end_p) == nullptr;
}

const void *__sanitizer_double_ended_contiguous_container_find_bad_address(
    const void *storage_beg_p, const void *container_beg_p,
    const void *container_end_p, const void *storage_end_p) {
  if (!flags()->detect_container_overflow)
    return nullptr;
  uptr granularity = ASAN_SHADOW_GRANULARITY;
  uptr storage_beg = reinterpret_cast<uptr>(storage_beg_p);
  uptr storage_end = reinterpret_cast<uptr>(storage_end_p);
  uptr beg = reinterpret_cast<uptr>(container_beg_p);
  uptr end = reinterpret_cast<uptr>(container_end_p);

  // The prefix of the firs granule of the container is unpoisoned.
  if (beg != end)
    beg = Max(storage_beg, RoundDownTo(beg, granularity));

  // If the byte after the storage is unpoisoned, the prefix of the last granule
  // is unpoisoned.
  uptr annotations_end = (!AddrIsAlignedByGranularity(storage_end) &&
#if 1 // CombiSan
                          !AddressIsPoisonedMasked(storage_end)
#else
                          !AddressIsPoisoned(storage_end)
#endif
                          )
                             ? RoundDownTo(storage_end, granularity)
                             : storage_end;
  storage_beg = Min(storage_beg, annotations_end);
  beg = Min(beg, annotations_end);
  end = Min(end, annotations_end);

  if (auto *bad = FindBadAddress(storage_beg, beg, true))
    return bad;
  if (auto *bad = FindBadAddress(beg, end, false))
    return bad;
  if (auto *bad = FindBadAddress(end, annotations_end, true))
    return bad;
  return FindBadAddress(annotations_end, storage_end, false);
}

int __sanitizer_verify_double_ended_contiguous_container(
    const void *storage_beg_p, const void *container_beg_p,
    const void *container_end_p, const void *storage_end_p) {
  return __sanitizer_double_ended_contiguous_container_find_bad_address(
             storage_beg_p, container_beg_p, container_end_p, storage_end_p) ==
         nullptr;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __asan_poison_intra_object_redzone(uptr ptr, uptr size) {
  AsanPoisonOrUnpoisonIntraObjectRedzone(ptr, size, true);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __asan_unpoison_intra_object_redzone(uptr ptr, uptr size) {
  AsanPoisonOrUnpoisonIntraObjectRedzone(ptr, size, false);
}

// --- Implementation of LSan-specific functions --- {{{1
namespace __lsan {
bool WordIsPoisoned(uptr addr) {
  // CombiSan: only consider ASan bits for LSan
  return (__asan_region_is_poisoned_masked(addr, sizeof(uptr)) != 0);
}
}
