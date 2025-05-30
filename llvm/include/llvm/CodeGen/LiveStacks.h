//===- LiveStacks.h - Live Stack Slot Analysis ------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the live stack slot analysis pass. It is analogous to
// live interval analysis except it's analyzing liveness of stack slots rather
// than registers.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CODEGEN_LIVESTACKS_H
#define LLVM_CODEGEN_LIVESTACKS_H

#include "llvm/CodeGen/LiveInterval.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/IR/PassManager.h"
#include "llvm/InitializePasses.h"
#include "llvm/PassRegistry.h"
#include <cassert>
#include <map>
#include <unordered_map>

namespace llvm {

class AnalysisUsage;
class MachineFunction;
class Module;
class raw_ostream;
class TargetRegisterClass;
class TargetRegisterInfo;

class LiveStacks {
  const TargetRegisterInfo *TRI = nullptr;

  /// Special pool allocator for VNInfo's (LiveInterval val#).
  ///
  VNInfo::Allocator VNInfoAllocator;

  /// S2IMap - Stack slot indices to live interval mapping.
  using SS2IntervalMap = std::unordered_map<int, LiveInterval>;
  SS2IntervalMap S2IMap;

  /// S2RCMap - Stack slot indices to register class mapping.
  std::map<int, const TargetRegisterClass *> S2RCMap;

public:
  using iterator = SS2IntervalMap::iterator;
  using const_iterator = SS2IntervalMap::const_iterator;

  const_iterator begin() const { return S2IMap.begin(); }
  const_iterator end() const { return S2IMap.end(); }
  iterator begin() { return S2IMap.begin(); }
  iterator end() { return S2IMap.end(); }

  unsigned getNumIntervals() const { return (unsigned)S2IMap.size(); }

  LiveInterval &getOrCreateInterval(int Slot, const TargetRegisterClass *RC);

  LiveInterval &getInterval(int Slot) {
    assert(Slot >= 0 && "Spill slot indice must be >= 0");
    SS2IntervalMap::iterator I = S2IMap.find(Slot);
    assert(I != S2IMap.end() && "Interval does not exist for stack slot");
    return I->second;
  }

  const LiveInterval &getInterval(int Slot) const {
    assert(Slot >= 0 && "Spill slot indice must be >= 0");
    SS2IntervalMap::const_iterator I = S2IMap.find(Slot);
    assert(I != S2IMap.end() && "Interval does not exist for stack slot");
    return I->second;
  }

  bool hasInterval(int Slot) const { return S2IMap.count(Slot); }

  const TargetRegisterClass *getIntervalRegClass(int Slot) const {
    assert(Slot >= 0 && "Spill slot indice must be >= 0");
    std::map<int, const TargetRegisterClass *>::const_iterator I =
        S2RCMap.find(Slot);
    assert(I != S2RCMap.end() &&
           "Register class info does not exist for stack slot");
    return I->second;
  }

  VNInfo::Allocator &getVNInfoAllocator() { return VNInfoAllocator; }

  void releaseMemory();
  /// init - analysis entry point
  void init(MachineFunction &MF);
  void print(raw_ostream &O, const Module *M = nullptr) const;
};

class LiveStacksWrapperLegacy : public MachineFunctionPass {
  LiveStacks Impl;

public:
  static char ID; // Pass identification, replacement for typeid

  LiveStacksWrapperLegacy() : MachineFunctionPass(ID) {
    initializeLiveStacksWrapperLegacyPass(*PassRegistry::getPassRegistry());
  }

  LiveStacks &getLS() { return Impl; }
  const LiveStacks &getLS() const { return Impl; }

  void getAnalysisUsage(AnalysisUsage &AU) const override;
  void releaseMemory() override;

  /// runOnMachineFunction - pass entry point
  bool runOnMachineFunction(MachineFunction &) override;

  /// print - Implement the dump method.
  void print(raw_ostream &O, const Module * = nullptr) const override;
};

class LiveStacksAnalysis : public AnalysisInfoMixin<LiveStacksAnalysis> {
  static AnalysisKey Key;
  friend AnalysisInfoMixin<LiveStacksAnalysis>;

public:
  using Result = LiveStacks;

  LiveStacks run(MachineFunction &MF, MachineFunctionAnalysisManager &);
};

class LiveStacksPrinterPass : public PassInfoMixin<LiveStacksPrinterPass> {
  raw_ostream &OS;

public:
  LiveStacksPrinterPass(raw_ostream &OS) : OS(OS) {}
  PreservedAnalyses run(MachineFunction &MF,
                        MachineFunctionAnalysisManager &AM);
};
} // end namespace llvm

#endif
