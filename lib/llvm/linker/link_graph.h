// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#pragma once

#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/expected.h"

namespace WasmEdge {
namespace LLVM {
namespace Linker {

enum class Target { X86_64, ARM, AArch64, RISCV64, S390X };
enum class Endianness { Little, Big };
enum class SectionKind { Text, ReadOnly, Data, BSS, Unwind };

struct SectionId {
  uint32_t Value;
};

inline bool operator==(SectionId LHS, SectionId RHS) noexcept {
  return LHS.Value == RHS.Value;
}

struct SymbolId {
  uint32_t Value;
};

inline bool operator==(SymbolId LHS, SymbolId RHS) noexcept {
  return LHS.Value == RHS.Value;
}

struct Section {
  std::string Name;
  SectionKind Kind;
  uint64_t Alignment;
  uint64_t Address;
  uint64_t FileOffset;
  uint64_t VirtualSize;
  std::vector<uint8_t> Content;
};

struct Symbol {
  std::string Name;
  std::optional<SectionId> Section;
  uint64_t Offset;
  uint64_t Size;
  bool Exported;
};

struct Relocation {
  SectionId Section;
  uint64_t Offset;
  uint32_t Type;
  SymbolId Symbol;
  int64_t Addend;
};

struct Rebase {
  SectionId Section;
  uint64_t Offset;
  uint32_t Type;
  int64_t Addend;
};

struct Diagnostic {
  explicit Diagnostic(std::string Value) : Message(std::move(Value)) {}

  std::string Message;
  std::optional<SectionId> Section;
  std::optional<SymbolId> Symbol;
  std::optional<uint32_t> RelocationType;
  std::optional<uint64_t> Offset;
  std::string SectionName;
  std::string SymbolName;
};

template <typename T> using LinkExpect = Expected<T, Diagnostic>;

class LinkGraph {
public:
  LinkGraph(Target TargetValue, Endianness EndianValue) noexcept
      : TargetValue(TargetValue), EndianValue(EndianValue) {}

  LinkExpect<void> beginInput(std::string_view Name);
  LinkExpect<SectionId> addSection(Section Value);
  LinkExpect<SymbolId> addSymbol(Symbol Value);
  LinkExpect<void> addRelocation(Relocation Value);
  LinkExpect<void> addRebase(Rebase Value);
  LinkExpect<void> validate() const;

  Target target() const noexcept { return TargetValue; }
  Endianness endianness() const noexcept { return EndianValue; }
  const std::vector<Section> &sections() const noexcept { return Sections; }
  const std::vector<Symbol> &symbols() const noexcept { return Symbols; }
  const std::vector<Relocation> &relocations() const noexcept {
    return Relocations;
  }
  const std::vector<Rebase> &rebases() const noexcept { return Rebases; }

private:
  Target TargetValue;
  Endianness EndianValue;
  std::optional<std::string> InputName;
  std::vector<Section> Sections;
  std::vector<Symbol> Symbols;
  std::vector<Relocation> Relocations;
  std::vector<Rebase> Rebases;
};

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
