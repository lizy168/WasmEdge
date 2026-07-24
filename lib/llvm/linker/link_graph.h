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
#include "common/span.h"
#include "common/types.h"

namespace WasmEdge {
namespace LLVM {
namespace Linker {

enum class Target : uint8_t { X86_64, ARM, AArch64, RISCV64, S390X };
enum class Endianness : uint8_t { Little, Big };
enum class SectionKind : uint8_t { Text, ReadOnly, Data, BSS, Unwind };
enum class SectionPurpose : uint8_t {
  Default,
  EHFrame,
  PData,
  XData,
  CompactUnwind,
};
enum class ObjectFormat : uint8_t { ELF, MachO, COFF };

using SectionId = uint32_t;
using SymbolId = uint32_t;
inline constexpr SectionId InvalidSectionId = UINT32_MAX;
inline constexpr SymbolId InvalidSymbolId = UINT32_MAX;
inline constexpr uint8_t NoPatch = 0;
inline constexpr uint8_t MinimumRebaseWidth = 1;

struct Section {
  std::string Name;
  SectionKind Kind;
  uint64_t Alignment;
  uint64_t VirtualSize = 0;
  uint64_t Address = 0;
  uint64_t FileOffset = 0;
  std::vector<Byte> Content{};
  SectionPurpose Purpose = SectionPurpose::Default;
};

struct Symbol {
  std::string Name;
  SectionId Section;
  uint64_t Offset;
  uint64_t Size;
  bool Exported;
  std::optional<std::string> ExportName = std::nullopt;
};

struct Relocation {
  SectionId Section;
  uint64_t Offset;
  uint32_t Type;
  SymbolId Symbol;
  int64_t Addend;
  bool AddendIsImplicit = false;
  ObjectFormat Format = ObjectFormat::ELF;
  uint8_t PatchSize = NoPatch;
  bool PCRelative = false;
  bool External = false;
  bool Scattered = false;
};

struct Rebase {
  SectionId Section;
  uint64_t Offset;
  uint32_t Type;
  int64_t Addend;
  uint8_t Width = NoPatch;
  ObjectFormat Format = ObjectFormat::ELF;
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

std::optional<uint8_t> relocationPatchSize(ObjectFormat Format,
                                           Target TargetValue, uint32_t Type,
                                           uint8_t MetadataSize) noexcept;
bool relocationIsPCRelative(ObjectFormat Format, Target TargetValue,
                            uint32_t Type) noexcept;

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
  LinkExpect<void> setSectionAddress(SectionId Id, uint64_t Address);
  LinkExpect<void> setSectionFileOffset(SectionId Id, uint64_t FileOffset);
  LinkExpect<Span<Byte>> sectionContent(SectionId Id);

  Target target() const noexcept { return TargetValue; }
  Endianness endianness() const noexcept { return EndianValue; }
  const std::vector<Section> &sections() const noexcept { return Sections; }
  const std::vector<Symbol> &symbols() const noexcept { return Symbols; }
  const std::vector<Relocation> &relocations() const noexcept {
    return Relocations;
  }
  const std::vector<Rebase> &rebases() const noexcept { return Rebases; }
  bool relocationsApplied() const noexcept { return RelocationsApplied; }

private:
  Target TargetValue;
  Endianness EndianValue;
  std::optional<std::string> InputName;
  std::vector<Section> Sections;
  std::vector<Symbol> Symbols;
  std::vector<Relocation> Relocations;
  std::vector<Rebase> Rebases;
  bool RelocationsApplied = false;

  friend Expect<void> applyRelocations(LinkGraph &) noexcept;
};

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
