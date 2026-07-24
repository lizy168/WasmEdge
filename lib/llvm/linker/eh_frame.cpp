// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/eh_frame.h"

#include "linker/relocation.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

constexpr uint8_t ExpectedFDEEncoding = 0x10;
constexpr uint8_t PointerWidth = 8;

Expect<void> fail() noexcept { return Unexpect(ErrCode::Value::IllegalPath); }

bool readU32(Span<const Byte> Bytes, size_t Offset, uint32_t &Value) noexcept {
  if (Offset > Bytes.size() || Bytes.size() - Offset < sizeof(Value))
    return false;
  std::memcpy(&Value, Bytes.data() + Offset, sizeof(Value));
  return true;
}

bool readU64(Span<const Byte> Bytes, size_t Offset, uint64_t &Value) noexcept {
  if (Offset > Bytes.size() || Bytes.size() - Offset < sizeof(Value))
    return false;
  std::memcpy(&Value, Bytes.data() + Offset, sizeof(Value));
  return true;
}

bool readULEB(Span<const Byte> Bytes, size_t &Offset,
              uint64_t &Value) noexcept {
  Value = 0;
  unsigned Shift = 0;
  while (Offset < Bytes.size() && Shift < 64) {
    const uint8_t Byte = Bytes[Offset++];
    if (Shift == 63 && (Byte & 0xFE) != 0)
      return false;
    Value |= static_cast<uint64_t>(Byte & 0x7F) << Shift;
    if ((Byte & 0x80) == 0)
      return true;
    Shift += 7;
  }
  return false;
}

bool readSLEB(Span<const Byte> Bytes, size_t &Offset, int64_t &Value) noexcept {
  uint64_t Raw = 0;
  unsigned Shift = 0;
  uint8_t Byte = 0;
  do {
    if (Offset >= Bytes.size() || Shift >= 64)
      return false;
    Byte = Bytes[Offset++];
    Raw |= static_cast<uint64_t>(Byte & 0x7F) << Shift;
    Shift += 7;
  } while ((Byte & 0x80) != 0);
  if (Shift < 64 && (Byte & 0x40) != 0)
    Raw |= UINT64_MAX << Shift;
  Value = static_cast<int64_t>(Raw);
  return true;
}

struct ParsedFrame {
  std::vector<size_t> Starts;
  std::set<size_t> FDEFields;
};

bool requiredSemanticFunction(const LinkGraph &Graph,
                              const Symbol &Symbol) noexcept {
  if (!Symbol.Global && !Symbol.Exported)
    return false;
  std::string_view Name = Symbol.ExportName ? *Symbol.ExportName : Symbol.Name;
  if (Graph.format() == ObjectFormat::MachO && !Name.empty() &&
      Name.front() == '_')
    Name.remove_prefix(1);
  if (Name.size() < 2 || (Name.front() != 't' && Name.front() != 'f'))
    return false;
  uint64_t Index = 0;
  const auto Parsed =
      std::from_chars(Name.data() + 1, Name.data() + Name.size(), Index);
  return Parsed.ec == std::errc{} && Parsed.ptr == Name.data() + Name.size() &&
         std::to_string(Index) == Name.substr(1);
}

Expect<ParsedFrame> parse(Span<const Byte> Bytes) {
  ParsedFrame Result;
  std::map<size_t, uint8_t> CIEs;
  size_t Offset = 0;
  bool Terminated = false;
  while (Offset < Bytes.size()) {
    uint32_t Length = 0;
    if (!readU32(Bytes, Offset, Length))
      return Unexpect(ErrCode::Value::IllegalPath);
    if (Length == 0) {
      Terminated = true;
      Offset += 4;
      if (std::any_of(Bytes.begin() + Offset, Bytes.end(),
                      [](Byte Value) { return Value != 0; }))
        return Unexpect(ErrCode::Value::IllegalPath);
      break;
    }
    constexpr uint32_t Dwarf64Marker = UINT32_MAX;
    if (Length == Dwarf64Marker || Offset > Bytes.size() - 4 ||
        Length > Bytes.size() - Offset - 4)
      return Unexpect(ErrCode::Value::IllegalPath);
    const size_t Record = Offset;
    const size_t End = Offset + 4 + Length;
    uint32_t Id = 0;
    if (!readU32(Bytes, Offset + 4, Id))
      return Unexpect(ErrCode::Value::IllegalPath);
    if (Id == 0) {
      size_t Cursor = Offset + 8;
      if (Cursor >= End || Bytes[Cursor++] != 1)
        return Unexpect(ErrCode::Value::IllegalPath);
      constexpr std::string_view Augmentation = "zR";
      for (const char Value : Augmentation) {
        if (Cursor >= End || Bytes[Cursor++] != static_cast<Byte>(Value))
          return Unexpect(ErrCode::Value::IllegalPath);
      }
      if (Cursor >= End || Bytes[Cursor++] != 0)
        return Unexpect(ErrCode::Value::IllegalPath);
      uint64_t Unsigned = 0;
      int64_t Signed = 0;
      if (!readULEB(Bytes.subspan(0, End), Cursor, Unsigned) || Unsigned != 1 ||
          !readSLEB(Bytes.subspan(0, End), Cursor, Signed) || Signed >= 0 ||
          !readULEB(Bytes.subspan(0, End), Cursor, Unsigned) ||
          !readULEB(Bytes.subspan(0, End), Cursor, Unsigned) || Unsigned != 1 ||
          Cursor >= End || Bytes[Cursor++] != ExpectedFDEEncoding)
        return Unexpect(ErrCode::Value::IllegalPath);
      CIEs.emplace(Record, ExpectedFDEEncoding);
    } else {
      const size_t CIEPointer = Offset + 4;
      if (Id > CIEPointer || CIEs.count(CIEPointer - Id) == 0)
        return Unexpect(ErrCode::Value::IllegalPath);
      const size_t Start = Offset + 8;
      uint64_t Ignored = 0;
      if (!readU64(Bytes.subspan(0, End), Start, Ignored) ||
          !readU64(Bytes.subspan(0, End), Start + PointerWidth, Ignored))
        return Unexpect(ErrCode::Value::IllegalPath);
      size_t Cursor = Start + PointerWidth * 2;
      uint64_t AugmentationLength = 0;
      if (!readULEB(Bytes.subspan(0, End), Cursor, AugmentationLength) ||
          AugmentationLength != 0)
        return Unexpect(ErrCode::Value::IllegalPath);
      Result.Starts.push_back(Start);
      Result.FDEFields.insert(Start);
    }
    Offset = End;
  }
  if (!Terminated || CIEs.empty() || Result.Starts.empty())
    return Unexpect(ErrCode::Value::IllegalPath);
  return Result;
}

} // namespace

Expect<void> normalizeMachOEHFrame(LinkGraph &Graph) {
  if (Graph.format() != ObjectFormat::MachO)
    return {};
  auto Sections = Graph.mutableSectionsForEHFrame();
  auto Relocations = Graph.mutableRelocationsForEHFrame();
  std::vector<std::vector<Byte>> Content;
  Content.reserve(Sections.size());
  for (const auto &Section : Sections)
    Content.push_back(Section.Content);
  std::vector<uint8_t> Remove(Relocations.size());
  std::set<SymbolId> CoveredSymbols;
  bool HasEHFrame = false;
  for (size_t I = 0; I < Sections.size(); ++I) {
    if (Sections[I].Purpose != SectionPurpose::EHFrame)
      continue;
    HasEHFrame = true;
    EXPECTED_TRY(auto Parsed, parse(Content[I]));
    std::map<size_t, SymbolId> References;
    for (const auto &Reference : Graph.ehFrameReferences()) {
      if (Reference.Section == I)
        References.emplace(Reference.Offset, Reference.Symbol);
    }
    for (const auto Field : Parsed.FDEFields) {
      if (References.count(Field) != 0)
        continue;
      uint64_t Raw = 0;
      if (!readU64(Content[I], Field, Raw))
        return fail();
      const int128_t TargetValue = int128_t(Sections[I].InputAddress) + Field +
                                   static_cast<int64_t>(Raw);
      if (TargetValue < 0 || TargetValue > UINT64_MAX)
        return fail();
      const uint64_t Target = static_cast<uint64_t>(TargetValue);
      const auto Symbol = std::find_if(
          Graph.symbols().begin(), Graph.symbols().end(),
          [&](const auto &Value) {
            return Value.Section < Sections.size() &&
                   Sections[Value.Section].InputAddress + Value.Offset ==
                       Target;
          });
      if (Symbol == Graph.symbols().end())
        return fail();
      References.emplace(
          Field, static_cast<SymbolId>(Symbol - Graph.symbols().begin()));
    }
    for (size_t J = 0; J < Relocations.size(); ++J) {
      const auto &Relocation = Relocations[J];
      if (Relocation.Section != I)
        continue;
      if (Parsed.FDEFields.count(Relocation.Offset) == 0 ||
          (Relocation.PatchSize != 4 && Relocation.PatchSize != PointerWidth) ||
          Relocation.Symbol >= Graph.symbols().size())
        return fail();
      const auto &Symbol = Graph.symbols()[Relocation.Symbol];
      if (Symbol.Section >= Sections.size())
        return fail();
      const int128_t Delta = int128_t(Sections[Symbol.Section].Address) +
                             Symbol.Offset - int128_t(Sections[I].Address) -
                             Relocation.Offset;
      if (Delta < std::numeric_limits<int64_t>::min() ||
          Delta > std::numeric_limits<int64_t>::max())
        return fail();
      if (!Internal::writeSigned(Content[I], Relocation.Offset, PointerWidth,
                                 Endianness::Little,
                                 static_cast<int64_t>(Delta)))
        return fail();
      Remove[J] = true;
    }
    for (const auto &[Field, SymbolId] : References) {
      CoveredSymbols.insert(SymbolId);
      const auto &Symbol = Graph.symbols()[SymbolId];
      const int128_t S =
          int128_t(Sections[Symbol.Section].Address) + Symbol.Offset;
      const int128_t P = int128_t(Sections[I].Address) + Field;
      const int128_t Delta = S - P;
      if (Delta < std::numeric_limits<int64_t>::min() ||
          Delta > std::numeric_limits<int64_t>::max())
        return fail();
      if (!Internal::writeSigned(Content[I], Field, PointerWidth,
                                 Endianness::Little,
                                 static_cast<int64_t>(Delta)))
        return fail();
    }
    EXPECTED_TRY(parse(Content[I]));
  }
  if (!HasEHFrame)
    return fail();
  for (SymbolId I = 0; I < Graph.symbols().size(); ++I) {
    if (requiredSemanticFunction(Graph, Graph.symbols()[I]) &&
        CoveredSymbols.count(I) == 0)
      return fail();
  }
  for (size_t I = 0; I < Sections.size(); ++I)
    Sections[I].Content = std::move(Content[I]);
  Graph.removeEHFrameRelocations(Remove);
  return {};
}

Expect<void> validateMachOEHFrameCoverage(const LinkGraph &Graph) {
  if (Graph.format() != ObjectFormat::MachO)
    return {};
  EXPECTED_TRY(auto Starts, machOEHFrameStarts(Graph, 0));
  for (const auto &Symbol : Graph.symbols()) {
    if (!requiredSemanticFunction(Graph, Symbol))
      continue;
    if (Symbol.Section >= Graph.sections().size())
      return fail();
    const int128_t Address =
        int128_t(Graph.sections()[Symbol.Section].Address) + Symbol.Offset;
    if (Address < 0 || Address > UINT64_MAX ||
        std::find(Starts.begin(), Starts.end(),
                  static_cast<uint64_t>(Address)) == Starts.end())
      return fail();
  }
  return {};
}

Expect<std::vector<uint64_t>> machOEHFrameStarts(const LinkGraph &Graph,
                                                 uint64_t LoadBase) {
  std::vector<uint64_t> Result;
  for (const auto &Section : Graph.sections()) {
    if (Section.Purpose != SectionPurpose::EHFrame)
      continue;
    EXPECTED_TRY(auto Parsed, parse(Section.Content));
    for (const auto Field : Parsed.Starts) {
      uint64_t Raw = 0;
      if (!readU64(Section.Content, Field, Raw))
        return Unexpect(ErrCode::Value::IllegalPath);
      const int64_t Delta = static_cast<int64_t>(Raw);
      Result.push_back(LoadBase + Section.Address + Field + Delta);
    }
  }
  if (Result.empty())
    return Unexpect(ErrCode::Value::IllegalPath);
  return Result;
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
