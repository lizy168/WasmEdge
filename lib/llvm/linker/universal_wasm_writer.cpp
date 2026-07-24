// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/universal_wasm_writer.h"

#include "aot/version.h"
#include "common/defines.h"
#include "common/spdlog.h"
#include "linker/writer.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <optional>
#include <string_view>
#include <tuple>
#include <vector>

using namespace std::literals;

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

enum class AOTSectionKind : uint8_t {
  Text = 1,
  Data = 2,
  BSS = 3,
  Unwind = 4,
};

enum class AOTOSType : uint8_t { Linux = 1, MacOS = 2, Windows = 3 };
enum class AOTArchType : uint8_t {
  X86_64 = 1,
  AArch64 = 2,
  RISCV64 = 3,
  ARM = 4,
  S390X = 5,
};

constexpr uint8_t CustomSectionId = 0;

Expect<void> writeError() noexcept {
  return Unexpect(ErrCode::Value::IllegalPath);
}

std::optional<uint8_t> hostOS() noexcept {
#if WASMEDGE_OS_LINUX
  return static_cast<uint8_t>(AOTOSType::Linux);
#elif WASMEDGE_OS_MACOS
  return static_cast<uint8_t>(AOTOSType::MacOS);
#elif WASMEDGE_OS_WINDOWS
  return static_cast<uint8_t>(AOTOSType::Windows);
#else
  return std::nullopt;
#endif
}

std::optional<uint8_t> architecture(Target Value) noexcept {
  switch (Value) {
  case Target::X86_64:
    return static_cast<uint8_t>(AOTArchType::X86_64);
  case Target::AArch64:
    return static_cast<uint8_t>(AOTArchType::AArch64);
  case Target::RISCV64:
    return static_cast<uint8_t>(AOTArchType::RISCV64);
  case Target::ARM:
    return static_cast<uint8_t>(AOTArchType::ARM);
  case Target::S390X:
    return static_cast<uint8_t>(AOTArchType::S390X);
  }
  return std::nullopt;
}

std::optional<AOTSectionKind> sectionKind(SectionKind Kind) noexcept {
  switch (Kind) {
  case SectionKind::Text:
    return AOTSectionKind::Text;
  case SectionKind::ReadOnly:
  case SectionKind::Data:
    return AOTSectionKind::Data;
  case SectionKind::BSS:
    return AOTSectionKind::BSS;
  case SectionKind::Unwind:
    return AOTSectionKind::Unwind;
  }
  return std::nullopt;
}

struct OutputSection {
  SectionKind Kind;
  uint64_t Address;
  uint64_t Size;
  std::vector<Byte> Content;
};

Expect<std::vector<OutputSection>> outputSections(const LinkGraph &Graph) {
  std::vector<const Section *> Ordered;
  for (const auto &Value : Graph.sections()) {
    if (Value.VirtualSize != 0 &&
        Value.Purpose != SectionPurpose::CompactUnwind) {
      Ordered.push_back(&Value);
    }
  }
  std::sort(Ordered.begin(), Ordered.end(),
            [](const auto *Left, const auto *Right) {
              return std::tuple(Left->Kind, Left->Address, Left->Name) <
                     std::tuple(Right->Kind, Right->Address, Right->Name);
            });
  std::vector<OutputSection> Result;
  for (const auto *Value : Ordered) {
    if (Value->Content.size() > Value->VirtualSize ||
        Value->Address >
            std::numeric_limits<uint64_t>::max() - Value->VirtualSize) {
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    const uint64_t End = Value->Address + Value->VirtualSize;
    if (Result.empty() || Result.back().Kind != Value->Kind) {
      Result.push_back(OutputSection{Value->Kind, Value->Address,
                                     Value->VirtualSize, Value->Content});
      continue;
    }
    auto &Output = Result.back();
    if (Value->Address < Output.Address ||
        Value->Address < Output.Address + Output.Size) {
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    const uint64_t Size = End - Output.Address;
    if (Size > std::numeric_limits<size_t>::max()) {
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    if (Output.Kind != SectionKind::BSS) {
      Output.Content.resize(
          static_cast<size_t>(Value->Address - Output.Address));
      Output.Content.insert(Output.Content.end(), Value->Content.begin(),
                            Value->Content.end());
    }
    Output.Size = Size;
  }
  return Result;
}

std::optional<uint64_t> symbolAddress(const LinkGraph &Graph,
                                      const Symbol &Value) noexcept {
  if (Value.Section >= Graph.sections().size()) {
    return std::nullopt;
  }
  const auto Base = Graph.sections()[Value.Section].Address;
  if (Value.Offset > std::numeric_limits<uint64_t>::max() - Base) {
    return std::nullopt;
  }
  return Base + Value.Offset;
}

bool indexedSymbol(std::string_view Name, char Prefix,
                   uint64_t &Index) noexcept {
  if (Name.size() < 2 || Name.front() != Prefix) {
    return false;
  }
  const auto Result =
      std::from_chars(Name.data() + 1, Name.data() + Name.size(), Index);
  return Result.ec == std::errc{} && Result.ptr == Name.data() + Name.size();
}

std::optional<std::string_view> semanticName(const LinkGraph &Graph,
                                             const Symbol &Value) {
  if (!Value.Exported && !Value.Global)
    return std::nullopt;
  std::string_view Name = Value.ExportName ? *Value.ExportName : Value.Name;
  if (Graph.format() == ObjectFormat::MachO && !Name.empty() && Name[0] == '_')
    Name.remove_prefix(1);
  return Name;
}

Expect<void> writeAddresses(Writer &Output, const LinkGraph &Graph) {
  uint64_t Version = 0;
  uint64_t Intrinsics = 0;
  std::vector<uint64_t> Types;
  std::vector<uint64_t> Codes;
  std::vector<bool> TypePresent;
  std::vector<bool> CodePresent;
  uint64_t FirstCode = std::numeric_limits<uint64_t>::max();
  bool HasVersion = false;
  bool HasIntrinsics = false;
  for (const auto &SymbolValue : Graph.symbols()) {
    const auto Address = symbolAddress(Graph, SymbolValue);
    if (!Address) {
      return writeError();
    }
    const auto Name = semanticName(Graph, SymbolValue);
    if (!Name)
      continue;
    if (*Name == "version") {
      if (HasVersion)
        return writeError();
      HasVersion = true;
      Version = *Address;
    } else if (*Name == "intrinsics") {
      if (HasIntrinsics)
        return writeError();
      HasIntrinsics = true;
      Intrinsics = *Address;
    } else {
      uint64_t Index = 0;
      if (indexedSymbol(*Name, 't', Index) &&
          std::to_string(Index) == Name->substr(1)) {
        if (Index == std::numeric_limits<uint64_t>::max() ||
            Index >= std::numeric_limits<size_t>::max()) {
          return writeError();
        }
        if (TypePresent.size() > Index && TypePresent[Index])
          return writeError();
        Types.resize(std::max(Types.size(), static_cast<size_t>(Index + 1)));
        TypePresent.resize(Types.size());
        Types[Index] = *Address;
        TypePresent[Index] = true;
      } else if (indexedSymbol(*Name, 'f', Index) &&
                 std::to_string(Index) == Name->substr(1)) {
        if (Index == std::numeric_limits<uint64_t>::max() ||
            Index >= std::numeric_limits<size_t>::max()) {
          return writeError();
        }
        if (CodePresent.size() > Index && CodePresent[Index])
          return writeError();
        Codes.resize(std::max(Codes.size(), static_cast<size_t>(Index + 1)));
        CodePresent.resize(Codes.size());
        Codes[Index] = *Address;
        CodePresent[Index] = true;
        FirstCode = std::min(FirstCode, Index);
      }
    }
  }
  if (!HasVersion || !HasIntrinsics ||
      std::find(TypePresent.begin(), TypePresent.end(), false) !=
          TypePresent.end()) {
    spdlog::error(
        "universal writer: invalid semantic symbols version={} intrinsics={} types={} codes={}"sv,
        HasVersion, HasIntrinsics, Types.size(), Codes.size());
    return writeError();
  }
  if (FirstCode != std::numeric_limits<uint64_t>::max()) {
    Codes.erase(Codes.begin(), Codes.begin() + static_cast<size_t>(FirstCode));
    CodePresent.erase(CodePresent.begin(),
                      CodePresent.begin() + static_cast<size_t>(FirstCode));
  }
  if (std::find(CodePresent.begin(), CodePresent.end(), false) !=
      CodePresent.end())
    return writeError();
  EXPECTED_TRY(Output.writeU64(Version));
  EXPECTED_TRY(Output.writeU64(Intrinsics));
  EXPECTED_TRY(Output.writeU64(Types.size()));
  for (const auto Address : Types) {
    EXPECTED_TRY(Output.writeU64(Address));
  }
  EXPECTED_TRY(Output.writeU64(Codes.size()));
  for (const auto Address : Codes) {
    EXPECTED_TRY(Output.writeU64(Address));
  }
  return {};
}

} // namespace

Expect<void>
UniversalWasmWriter::write(const LinkGraph &Graph, Span<const Byte> Wasm,
                           const std::filesystem::path &Output) noexcept {
  try {
    Writer Result(Output);
    return write(Graph, Wasm, Result);
  } catch (...) {
    return writeError();
  }
}

Expect<void> UniversalWasmWriter::write(const LinkGraph &Graph,
                                        Span<const Byte> Wasm, Writer &Result) {
  constexpr std::array<Byte, 8> WasmHeader{0x00, 0x61, 0x73, 0x6D,
                                           0x01, 0x00, 0x00, 0x00};
  if (Wasm.size() < WasmHeader.size() ||
      !std::equal(WasmHeader.begin(), WasmHeader.end(), Wasm.begin()))
    return writeError();
  size_t Offset = WasmHeader.size();
  while (Offset < Wasm.size()) {
    const Byte SectionId = Wasm[Offset++];
    constexpr Byte LastCoreSectionId = 13;
    if (SectionId > LastCoreSectionId)
      return writeError();
    uint32_t Size = 0;
    unsigned Shift = 0;
    Byte Encoded = 0;
    do {
      if (Offset >= Wasm.size() || Shift >= 35)
        return writeError();
      Encoded = Wasm[Offset++];
      if (Shift == 28 && (Encoded & 0xF0) != 0)
        return writeError();
      Size |= static_cast<uint32_t>(Encoded & 0x7F) << Shift;
      Shift += 7;
    } while ((Encoded & 0x80) != 0);
    if (Offset > Wasm.size() || Size > Wasm.size() - Offset)
      return writeError();
    Offset += Size;
  }
  const auto OS = hostOS();
  const auto Arch = architecture(Graph.target());
  if (!OS || !Arch || !Graph.relocationsApplied()) {
    return writeError();
  }

  std::vector<Byte> Payload;
  Writer Section(Payload);
  EXPECTED_TRY(Section.writeName("wasmedge"sv));
  EXPECTED_TRY(Section.writeU32(AOT::kBinaryVersion));
  EXPECTED_TRY(Section.writeByte(*OS));
  EXPECTED_TRY(Section.writeByte(*Arch));
  EXPECTED_TRY(writeAddresses(Section, Graph));
  EXPECTED_TRY(auto Sections, outputSections(Graph));
  if (Sections.size() > std::numeric_limits<uint32_t>::max()) {
    return writeError();
  }
  EXPECTED_TRY(Section.writeU32(static_cast<uint32_t>(Sections.size())));
  for (const auto &Value : Sections) {
    const auto Kind = sectionKind(Value.Kind);
    if (!Kind) {
      return writeError();
    }
    EXPECTED_TRY(Section.writeByte(static_cast<uint8_t>(*Kind)));
    EXPECTED_TRY(Section.writeU64(Value.Address));
    EXPECTED_TRY(Section.writeU64(Value.Size));
    EXPECTED_TRY(Section.writeName(
        std::string_view(reinterpret_cast<const char *>(Value.Content.data()),
                         Value.Content.size())));
  }
  EXPECTED_TRY(Section.close());
  if (Payload.size() > UINT32_MAX) {
    return writeError();
  }

  EXPECTED_TRY(Result.write(Wasm));
  EXPECTED_TRY(Result.writeByte(CustomSectionId));
  EXPECTED_TRY(Result.writeU32(static_cast<uint32_t>(Payload.size())));
  EXPECTED_TRY(Result.write(Payload));
  return Result.close();
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
