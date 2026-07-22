// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

#include <limits>
#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {
namespace Internal {

namespace {

using namespace std::literals;

constexpr uint32_t R_X86_64_64 = 1;
constexpr uint32_t R_X86_64_PC32 = 2;
constexpr uint32_t R_X86_64_PLT32 = 4;
constexpr uint32_t R_X86_64_GOTPCRELX = 41;
constexpr uint32_t R_X86_64_REX_GOTPCRELX = 42;

uint64_t magnitude(int64_t Value) noexcept {
  return Value < 0 ? static_cast<uint64_t>(-(Value + 1)) + 1
                   : static_cast<uint64_t>(Value);
}

bool addUnsigned(uint64_t Value, int64_t Addend, uint64_t &Result) noexcept {
  if (Addend < 0) {
    const uint64_t Amount = magnitude(Addend);
    if (Value < Amount) {
      return false;
    }
    Result = Value - Amount;
    return true;
  }
  const uint64_t Amount = static_cast<uint64_t>(Addend);
  if (Value > std::numeric_limits<uint64_t>::max() - Amount) {
    return false;
  }
  Result = Value + Amount;
  return true;
}

bool delta32(uint64_t Symbol, int64_t Addend, uint64_t Place,
             int64_t &Result) noexcept {
  bool Negative = Symbol < Place;
  uint64_t Amount = Negative ? Place - Symbol : Symbol - Place;
  const bool AddendNegative = Addend < 0;
  const uint64_t AddendAmount = magnitude(Addend);
  if (Negative == AddendNegative) {
    if (Amount > UINT64_MAX - AddendAmount) {
      return false;
    }
    Amount += AddendAmount;
  } else if (Amount >= AddendAmount) {
    Amount -= AddendAmount;
  } else {
    Amount = AddendAmount - Amount;
    Negative = AddendNegative;
  }
  if ((!Negative && Amount > static_cast<uint64_t>(INT32_MAX)) ||
      (Negative && Amount > UINT64_C(2147483648))) {
    return false;
  }
  Result =
      Negative ? -static_cast<int64_t>(Amount) : static_cast<int64_t>(Amount);
  return true;
}

Expect<RelocationResult> fail(const Relocation &RelocationValue,
                              std::string_view Message) {
  spdlog::error(
      "native linker: {} (section {}, symbol {}, type {}, offset {})"sv,
      Message, RelocationValue.Section, RelocationValue.Symbol,
      RelocationValue.Type, RelocationValue.Offset);
  return Unexpect(ErrCode::Value::IllegalPath);
}

} // namespace

Expect<RelocationResult> applyX86_64(const LinkGraph &Graph) {
  RelocationResult Result;
  Result.Content.reserve(Graph.sections().size());
  for (const auto &Section : Graph.sections()) {
    Result.Content.push_back(Section.Content);
  }
  Result.Rebases = Graph.rebases();

  for (const auto &RelocationValue : Graph.relocations()) {
    uint8_t Width = 0;
    bool Absolute = false;
    bool Relax = false;
    int64_t FormatAdjustment = 0;
    if (RelocationValue.Format == ObjectFormat::ELF) {
      switch (RelocationValue.Type) {
      case R_X86_64_64:
        Width = 8;
        Absolute = true;
        break;
      case R_X86_64_PC32:
      case R_X86_64_PLT32:
        Width = 4;
        break;
      case R_X86_64_GOTPCRELX:
      case R_X86_64_REX_GOTPCRELX:
        Width = 4;
        Relax = true;
        break;
      default:
        return fail(RelocationValue, "unsupported x86_64 relocation type");
      }
    } else if (RelocationValue.Format == ObjectFormat::MachO &&
               RelocationValue.Type == 1) {
      Width = 4;
    } else if (RelocationValue.Format == ObjectFormat::COFF &&
               RelocationValue.Type == 4) {
      Width = 4;
      FormatAdjustment = -4;
    } else {
      return fail(RelocationValue, "unsupported x86_64 relocation type");
    }
    auto &Bytes = Result.Content[RelocationValue.Section];
    if (RelocationValue.Offset > Bytes.size() ||
        Width > Bytes.size() - RelocationValue.Offset) {
      return fail(RelocationValue, "relocation field exceeds section content");
    }
    const auto &Symbol = Graph.symbols()[RelocationValue.Symbol];
    const auto &SymbolSection = Graph.sections()[Symbol.Section];
    if (Symbol.Offset > UINT64_MAX - SymbolSection.Address) {
      return fail(RelocationValue, "symbol address overflows");
    }
    const uint64_t S = SymbolSection.Address + Symbol.Offset;
    const auto &PatchSection = Graph.sections()[RelocationValue.Section];
    if (RelocationValue.Offset > UINT64_MAX - PatchSection.Address) {
      return fail(RelocationValue, "relocation place overflows");
    }
    const uint64_t P = PatchSection.Address + RelocationValue.Offset;
    int64_t Addend = RelocationValue.Addend;
    if (RelocationValue.AddendIsImplicit) {
      auto Decoded =
          readSigned(Bytes, RelocationValue.Offset, Width, Graph.endianness());
      if (!Decoded) {
        return fail(RelocationValue, "cannot decode implicit addend");
      }
      Addend = *Decoded;
    }
    if ((FormatAdjustment < 0 &&
         Addend < std::numeric_limits<int64_t>::min() - FormatAdjustment) ||
        (FormatAdjustment > 0 &&
         Addend > std::numeric_limits<int64_t>::max() - FormatAdjustment)) {
      return fail(RelocationValue, "relocation addend overflows");
    }
    Addend += FormatAdjustment;
    if (Absolute) {
      uint64_t Value = 0;
      if (!addUnsigned(S, Addend, Value) ||
          !writeUnsigned(Bytes, RelocationValue.Offset, Width,
                         Graph.endianness(), Value)) {
        return fail(RelocationValue, "absolute relocation overflows");
      }
      Result.Rebases.push_back(Rebase{RelocationValue.Section,
                                      RelocationValue.Offset,
                                      RelocationValue.Type, Addend, Width});
      Result.Rebases.back().Format = RelocationValue.Format;
      continue;
    }
    if (Relax) {
      size_t Opcode = Bytes.size();
      if (RelocationValue.Offset >= 2 &&
          Bytes[RelocationValue.Offset - 2] == 0x8B) {
        Opcode = static_cast<size_t>(RelocationValue.Offset - 2);
      } else if (RelocationValue.Offset >= 1 &&
                 Bytes[RelocationValue.Offset - 1] == 0x8B) {
        Opcode = static_cast<size_t>(RelocationValue.Offset - 1);
      }
      if (Opcode == Bytes.size()) {
        return fail(RelocationValue, "unsupported GOTPCRELX instruction");
      }
      Bytes[Opcode] = 0x8D;
    }
    int64_t Value = 0;
    if (!delta32(S, Addend, P, Value) ||
        !writeSigned(Bytes, RelocationValue.Offset, Width, Graph.endianness(),
                     Value)) {
      return fail(RelocationValue, "PC-relative relocation overflows");
    }
  }
  return Result;
}

} // namespace Internal
} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
