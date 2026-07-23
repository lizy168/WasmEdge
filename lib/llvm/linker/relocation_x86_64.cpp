// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

#include <algorithm>
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
      const auto Overlap = std::find_if(
          Result.Rebases.begin(), Result.Rebases.end(), [&](const auto &Old) {
            if (Old.Section != RelocationValue.Section) {
              return false;
            }
            const uint64_t OldWidth = std::max<uint8_t>(Old.Width, 1);
            if (RelocationValue.Offset <= Old.Offset) {
              return Width > Old.Offset - RelocationValue.Offset;
            }
            return OldWidth > RelocationValue.Offset - Old.Offset;
          });
      if (Overlap != Result.Rebases.end()) {
        return fail(RelocationValue, "overlapping generated rebase");
      }
      Result.Rebases.push_back(Rebase{RelocationValue.Section,
                                      RelocationValue.Offset,
                                      RelocationValue.Type, Addend, Width});
      Result.Rebases.back().Format = RelocationValue.Format;
      continue;
    }
    if (Relax) {
      if (RelocationValue.AddendIsImplicit || Addend != -4 ||
          RelocationValue.Offset < 2) {
        return fail(RelocationValue, "unsupported GOTPCRELX instruction");
      }
      const size_t Opcode = static_cast<size_t>(RelocationValue.Offset - 2);
      const uint8_t Op = Bytes[Opcode];
      const uint8_t ModRM = Bytes[Opcode + 1];
      const bool HasRex = RelocationValue.Offset >= 3 &&
                          (Bytes[RelocationValue.Offset - 3] & 0xF0) == 0x40;
      if (RelocationValue.Type == R_X86_64_REX_GOTPCRELX && !HasRex) {
        return fail(RelocationValue, "unsupported GOTPCRELX instruction");
      }
      if (Op == 0x8B && (ModRM & 0xC7) == 0x05) {
        Bytes[Opcode] = 0x8D;
      } else if (Op == 0xFF && ModRM == 0x15 && S <= UINT32_MAX) {
        Bytes[Opcode] = 0x67;
        Bytes[Opcode + 1] = 0xE8;
      } else if (Op == 0xFF && ModRM == 0x25 && S <= UINT32_MAX) {
        int64_t Value = 0;
        if (!delta32(S, Addend + 1, P, Value) ||
            !writeSigned(Bytes, RelocationValue.Offset - 1, Width,
                         Graph.endianness(), Value)) {
          return fail(RelocationValue, "PC-relative relocation overflows");
        }
        Bytes[Opcode] = 0xE9;
        Bytes[RelocationValue.Offset + 3] = 0x90;
        continue;
      } else {
        return fail(RelocationValue, "unsupported GOTPCRELX instruction");
      }
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
