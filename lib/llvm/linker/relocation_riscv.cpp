// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

#include <map>
#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {
namespace Internal {
namespace {

using namespace std::literals;

Expect<RelocationResult> fail(const Relocation &Value,
                              std::string_view Message) {
  spdlog::error("native linker: {} (RISC-V type {}, offset {})"sv, Message,
                Value.Type, Value.Offset);
  return Unexpect(ErrCode::Value::IllegalPath);
}

bool signedBits(int128_t Value, unsigned Bits) {
  const int128_t Limit = int128_t(1) << (Bits - 1);
  return Value >= -Limit && Value < Limit;
}

} // namespace

Expect<RelocationResult> applyRISCV(const LinkGraph &Graph) {
  RelocationResult Result;
  for (const auto &Section : Graph.sections()) {
    Result.Content.push_back(Section.Content);
  }
  Result.Rebases = Graph.rebases();
  std::map<std::pair<SectionId, uint64_t>, int128_t> HighValues;
  for (const auto &Rel : Graph.relocations()) {
    if (Rel.Format != ObjectFormat::ELF ||
        (Rel.PatchSize != 0 && (Rel.Offset & 3) != 0)) {
      return fail(Rel, "invalid relocation field");
    }
    if (Rel.Type == 51) {
      continue;
    }
    auto &Bytes = Result.Content[Rel.Section];
    const auto &Symbol = Graph.symbols()[Rel.Symbol];
    const int128_t S = int128_t(Graph.sections()[Symbol.Section].Address) +
                       Symbol.Offset + Rel.Addend;
    const int128_t P =
        int128_t(Graph.sections()[Rel.Section].Address) + Rel.Offset;
    if (Rel.Type == 2) {
      if (S < 0 || S > UINT64_MAX ||
          !writeUnsigned(Bytes, Rel.Offset, 8, Endianness::Little,
                         static_cast<uint64_t>(S))) {
        return fail(Rel, "absolute relocation overflows");
      }
      if (hasRebaseOverlap(Result.Rebases, Rel.Section, Rel.Offset, 8)) {
        return fail(Rel, "overlapping generated rebase");
      }
      Result.Rebases.push_back(
          Rebase{Rel.Section, Rel.Offset, Rel.Type, Rel.Addend, 8});
      continue;
    }
    if (Rel.Type == 57) {
      const int128_t Value = S - P;
      if (!signedBits(Value, 32) ||
          !writeSigned(Bytes, Rel.Offset, 4, Endianness::Little,
                       static_cast<int64_t>(Value))) {
        return fail(Rel, "32_PCREL relocation overflows");
      }
      continue;
    }
    auto Word = readUnsigned(Bytes, Rel.Offset, 4, Endianness::Little);
    if (!Word) {
      return fail(Rel, "relocation field exceeds section content");
    }
    uint32_t Instruction = static_cast<uint32_t>(*Word);
    if (Rel.Type == 18 || Rel.Type == 19) {
      auto Second = readUnsigned(Bytes, Rel.Offset + 4, 4, Endianness::Little);
      if ((Instruction & 0x7F) != 0x17 || !Second ||
          (*Second & 0x707F) != 0x67) {
        return fail(Rel, "invalid call instruction pair");
      }
      const int128_t Delta = S - P;
      const int128_t High = (Delta + 0x800) >> 12;
      const int128_t Low = Delta - (High << 12);
      if (!signedBits(Delta, 32) || !signedBits(Low, 12)) {
        return fail(Rel, "call displacement overflows");
      }
      Instruction = (Instruction & 0xFFF) | (static_cast<uint32_t>(High) << 12);
      const uint32_t Jalr = (static_cast<uint32_t>(*Second) & 0x000FFFFF) |
                            ((static_cast<uint32_t>(Low) & 0xFFF) << 20);
      if (!writeUnsigned(Bytes, Rel.Offset, 4, Endianness::Little,
                         Instruction) ||
          !writeUnsigned(Bytes, Rel.Offset + 4, 4, Endianness::Little, Jalr)) {
        return fail(Rel, "cannot encode call pair");
      }
      continue;
    }
    if (Rel.Type == 23) {
      if ((Instruction & 0x7F) != 0x17) {
        return fail(Rel, "invalid PCREL_HI20 instruction");
      }
      const int128_t Delta = S - P;
      const int128_t High = (Delta + 0x800) >> 12;
      if (!signedBits(Delta, 32)) {
        return fail(Rel, "PCREL_HI20 displacement overflows");
      }
      Instruction = (Instruction & 0xFFF) | (static_cast<uint32_t>(High) << 12);
      HighValues.emplace(std::make_pair(Rel.Section, Rel.Offset), Delta);
    } else if (Rel.Type == 24 || Rel.Type == 25) {
      const auto HighSection = Graph.symbols()[Rel.Symbol].Section;
      const auto HighOffset = Graph.symbols()[Rel.Symbol].Offset;
      const auto High = HighValues.find({HighSection, HighOffset});
      if (High == HighValues.end()) {
        return fail(Rel, "missing PCREL_HI20 pair");
      }
      const int128_t Rounded = (High->second + 0x800) >> 12;
      const uint32_t Low =
          static_cast<uint32_t>(High->second - (Rounded << 12)) & 0xFFF;
      if (Rel.Type == 24) {
        if ((Instruction & 0x7F) != 0x13 && (Instruction & 0x7F) != 0x03 &&
            (Instruction & 0x7F) != 0x67) {
          return fail(Rel, "invalid PCREL_LO12_I instruction");
        }
        Instruction = (Instruction & 0x000FFFFF) | (Low << 20);
      } else {
        if ((Instruction & 0x7F) != 0x23) {
          return fail(Rel, "invalid PCREL_LO12_S instruction");
        }
        Instruction = (Instruction & 0x01FFF07F) | ((Low & 0x1F) << 7) |
                      ((Low & 0xFE0) << 20);
      }
    } else {
      return fail(Rel, "unsupported RISC-V relocation type");
    }
    if (!writeUnsigned(Bytes, Rel.Offset, 4, Endianness::Little, Instruction)) {
      return fail(Rel, "cannot encode instruction");
    }
  }
  return Result;
}

} // namespace Internal
} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
