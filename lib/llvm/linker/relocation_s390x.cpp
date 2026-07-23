// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/relocation.h"

#include "common/spdlog.h"

#include <string_view>

namespace WasmEdge {
namespace LLVM {
namespace Linker {
namespace Internal {
namespace {

using namespace std::literals;

Expect<RelocationResult> fail(const Relocation &Value,
                              std::string_view Message) {
  spdlog::error("native linker: {} (s390x type {}, offset {})"sv, Message,
                Value.Type, Value.Offset);
  return Unexpect(ErrCode::Value::IllegalPath);
}

bool signedBits(int128_t Value, unsigned Bits) {
  const int128_t Limit = int128_t(1) << (Bits - 1);
  return Value >= -Limit && Value < Limit;
}

} // namespace

Expect<RelocationResult> applyS390X(const LinkGraph &Graph) {
  RelocationResult Result;
  for (const auto &Section : Graph.sections()) {
    Result.Content.push_back(Section.Content);
  }
  Result.Rebases = Graph.rebases();
  for (const auto &Rel : Graph.relocations()) {
    if (Rel.Format != ObjectFormat::ELF || (Rel.Offset & 1) != 0) {
      return fail(Rel, "invalid relocation field");
    }
    auto &Bytes = Result.Content[Rel.Section];
    const auto &Symbol = Graph.symbols()[Rel.Symbol];
    const int128_t S = int128_t(Graph.sections()[Symbol.Section].Address) +
                       Symbol.Offset + Rel.Addend;
    const int128_t P =
        int128_t(Graph.sections()[Rel.Section].Address) + Rel.Offset;
    if (Rel.Type == 22) {
      if (S < 0 || S > UINT64_MAX ||
          !writeUnsigned(Bytes, Rel.Offset, 8, Endianness::Big,
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
    int128_t Value = S - P;
    if (Rel.Type == 19 || Rel.Type == 20) {
      if ((Value & 1) != 0) {
        return fail(Rel, "doubled displacement is not even");
      }
      Value /= 2;
    } else if (Rel.Type != 5) {
      return fail(Rel, "unsupported s390x relocation type");
    }
    if (!signedBits(Value, 32) ||
        !writeSigned(Bytes, Rel.Offset, 4, Endianness::Big,
                     static_cast<int64_t>(Value))) {
      return fail(Rel, "PC-relative relocation overflows");
    }
  }
  return Result;
}

} // namespace Internal
} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
