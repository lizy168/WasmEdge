// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/layout.h"

#include <algorithm>
#include <array>
#include <limits>
#include <numeric>
#include <tuple>
#include <utility>
#include <vector>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

template <typename T> LinkExpect<T> fail(Diagnostic Value) {
  return Unexpected<Diagnostic>(std::move(Value));
}

uint8_t kindOrder(SectionKind Kind) noexcept {
  switch (Kind) {
  case SectionKind::Text:
    return 0;
  case SectionKind::ReadOnly:
    return 1;
  case SectionKind::Unwind:
    return 2;
  case SectionKind::Data:
    return 3;
  case SectionKind::BSS:
    return 4;
  }
  return std::numeric_limits<uint8_t>::max();
}

bool checkedAlign(uint64_t Value, uint64_t Alignment,
                  uint64_t &Result) noexcept {
  const uint64_t Mask = Alignment - 1;
  if (Value > std::numeric_limits<uint64_t>::max() - Mask) {
    return false;
  }
  Result = (Value + Mask) & ~Mask;
  return true;
}

bool checkedAdd(uint64_t Left, uint64_t Right, uint64_t &Result) noexcept {
  if (Left > std::numeric_limits<uint64_t>::max() - Right) {
    return false;
  }
  Result = Left + Right;
  return true;
}

LinkExpect<void> overflow(const Section &SectionValue, SectionId Id,
                          const char *Message) {
  Diagnostic Diag{Message};
  Diag.Section = Id;
  Diag.SectionName = SectionValue.Name;
  return fail<void>(std::move(Diag));
}

} // namespace

LinkExpect<void> layout(LinkGraph &Graph, uint64_t ImageBase) noexcept {
  if (auto Result = Graph.validate(); !Result) {
    return Result;
  }

  const auto &Sections = Graph.sections();
  std::vector<SectionId> Order(Sections.size());
  std::iota(Order.begin(), Order.end(), SectionId{0});
  std::sort(Order.begin(), Order.end(), [&](SectionId Left, SectionId Right) {
    const auto &L = Sections[Left];
    const auto &R = Sections[Right];
    return std::tuple(kindOrder(L.Kind), L.Name, Left) <
           std::tuple(kindOrder(R.Kind), R.Name, Right);
  });

  std::vector<std::array<uint64_t, 2>> Placements(Sections.size());
  uint64_t Address = ImageBase;
  uint64_t FileOffset = 0;
  for (const SectionId Id : Order) {
    const auto &SectionValue = Sections[Id];
    if (!checkedAlign(Address, SectionValue.Alignment, Address)) {
      return overflow(SectionValue, Id, "section address alignment overflows");
    }
    if (SectionValue.Kind != SectionKind::BSS &&
        !checkedAlign(FileOffset, SectionValue.Alignment, FileOffset)) {
      return overflow(SectionValue, Id,
                      "section file offset alignment overflows");
    }
    Placements[Id] = {Address, FileOffset};
    if (!checkedAdd(Address, SectionValue.VirtualSize, Address)) {
      return overflow(SectionValue, Id, "section virtual size overflows");
    }
    if (SectionValue.Kind != SectionKind::BSS &&
        !checkedAdd(FileOffset, SectionValue.Content.size(), FileOffset)) {
      return overflow(SectionValue, Id, "section file size overflows");
    }
  }

  for (SectionId Id = 0; Id < Placements.size(); ++Id) {
    if (auto Result = Graph.setSectionAddress(Id, Placements[Id][0]); !Result) {
      return Result;
    }
    if (auto Result = Graph.setSectionFileOffset(Id, Placements[Id][1]);
        !Result) {
      return Result;
    }
  }
  return {};
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
