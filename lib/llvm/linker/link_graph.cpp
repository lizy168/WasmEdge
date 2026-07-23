// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/link_graph.h"

#include <algorithm>
#include <utility>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

template <typename T> LinkExpect<T> fail(Diagnostic Value) {
  return Unexpected<Diagnostic>(std::move(Value));
}

bool extendsBeyond(uint64_t Offset, uint64_t Size, uint64_t Limit) noexcept {
  return Offset > Limit || Size > Limit - Offset;
}

template <typename T, typename Size>
bool overlaps(const T &Left, const T &Right, Size GetSize) noexcept {
  if (Left.Section != Right.Section) {
    return false;
  }
  const uint64_t LeftSize = GetSize(Left);
  const uint64_t RightSize = GetSize(Right);
  if (Left.Offset <= Right.Offset) {
    return LeftSize > Right.Offset - Left.Offset;
  }
  return RightSize > Left.Offset - Right.Offset;
}

LinkExpect<void> relocated() {
  return fail<void>(Diagnostic{"link graph relocations already applied"});
}

} // namespace

LinkExpect<void> LinkGraph::beginInput(std::string_view Name) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (InputName) {
    return fail<void>(
        Diagnostic{"link graph accepts exactly one input object"});
  }
  InputName = std::string(Name);
  return {};
}

LinkExpect<SectionId> LinkGraph::addSection(Section Value) {
  if (RelocationsApplied) {
    return fail<SectionId>(
        Diagnostic{"link graph relocations already applied"});
  }
  if (Value.Alignment == 0 || (Value.Alignment & (Value.Alignment - 1)) != 0) {
    Diagnostic Diag{"section alignment must be a non-zero power of two"};
    Diag.SectionName = Value.Name;
    return fail<SectionId>(std::move(Diag));
  }
  if (Value.Content.size() > Value.VirtualSize) {
    Diagnostic Diag{"section content exceeds section virtual size"};
    Diag.SectionName = Value.Name;
    return fail<SectionId>(std::move(Diag));
  }
  if (Sections.size() >= InvalidSectionId) {
    return fail<SectionId>(Diagnostic{"too many sections"});
  }
  const SectionId Id{static_cast<uint32_t>(Sections.size())};
  Sections.push_back(std::move(Value));
  return Id;
}

LinkExpect<SymbolId> LinkGraph::addSymbol(Symbol Value) {
  if (RelocationsApplied) {
    return fail<SymbolId>(Diagnostic{"link graph relocations already applied"});
  }
  if (Value.Section == InvalidSectionId) {
    Diagnostic Diag{"undefined symbol"};
    Diag.SymbolName = Value.Name;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  if (Value.Section >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Value.Section;
    Diag.SymbolName = Value.Name;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  if (extendsBeyond(Value.Offset, Value.Size,
                    Sections[Value.Section].VirtualSize)) {
    Diagnostic Diag{"symbol extends beyond section virtual size"};
    Diag.Section = Value.Section;
    Diag.SymbolName = Value.Name;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  const auto Duplicate =
      std::find_if(Symbols.begin(), Symbols.end(), [&](const auto &Defined) {
        return Defined.Name == Value.Name;
      });
  if (Duplicate != Symbols.end()) {
    Diagnostic Diag{"duplicate symbol definition"};
    Diag.SymbolName = Value.Name;
    Diag.Section = Value.Section;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  if (Symbols.size() >= InvalidSymbolId) {
    return fail<SymbolId>(Diagnostic{"too many symbols"});
  }
  const SymbolId Id{static_cast<uint32_t>(Symbols.size())};
  Symbols.push_back(std::move(Value));
  return Id;
}

LinkExpect<void> LinkGraph::addRelocation(Relocation Value) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (Value.Section >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Value.Section;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  if (Value.Symbol >= Symbols.size()) {
    Diagnostic Diag{"invalid symbol ID"};
    Diag.Section = Value.Section;
    Diag.Symbol = Value.Symbol;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  if (extendsBeyond(Value.Offset, Value.PatchSize,
                    Sections[Value.Section].Content.size())) {
    Diagnostic Diag{"relocation offset is outside section content"};
    Diag.Section = Value.Section;
    Diag.Symbol = Value.Symbol;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  if (std::any_of(Relocations.begin(), Relocations.end(), [&](const auto &Old) {
        return overlaps(Value, Old, [](const auto &RelocationValue) {
          return RelocationValue.PatchSize;
        });
      })) {
    Diagnostic Diag{"overlapping relocation patches"};
    Diag.Section = Value.Section;
    Diag.Symbol = Value.Symbol;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  Relocations.push_back(Value);
  return {};
}

LinkExpect<void> LinkGraph::addRebase(Rebase Value) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (Value.Section >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Value.Section;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  const uint8_t Width = std::max<uint8_t>(Value.Width, 1);
  if (extendsBeyond(Value.Offset, Width,
                    Sections[Value.Section].Content.size())) {
    Diagnostic Diag{"rebase offset is outside section content"};
    Diag.Section = Value.Section;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  if (std::any_of(Rebases.begin(), Rebases.end(), [&](const auto &Old) {
        return overlaps(Value, Old, [](const auto &RebaseValue) {
          return std::max<uint8_t>(RebaseValue.Width, 1);
        });
      })) {
    Diagnostic Diag{"overlapping rebase patches"};
    Diag.Section = Value.Section;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  Rebases.push_back(Value);
  return {};
}

LinkExpect<void> LinkGraph::validate() const {
  if (!InputName) {
    return fail<void>(Diagnostic{"link graph requires one input object"});
  }
  for (SectionId I = 0; I < Sections.size(); ++I) {
    const auto &Value = Sections[I];
    if (Value.Alignment == 0 ||
        (Value.Alignment & (Value.Alignment - 1)) != 0) {
      Diagnostic Diag{"section alignment must be a non-zero power of two"};
      Diag.Section = I;
      Diag.SectionName = Value.Name;
      return fail<void>(std::move(Diag));
    }
    if (Value.Content.size() > Value.VirtualSize) {
      Diagnostic Diag{"section content exceeds section virtual size"};
      Diag.Section = I;
      Diag.SectionName = Value.Name;
      return fail<void>(std::move(Diag));
    }
  }
  for (size_t I = 0; I < Symbols.size(); ++I) {
    const auto &Value = Symbols[I];
    if (Value.Section >= Sections.size()) {
      Diagnostic Diag{"invalid section ID"};
      Diag.Section = Value.Section;
      Diag.Symbol = static_cast<SymbolId>(I);
      Diag.SymbolName = Value.Name;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    if (extendsBeyond(Value.Offset, Value.Size,
                      Sections[Value.Section].VirtualSize)) {
      Diagnostic Diag{"symbol extends beyond section virtual size"};
      Diag.Section = Value.Section;
      Diag.Symbol = static_cast<SymbolId>(I);
      Diag.SymbolName = Value.Name;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
  }
  for (const auto &Value : Relocations) {
    if (Value.Section >= Sections.size()) {
      Diagnostic Diag{"invalid section ID"};
      Diag.Section = Value.Section;
      Diag.Symbol = Value.Symbol;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    if (Value.Symbol >= Symbols.size()) {
      Diagnostic Diag{"invalid symbol ID"};
      Diag.Section = Value.Section;
      Diag.Symbol = Value.Symbol;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    if (extendsBeyond(Value.Offset, Value.PatchSize,
                      Sections[Value.Section].Content.size())) {
      Diagnostic Diag{"relocation offset is outside section content"};
      Diag.Section = Value.Section;
      Diag.Symbol = Value.Symbol;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
  }
  for (size_t I = 0; I < Relocations.size(); ++I) {
    for (size_t J = I + 1; J < Relocations.size(); ++J) {
      if (overlaps(Relocations[I], Relocations[J],
                   [](const auto &Value) { return Value.PatchSize; })) {
        return fail<void>(Diagnostic{"overlapping relocation patches"});
      }
    }
  }
  for (const auto &Value : Rebases) {
    if (Value.Section >= Sections.size()) {
      Diagnostic Diag{"invalid section ID"};
      Diag.Section = Value.Section;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    if (extendsBeyond(Value.Offset, std::max<uint8_t>(Value.Width, 1),
                      Sections[Value.Section].Content.size())) {
      Diagnostic Diag{"rebase offset is outside section content"};
      Diag.Section = Value.Section;
      Diag.RelocationType = Value.Type;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
  }
  for (size_t I = 0; I < Rebases.size(); ++I) {
    for (size_t J = I + 1; J < Rebases.size(); ++J) {
      if (overlaps(Rebases[I], Rebases[J], [](const auto &Value) {
            return std::max<uint8_t>(Value.Width, 1);
          })) {
        return fail<void>(Diagnostic{"overlapping rebase patches"});
      }
    }
  }
  return {};
}

LinkExpect<void> LinkGraph::setSectionAddress(SectionId Id, uint64_t Address) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (Id >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Id;
    return fail<void>(std::move(Diag));
  }
  Sections[Id].Address = Address;
  return {};
}

LinkExpect<void> LinkGraph::setSectionFileOffset(SectionId Id,
                                                 uint64_t FileOffset) {
  if (RelocationsApplied) {
    return relocated();
  }
  if (Id >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Id;
    return fail<void>(std::move(Diag));
  }
  Sections[Id].FileOffset = FileOffset;
  return {};
}

LinkExpect<Span<Byte>> LinkGraph::sectionContent(SectionId Id) {
  if (RelocationsApplied) {
    return fail<Span<Byte>>(
        Diagnostic{"link graph relocations already applied"});
  }
  if (Id >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Id;
    return fail<Span<Byte>>(std::move(Diag));
  }
  return Span<Byte>(Sections[Id].Content.data(), Sections[Id].Content.size());
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
