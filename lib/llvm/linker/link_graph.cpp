// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/link_graph.h"

#include <algorithm>
#include <limits>
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

} // namespace

LinkExpect<void> LinkGraph::beginInput(std::string_view Name) {
  if (InputName) {
    return fail<void>(
        Diagnostic{"link graph accepts exactly one input object"});
  }
  InputName = std::string(Name);
  return {};
}

LinkExpect<SectionId> LinkGraph::addSection(Section Value) {
  if (Value.Alignment == 0 || (Value.Alignment & (Value.Alignment - 1)) != 0) {
    Diagnostic Diag{"section alignment must be a non-zero power of two"};
    Diag.SectionName = Value.Name;
    return fail<SectionId>(std::move(Diag));
  }
  if (Sections.size() > std::numeric_limits<uint32_t>::max()) {
    return fail<SectionId>(Diagnostic{"too many sections"});
  }
  const SectionId Id{static_cast<uint32_t>(Sections.size())};
  Sections.push_back(std::move(Value));
  return Id;
}

LinkExpect<SymbolId> LinkGraph::addSymbol(Symbol Value) {
  if (Value.Section && Value.Section->Value >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Value.Section;
    Diag.SymbolName = Value.Name;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  if (Value.Section &&
      extendsBeyond(Value.Offset, Value.Size,
                    Sections[Value.Section->Value].VirtualSize)) {
    Diagnostic Diag{"symbol extends beyond section virtual size"};
    Diag.Section = Value.Section;
    Diag.SymbolName = Value.Name;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  const auto Duplicate =
      std::find_if(Symbols.begin(), Symbols.end(), [&](const auto &Defined) {
        return Defined.Section && Value.Section && Defined.Name == Value.Name;
      });
  if (Duplicate != Symbols.end()) {
    Diagnostic Diag{"duplicate symbol definition"};
    Diag.SymbolName = Value.Name;
    Diag.Section = Value.Section;
    Diag.Offset = Value.Offset;
    return fail<SymbolId>(std::move(Diag));
  }
  if (Symbols.size() > std::numeric_limits<uint32_t>::max()) {
    return fail<SymbolId>(Diagnostic{"too many symbols"});
  }
  const SymbolId Id{static_cast<uint32_t>(Symbols.size())};
  Symbols.push_back(std::move(Value));
  return Id;
}

LinkExpect<void> LinkGraph::addRelocation(Relocation Value) {
  if (Value.Section.Value >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
    Diag.Section = Value.Section;
    Diag.RelocationType = Value.Type;
    Diag.Offset = Value.Offset;
    return fail<void>(std::move(Diag));
  }
  if (Value.Symbol.Value >= Symbols.size()) {
    Diagnostic Diag{"invalid symbol ID"};
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
  if (Value.Section.Value >= Sections.size()) {
    Diagnostic Diag{"invalid section ID"};
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
  for (uint32_t I = 0; I < Symbols.size(); ++I) {
    const auto &Value = Symbols[I];
    if (!Value.Section) {
      Diagnostic Diag{"undefined symbol"};
      Diag.Symbol = SymbolId{I};
      Diag.SymbolName = Value.Name;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    if (Value.Section->Value >= Sections.size()) {
      Diagnostic Diag{"invalid section ID"};
      Diag.Section = Value.Section;
      Diag.Symbol = SymbolId{I};
      Diag.SymbolName = Value.Name;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
    if (extendsBeyond(Value.Offset, Value.Size,
                      Sections[Value.Section->Value].VirtualSize)) {
      Diagnostic Diag{"symbol extends beyond section virtual size"};
      Diag.Section = Value.Section;
      Diag.Symbol = SymbolId{I};
      Diag.SymbolName = Value.Name;
      Diag.Offset = Value.Offset;
      return fail<void>(std::move(Diag));
    }
  }
  return {};
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
