// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/object_reader.h"

#include "common/spdlog.h"

#include <llvm/BinaryFormat/COFF.h>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/MachO.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/SymbolSize.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBufferRef.h>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace std::literals;

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

template <typename T> Expect<T> fail(std::string_view Message) {
  spdlog::error("object reader: {}"sv, Message);
  return Unexpect(ErrCode::Value::IllegalPath);
}

template <typename T>
bool take(llvm::Expected<T> Value, T &Output, std::string_view Context) {
  if (!Value) {
    spdlog::error("object reader: {}: {}"sv, Context,
                  llvm::toString(Value.takeError()));
    return false;
  }
  Output = std::move(*Value);
  return true;
}

std::optional<Target> normalizeTarget(llvm::Triple::ArchType Arch) noexcept {
  switch (Arch) {
  case llvm::Triple::x86_64:
    return Target::X86_64;
  case llvm::Triple::arm:
  case llvm::Triple::armeb:
  case llvm::Triple::thumb:
  case llvm::Triple::thumbeb:
    return Target::ARM;
  case llvm::Triple::aarch64:
  case llvm::Triple::aarch64_be:
    return Target::AArch64;
  case llvm::Triple::riscv64:
    return Target::RISCV64;
  case llvm::Triple::systemz:
    return Target::S390X;
  default:
    return std::nullopt;
  }
}

bool isSupportedFormat(const llvm::object::ObjectFile &Object) noexcept {
  return Object.isELF() || Object.isCOFF() || Object.isMachO();
}

uint64_t sectionAlignment(const llvm::object::SectionRef &Section) noexcept {
#if LLVM_VERSION_MAJOR >= 11
  return Section.getAlignment().value();
#else
  return std::max<uint64_t>(Section.getAlignment(), 1);
#endif
}

bool isAllocatable(const llvm::object::ObjectFile &Object,
                   const llvm::object::SectionRef &Section) noexcept {
  if (const auto *ELF =
          llvm::dyn_cast<llvm::object::ELFObjectFileBase>(&Object)) {
    (void)ELF;
    return (llvm::object::ELFSectionRef(Section).getFlags() &
            llvm::ELF::SHF_ALLOC) != 0;
  }
  if (const auto *COFF =
          llvm::dyn_cast<llvm::object::COFFObjectFile>(&Object)) {
    const auto Flags = COFF->getCOFFSection(Section)->Characteristics;
    return (Flags & (llvm::COFF::IMAGE_SCN_MEM_EXECUTE |
                     llvm::COFF::IMAGE_SCN_MEM_READ |
                     llvm::COFF::IMAGE_SCN_MEM_WRITE)) != 0 &&
           (Flags & llvm::COFF::IMAGE_SCN_MEM_DISCARDABLE) == 0;
  }
  return Section.isBerkeleyText() || Section.isBerkeleyData() ||
         Section.isBSS();
}

SectionKind sectionKind(const llvm::object::SectionRef &Section,
                        llvm::StringRef Name) noexcept {
  if (Section.isText()) {
    return SectionKind::Text;
  }
  if (Section.isBSS() || Section.isVirtual()) {
    return SectionKind::BSS;
  }
  if (Name.contains("eh_frame") || Name.contains("unwind") ||
#if LLVM_VERSION_MAJOR >= 19
      Name.starts_with(".pdata") || Name.starts_with(".xdata")) {
#else
      Name.startswith(".pdata") || Name.startswith(".xdata")) {
#endif
    return SectionKind::Unwind;
  }
  if (Section.isBerkeleyText()) {
    return SectionKind::ReadOnly;
  }
  if (Section.isData() || Section.isBerkeleyData()) {
    return SectionKind::Data;
  }
  return SectionKind::ReadOnly;
}

std::pair<int64_t, bool>
relocationAddend(const llvm::object::ObjectFile &Object,
                 const llvm::object::RelocationRef &Relocation) noexcept {
  if (!llvm::isa<llvm::object::ELFObjectFileBase>(Object)) {
    return {0, true};
  }
  auto Addend = llvm::object::ELFRelocationRef(Relocation).getAddend();
  if (!Addend) {
    llvm::consumeError(Addend.takeError());
    return {0, true};
  }
  return {*Addend, false};
}

bool parseCOFFExports(llvm::StringRef Directives,
                      std::set<std::string> &Exports) {
  while (!Directives.trim().empty()) {
    Directives = Directives.ltrim();
    llvm::StringRef Token;
    if (Directives.front() == '"') {
      const auto End = Directives.drop_front().find('"');
      if (End == llvm::StringRef::npos) {
        return false;
      }
      Token = Directives.substr(1, End);
      Directives = Directives.drop_front(End + 2);
    } else {
      std::tie(Token, Directives) = Directives.split(' ');
    }
    if (Token.size() < 8 ||
#if LLVM_VERSION_MAJOR >= 19
        !Token.take_front(8).equals_insensitive("/export:")) {
#else
        !Token.take_front(8).equals_lower("/export:")) {
#endif
      continue;
    }
    Token = Token.drop_front(8);
    Token = Token.split(',').first;
    Token = Token.split('=').first;
    if (Token.empty()) {
      return false;
    }
    Exports.emplace(Token.str());
  }
  return true;
}

} // namespace

Expect<LinkGraph> ObjectReader::read(Span<const Byte> Buffer,
                                     Target ExpectedTarget) noexcept {
  if (Buffer.empty()) {
    return fail<LinkGraph>("empty object buffer");
  }
  const auto Data = llvm::StringRef(
      reinterpret_cast<const char *>(Buffer.data()), Buffer.size());
  auto ObjectResult = llvm::object::ObjectFile::createObjectFile(
      llvm::MemoryBufferRef(Data, "object"));
  if (!ObjectResult) {
    spdlog::error("object file parse error: {}"sv,
                  llvm::toString(ObjectResult.takeError()));
    return Unexpect(ErrCode::Value::IllegalPath);
  }
  const auto &Object = **ObjectResult;
  if (!Object.isRelocatableObject()) {
    return fail<LinkGraph>("input is not a relocatable object");
  }
  if (!isSupportedFormat(Object)) {
    return fail<LinkGraph>("unsupported object format");
  }
  const auto ActualTarget = normalizeTarget(Object.getArch());
  if (!ActualTarget) {
    return fail<LinkGraph>("unsupported object architecture");
  }
  if (*ActualTarget != ExpectedTarget) {
    return fail<LinkGraph>("object target does not match expected host target");
  }

  LinkGraph Graph(*ActualTarget, Object.isLittleEndian() ? Endianness::Little
                                                         : Endianness::Big);
  if (!Graph.beginInput("object")) {
    return fail<LinkGraph>("cannot initialize link graph input");
  }
  std::map<uint64_t, SectionId> SectionIds;
  std::set<std::string> COFFExports;
  for (const auto &InputSection : Object.sections()) {
    llvm::StringRef Name;
    if (!take(InputSection.getName(), Name, "cannot read section name")) {
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    if (Object.isCOFF() && Name == ".drectve") {
      llvm::StringRef Contents;
      if (!take(InputSection.getContents(), Contents, "cannot read .drectve") ||
          !parseCOFFExports(Contents, COFFExports)) {
        return fail<LinkGraph>("malformed COFF .drectve export directive");
      }
    }
    if (!isAllocatable(Object, InputSection)) {
      continue;
    }
    llvm::StringRef Contents;
    if (!InputSection.isVirtual() && !take(InputSection.getContents(), Contents,
                                           "cannot read section contents")) {
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    std::vector<Byte> Bytes(Contents.bytes_begin(), Contents.bytes_end());
    auto Added = Graph.addSection(
        Section{Name.str(), sectionKind(InputSection, Name),
                sectionAlignment(InputSection), InputSection.getSize(), 0, 0,
                std::move(Bytes)});
    if (!Added) {
      return fail<LinkGraph>(Added.error().Message);
    }
    SectionIds.emplace(InputSection.getIndex(), *Added);
  }

  std::map<llvm::object::DataRefImpl, SymbolId> SymbolIds;
  std::map<llvm::object::DataRefImpl, uint64_t> SymbolSizes;
  for (const auto &[InputSymbol, Size] :
       llvm::object::computeSymbolSizes(Object)) {
    SymbolSizes.emplace(InputSymbol.getRawDataRefImpl(), Size);
  }
  for (const auto &InputSymbol : Object.symbols()) {
    llvm::StringRef Name;
    uint32_t Flags = 0;
    llvm::object::SymbolRef::Type Type{};
    if (!take(InputSymbol.getName(), Name, "cannot read symbol name") ||
        !take(InputSymbol.getFlags(), Flags, "cannot read symbol flags") ||
        !take(InputSymbol.getType(), Type, "cannot read symbol type")) {
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    if ((Flags & llvm::object::SymbolRef::SF_Undefined) != 0) {
      if (!Name.empty() && Type != llvm::object::SymbolRef::ST_File &&
          Type != llvm::object::SymbolRef::ST_Debug) {
        spdlog::error("object reader: undefined symbol '{}'"sv, Name);
        return Unexpect(ErrCode::Value::IllegalPath);
      }
      continue;
    }
    auto InputSection = InputSymbol.getSection();
    if (!InputSection) {
      spdlog::error("object reader: cannot read section for symbol '{}': {}"sv,
                    Name, llvm::toString(InputSection.takeError()));
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    if (*InputSection == Object.section_end()) {
      continue;
    }
    const auto Section = SectionIds.find((*InputSection)->getIndex());
    if (Section == SectionIds.end()) {
      continue;
    }
    if (Name.empty()) {
      Name = "$section";
    }
    uint64_t Address = 0;
    if (!take(InputSymbol.getAddress(), Address,
              "cannot read symbol address")) {
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    const uint64_t Base = (*InputSection)->getAddress();
    if (Address < Base) {
      return fail<LinkGraph>("symbol address precedes its section");
    }
    bool Exported = (Flags & llvm::object::SymbolRef::SF_Exported) != 0;
    if (Object.isMachO()) {
      Exported = (Flags & llvm::object::SymbolRef::SF_Global) != 0;
    } else if (Object.isCOFF()) {
      Exported = COFFExports.count(Name.str()) != 0;
    }
    std::string SymbolName = Name.str();
    if (SymbolName == "$section") {
      SymbolName += std::to_string((*InputSection)->getIndex());
    }
    auto Added = Graph.addSymbol(
        Symbol{std::move(SymbolName), Section->second, Address - Base,
               SymbolSizes[InputSymbol.getRawDataRefImpl()], Exported});
    if (!Added) {
      return fail<LinkGraph>(Added.error().Message);
    }
    SymbolIds.emplace(InputSymbol.getRawDataRefImpl(), *Added);
  }

  for (const auto &InputSection : Object.sections()) {
    auto RelocatedSection = InputSection.getRelocatedSection();
    if (!RelocatedSection) {
      spdlog::error("object reader: cannot read relocated section: {}"sv,
                    llvm::toString(RelocatedSection.takeError()));
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    const uint64_t SectionIndex = *RelocatedSection == Object.section_end()
                                      ? InputSection.getIndex()
                                      : (*RelocatedSection)->getIndex();
    const auto Section = SectionIds.find(SectionIndex);
    if (Section == SectionIds.end()) {
      continue;
    }
    for (const auto &InputRelocation : InputSection.relocations()) {
      const auto InputSymbol = InputRelocation.getSymbol();
      if (InputSymbol == Object.symbol_end()) {
        return fail<LinkGraph>("relocation has no target symbol");
      }
      const auto Symbol = SymbolIds.find(InputSymbol->getRawDataRefImpl());
      if (Symbol == SymbolIds.end()) {
        return fail<LinkGraph>("relocation targets an unsupported symbol");
      }
      const auto [Addend, Implicit] = relocationAddend(Object, InputRelocation);
      auto Added = Graph.addRelocation(
          Relocation{Section->second, InputRelocation.getOffset(),
                     static_cast<uint32_t>(InputRelocation.getType()),
                     Symbol->second, Addend, Implicit});
      if (!Added) {
        return fail<LinkGraph>(Added.error().Message);
      }
    }
  }
  if (auto Valid = Graph.validate(); !Valid) {
    return fail<LinkGraph>(Valid.error().Message);
  }
  return Graph;
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
