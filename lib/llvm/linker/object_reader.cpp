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
#if LLVM_VERSION_MAJOR >= 16
  return Internal::normalizeSectionAlignment(Section.getAlignment().value());
#else
  return Internal::normalizeSectionAlignment(Section.getAlignment());
#endif
}

bool symbolFlags(const llvm::object::SymbolRef &Symbol, uint32_t &Flags) {
#if LLVM_VERSION_MAJOR >= 11
  return take(Symbol.getFlags(), Flags, "cannot read symbol flags");
#else
  Flags = Symbol.getFlags();
  return true;
#endif
}

template <typename T>
bool readELFInteger(Span<const Byte> Buffer, uint64_t Offset, bool LittleEndian,
                    T &Value) noexcept {
  if (Offset > Buffer.size() || sizeof(T) > Buffer.size() - Offset) {
    return false;
  }
  Value = 0;
  for (size_t I = 0; I < sizeof(T); ++I) {
    const size_t Shift = LittleEndian ? I * 8 : (sizeof(T) - I - 1) * 8;
    Value |= static_cast<T>(Buffer[Offset + I]) << Shift;
  }
  return true;
}

bool validELFRelocations(Span<const Byte> Buffer) noexcept {
  if (Buffer.size() < 16 || Buffer[0] != 0x7F || Buffer[1] != 'E' ||
      Buffer[2] != 'L' || Buffer[3] != 'F') {
    return true;
  }
  const bool Is64 = Buffer[4] == llvm::ELF::ELFCLASS64;
  const bool Is32 = Buffer[4] == llvm::ELF::ELFCLASS32;
  const bool LittleEndian = Buffer[5] == llvm::ELF::ELFDATA2LSB;
  if ((!Is32 && !Is64) ||
      (!LittleEndian && Buffer[5] != llvm::ELF::ELFDATA2MSB)) {
    return false;
  }
  uint64_t SectionOffset = 0;
  uint16_t SectionEntrySize = 0;
  uint16_t SectionCount16 = 0;
  if (Is64) {
    if (!readELFInteger(Buffer, 40, LittleEndian, SectionOffset) ||
        !readELFInteger(Buffer, 58, LittleEndian, SectionEntrySize) ||
        !readELFInteger(Buffer, 60, LittleEndian, SectionCount16)) {
      return false;
    }
  } else {
    uint32_t Offset32 = 0;
    if (!readELFInteger(Buffer, 32, LittleEndian, Offset32) ||
        !readELFInteger(Buffer, 46, LittleEndian, SectionEntrySize) ||
        !readELFInteger(Buffer, 48, LittleEndian, SectionCount16)) {
      return false;
    }
    SectionOffset = Offset32;
  }
  uint64_t SectionCount = SectionCount16;
  const uint64_t RequiredSectionSize = Is64 ? 64 : 40;
  if (SectionEntrySize < RequiredSectionSize || SectionOffset > Buffer.size() ||
      SectionEntrySize > Buffer.size() - SectionOffset) {
    return false;
  }
  if (SectionCount == 0) {
    if (Is64) {
      if (!readELFInteger(Buffer, SectionOffset + 32, LittleEndian,
                          SectionCount)) {
        return false;
      }
    } else {
      uint32_t ExtendedCount = 0;
      if (!readELFInteger(Buffer, SectionOffset + 20, LittleEndian,
                          ExtendedCount)) {
        return false;
      }
      SectionCount = ExtendedCount;
    }
  }
  if (SectionCount == 0 ||
      static_cast<uint64_t>(SectionCount) >
          (Buffer.size() - SectionOffset) / SectionEntrySize) {
    return false;
  }
  auto readSection = [&](uint64_t Index, uint32_t &Type, uint64_t &Offset,
                         uint64_t &Size, uint32_t &Link,
                         uint64_t &EntrySize) noexcept {
    if (Index >= SectionCount) {
      return false;
    }
    const uint64_t Base = SectionOffset + Index * SectionEntrySize;
    if (!readELFInteger(Buffer, Base + 4, LittleEndian, Type) ||
        !readELFInteger(Buffer, Base + (Is64 ? 40 : 24), LittleEndian, Link)) {
      return false;
    }
    if (Is64) {
      return readELFInteger(Buffer, Base + 24, LittleEndian, Offset) &&
             readELFInteger(Buffer, Base + 32, LittleEndian, Size) &&
             readELFInteger(Buffer, Base + 56, LittleEndian, EntrySize);
    }
    uint32_t Offset32 = 0;
    uint32_t Size32 = 0;
    uint32_t EntrySize32 = 0;
    if (!readELFInteger(Buffer, Base + 16, LittleEndian, Offset32) ||
        !readELFInteger(Buffer, Base + 20, LittleEndian, Size32) ||
        !readELFInteger(Buffer, Base + 36, LittleEndian, EntrySize32)) {
      return false;
    }
    Offset = Offset32;
    Size = Size32;
    EntrySize = EntrySize32;
    return true;
  };
  for (uint64_t I = 0; I < SectionCount; ++I) {
    uint32_t Type = 0;
    uint32_t Link = 0;
    uint64_t Offset = 0;
    uint64_t Size = 0;
    uint64_t EntrySize = 0;
    if (!readSection(I, Type, Offset, Size, Link, EntrySize)) {
      return false;
    }
    const bool IsCrel =
#if LLVM_VERSION_MAJOR >= 19
        Type == llvm::ELF::SHT_CREL;
#else
        false;
#endif
    if (Type != llvm::ELF::SHT_REL && Type != llvm::ELF::SHT_RELA && !IsCrel) {
      continue;
    }
    const uint64_t ExpectedEntrySize =
        IsCrel ? 1
        : Is64 ? (Type == llvm::ELF::SHT_RELA ? 24 : 16)
               : (Type == llvm::ELF::SHT_RELA ? 12 : 8);
    uint32_t SymbolType = 0;
    uint32_t SymbolLink = 0;
    uint64_t SymbolOffset = 0;
    uint64_t SymbolSize = 0;
    uint64_t SymbolEntrySize = 0;
    if (EntrySize != ExpectedEntrySize || Size % EntrySize != 0 ||
        Offset > Buffer.size() || Size > Buffer.size() - Offset ||
        !readSection(Link, SymbolType, SymbolOffset, SymbolSize, SymbolLink,
                     SymbolEntrySize) ||
        (SymbolType != llvm::ELF::SHT_SYMTAB &&
         SymbolType != llvm::ELF::SHT_DYNSYM) ||
        SymbolEntrySize != (Is64 ? 24U : 16U) ||
        SymbolSize % SymbolEntrySize != 0 || SymbolOffset > Buffer.size() ||
        SymbolSize > Buffer.size() - SymbolOffset) {
      return false;
    }
    const uint64_t SymbolCount = SymbolSize / SymbolEntrySize;
    if (IsCrel) {
#if LLVM_VERSION_MAJOR >= 19
      uint64_t DeclaredCount = 0;
      uint64_t DecodedCount = 0;
      bool ValidSymbols = true;
      const auto Content =
          llvm::ArrayRef<uint8_t>(Buffer.data() + Offset, Size);
      auto Error =
          Is64 ? llvm::object::decodeCrel<true>(
                     Content,
                     [&](uint64_t Count, bool) { DeclaredCount = Count; },
                     [&](const auto &Relocation) {
                       ++DecodedCount;
                       ValidSymbols &= Relocation.r_symidx < SymbolCount;
                     })
               : llvm::object::decodeCrel<false>(
                     Content,
                     [&](uint64_t Count, bool) { DeclaredCount = Count; },
                     [&](const auto &Relocation) {
                       ++DecodedCount;
                       ValidSymbols &= Relocation.r_symidx < SymbolCount;
                     });
      if (Error) {
        llvm::consumeError(std::move(Error));
        return false;
      }
      if (!ValidSymbols || DecodedCount != DeclaredCount) {
        return false;
      }
#endif
      continue;
    }
    for (uint64_t J = 0; J < Size / EntrySize; ++J) {
      const uint64_t InfoOffset = Offset + J * EntrySize + (Is64 ? 8 : 4);
      uint64_t Info = 0;
      if (Is64) {
        if (!readELFInteger(Buffer, InfoOffset, LittleEndian, Info) ||
            (Info >> 32) >= SymbolCount) {
          return false;
        }
      } else {
        uint32_t Info32 = 0;
        if (!readELFInteger(Buffer, InfoOffset, LittleEndian, Info32) ||
            (Info32 >> 8) >= SymbolCount) {
          return false;
        }
      }
    }
  }
  return true;
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

} // namespace

namespace Internal {

uint64_t normalizeSectionAlignment(uint64_t Alignment) noexcept {
  return std::max<uint64_t>(Alignment, 1);
}

std::optional<std::map<std::string, std::string>>
parseCOFFExports(std::string_view Input) {
  llvm::StringRef Directives(Input.data(), Input.size());
  std::map<std::string, std::string> Exports;
  while (!Directives.trim().empty()) {
    Directives = Directives.ltrim();
    llvm::StringRef Token;
    if (Directives.front() == '"') {
      const auto End = Directives.drop_front().find('"');
      if (End == llvm::StringRef::npos) {
        return std::nullopt;
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
    const auto [ExportName, SymbolName] = Token.split('=');
    if (ExportName.empty()) {
      return std::nullopt;
    }
    Exports.emplace(ExportName.str(),
                    SymbolName.empty() ? ExportName.str() : SymbolName.str());
  }
  return Exports;
}

} // namespace Internal

Expect<LinkGraph> ObjectReader::read(Span<const Byte> Buffer,
                                     Target ExpectedTarget) noexcept {
  if (Buffer.empty()) {
    return fail<LinkGraph>("empty object buffer");
  }
  if (!validELFRelocations(Buffer)) {
    return fail<LinkGraph>("malformed ELF relocation metadata");
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
  std::map<std::string, std::string> COFFExports;
  for (const auto &InputSection : Object.sections()) {
    llvm::StringRef Name;
    if (!take(InputSection.getName(), Name, "cannot read section name")) {
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    if (Object.isCOFF() && Name == ".drectve") {
      llvm::StringRef Contents;
      if (!take(InputSection.getContents(), Contents, "cannot read .drectve")) {
        return Unexpect(ErrCode::Value::IllegalPath);
      }
      auto Exports = Internal::parseCOFFExports(Contents.str());
      if (!Exports) {
        return fail<LinkGraph>("malformed COFF .drectve export directive");
      }
      COFFExports.insert(Exports->begin(), Exports->end());
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
        !symbolFlags(InputSymbol, Flags) ||
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
    std::optional<std::string> ExportName;
    if (Object.isMachO()) {
      Exported = (Flags & llvm::object::SymbolRef::SF_Global) != 0 &&
                 (Flags & llvm::object::SymbolRef::SF_Hidden) == 0;
    } else if (Object.isCOFF()) {
      const auto Export =
          std::find_if(COFFExports.begin(), COFFExports.end(),
                       [&](const auto &Entry) { return Entry.second == Name; });
      Exported = Export != COFFExports.end();
      if (Exported && Export->first != Name) {
        ExportName = Export->first;
      }
    }
    std::string SymbolName = Name.str();
    if (SymbolName == "$section") {
      SymbolName += std::to_string((*InputSection)->getIndex());
    }
    auto Added = Graph.addSymbol(Symbol{
        std::move(SymbolName), Section->second, Address - Base,
        SymbolSizes[InputSymbol.getRawDataRefImpl()], Exported, ExportName});
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
