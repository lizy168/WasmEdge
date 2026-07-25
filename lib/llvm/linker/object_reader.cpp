// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/object_reader.h"

#include "common/spdlog.h"

#include <llvm/BinaryFormat/COFF.h>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/BinaryFormat/MachO.h>
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

constexpr uint8_t BytePatch = 1;

enum class ELFIdentification : uint64_t {
  Size = llvm::ELF::EI_NIDENT,
  Magic0 = llvm::ELF::EI_MAG0,
  Magic1 = llvm::ELF::EI_MAG1,
  Magic2 = llvm::ELF::EI_MAG2,
  Magic3 = llvm::ELF::EI_MAG3,
  Class = llvm::ELF::EI_CLASS,
  Data = llvm::ELF::EI_DATA,
};

enum class ELF32Offset : uint64_t {
  SectionTable = 32,
  SectionEntrySize = 46,
  SectionCount = 48,
  SectionType = 4,
  SectionOffset = 16,
  SectionSize = 20,
  SectionLink = 24,
  SectionEntry = 36,
  RelocationInfo = 4,
};

enum class ELF64Offset : uint64_t {
  SectionTable = 40,
  SectionEntrySize = 58,
  SectionCount = 60,
  SectionType = 4,
  SectionOffset = 24,
  SectionSize = 32,
  SectionLink = 40,
  SectionEntry = 56,
  RelocationInfo = 8,
};

constexpr uint64_t value(ELFIdentification Value) noexcept {
  return static_cast<uint64_t>(Value);
}

constexpr uint64_t value(ELF32Offset Value) noexcept {
  return static_cast<uint64_t>(Value);
}

constexpr uint64_t value(ELF64Offset Value) noexcept {
  return static_cast<uint64_t>(Value);
}

static_assert(value(ELF32Offset::SectionTable) == 32);
static_assert(value(ELF32Offset::SectionEntrySize) == 46);
static_assert(value(ELF64Offset::SectionTable) == 40);
static_assert(value(ELF64Offset::SectionEntrySize) == 58);

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
  constexpr uint8_t BitsPerByte = 8;
  if (Offset > Buffer.size() || sizeof(T) > Buffer.size() - Offset) {
    return false;
  }
  Value = 0;
  for (size_t I = 0; I < sizeof(T); ++I) {
    const size_t Shift =
        LittleEndian ? I * BitsPerByte : (sizeof(T) - I - 1) * BitsPerByte;
    Value |= static_cast<T>(Buffer[Offset + I]) << Shift;
  }
  return true;
}

bool validELFRelocations(Span<const Byte> Buffer) noexcept {
  constexpr uint64_t MinimumCrelEntrySize = 1;
  constexpr uint64_t ELF32SectionEntrySize = 40;
  constexpr uint64_t ELF64SectionEntrySize = 64;
  constexpr uint64_t ELF32RelEntrySize = 8;
  constexpr uint64_t ELF32RelaEntrySize = 12;
  constexpr uint64_t ELF64RelEntrySize = 16;
  constexpr uint64_t ELF64RelaEntrySize = 24;
  constexpr uint64_t ELF32SymbolEntrySize = 16;
  constexpr uint64_t ELF64SymbolEntrySize = 24;
  constexpr unsigned ELF32SymbolIndexShift = 8;
  constexpr unsigned ELF64SymbolIndexShift = 32;
  if (Buffer.size() < value(ELFIdentification::Size) ||
      Buffer[value(ELFIdentification::Magic0)] != llvm::ELF::ElfMagic[0] ||
      Buffer[value(ELFIdentification::Magic1)] != llvm::ELF::ElfMagic[1] ||
      Buffer[value(ELFIdentification::Magic2)] != llvm::ELF::ElfMagic[2] ||
      Buffer[value(ELFIdentification::Magic3)] != llvm::ELF::ElfMagic[3]) {
    return true;
  }
  const bool Is64 =
      Buffer[value(ELFIdentification::Class)] == llvm::ELF::ELFCLASS64;
  const bool Is32 =
      Buffer[value(ELFIdentification::Class)] == llvm::ELF::ELFCLASS32;
  const bool LittleEndian =
      Buffer[value(ELFIdentification::Data)] == llvm::ELF::ELFDATA2LSB;
  if ((!Is32 && !Is64) ||
      (!LittleEndian &&
       Buffer[value(ELFIdentification::Data)] != llvm::ELF::ELFDATA2MSB)) {
    return false;
  }
  uint64_t SectionOffset = 0;
  uint16_t SectionEntrySize = 0;
  uint16_t SectionCount16 = 0;
  if (Is64) {
    if (!readELFInteger(Buffer, value(ELF64Offset::SectionTable), LittleEndian,
                        SectionOffset) ||
        !readELFInteger(Buffer, value(ELF64Offset::SectionEntrySize),
                        LittleEndian, SectionEntrySize) ||
        !readELFInteger(Buffer, value(ELF64Offset::SectionCount), LittleEndian,
                        SectionCount16)) {
      return false;
    }
  } else {
    uint32_t Offset32 = 0;
    if (!readELFInteger(Buffer, value(ELF32Offset::SectionTable), LittleEndian,
                        Offset32) ||
        !readELFInteger(Buffer, value(ELF32Offset::SectionEntrySize),
                        LittleEndian, SectionEntrySize) ||
        !readELFInteger(Buffer, value(ELF32Offset::SectionCount), LittleEndian,
                        SectionCount16)) {
      return false;
    }
    SectionOffset = Offset32;
  }
  uint64_t SectionCount = SectionCount16;
  const uint64_t RequiredSectionSize =
      Is64 ? ELF64SectionEntrySize : ELF32SectionEntrySize;
  if (SectionEntrySize < RequiredSectionSize || SectionOffset > Buffer.size() ||
      SectionEntrySize > Buffer.size() - SectionOffset) {
    return false;
  }
  if (SectionCount == 0) {
    if (Is64) {
      if (!readELFInteger(Buffer,
                          SectionOffset + value(ELF64Offset::SectionSize),
                          LittleEndian, SectionCount)) {
        return false;
      }
    } else {
      uint32_t ExtendedCount = 0;
      if (!readELFInteger(Buffer,
                          SectionOffset + value(ELF32Offset::SectionSize),
                          LittleEndian, ExtendedCount)) {
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
    if (!readELFInteger(Buffer,
                        Base + (Is64 ? value(ELF64Offset::SectionType)
                                     : value(ELF32Offset::SectionType)),
                        LittleEndian, Type) ||
        !readELFInteger(Buffer,
                        Base + (Is64 ? value(ELF64Offset::SectionLink)
                                     : value(ELF32Offset::SectionLink)),
                        LittleEndian, Link)) {
      return false;
    }
    if (Is64) {
      return readELFInteger(Buffer, Base + value(ELF64Offset::SectionOffset),
                            LittleEndian, Offset) &&
             readELFInteger(Buffer, Base + value(ELF64Offset::SectionSize),
                            LittleEndian, Size) &&
             readELFInteger(Buffer, Base + value(ELF64Offset::SectionEntry),
                            LittleEndian, EntrySize);
    }
    uint32_t Offset32 = 0;
    uint32_t Size32 = 0;
    uint32_t EntrySize32 = 0;
    if (!readELFInteger(Buffer, Base + value(ELF32Offset::SectionOffset),
                        LittleEndian, Offset32) ||
        !readELFInteger(Buffer, Base + value(ELF32Offset::SectionSize),
                        LittleEndian, Size32) ||
        !readELFInteger(Buffer, Base + value(ELF32Offset::SectionEntry),
                        LittleEndian, EntrySize32)) {
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
        IsCrel ? MinimumCrelEntrySize
        : Is64 ? (Type == llvm::ELF::SHT_RELA ? ELF64RelaEntrySize
                                              : ELF64RelEntrySize)
               : (Type == llvm::ELF::SHT_RELA ? ELF32RelaEntrySize
                                              : ELF32RelEntrySize);
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
        SymbolEntrySize !=
            (Is64 ? ELF64SymbolEntrySize : ELF32SymbolEntrySize) ||
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
      const uint64_t InfoOffset = Offset + J * EntrySize +
                                  (Is64 ? value(ELF64Offset::RelocationInfo)
                                        : value(ELF32Offset::RelocationInfo));
      uint64_t Info = 0;
      if (Is64) {
        if (!readELFInteger(Buffer, InfoOffset, LittleEndian, Info) ||
            (Info >> ELF64SymbolIndexShift) >= SymbolCount) {
          return false;
        }
      } else {
        uint32_t Info32 = 0;
        if (!readELFInteger(Buffer, InfoOffset, LittleEndian, Info32) ||
            (Info32 >> ELF32SymbolIndexShift) >= SymbolCount) {
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

SectionPurpose sectionPurpose(const llvm::object::ObjectFile &Object,
                              llvm::StringRef Name) noexcept {
  if (Name == ".ARM.exidx" || Name.starts_with(".ARM.exidx."))
    return SectionPurpose::ARMExidx;
  if (Name.contains("eh_frame"))
    return SectionPurpose::EHFrame;
#if LLVM_VERSION_MAJOR >= 19
  if (Name.starts_with(".pdata"))
    return SectionPurpose::PData;
  if (Name.starts_with(".xdata"))
    return SectionPurpose::XData;
#else
  if (Name.startswith(".pdata"))
    return SectionPurpose::PData;
  if (Name.startswith(".xdata"))
    return SectionPurpose::XData;
#endif
  if (Object.isMachO() && Name.contains("compact_unwind"))
    return SectionPurpose::CompactUnwind;
  return SectionPurpose::Default;
}

SectionKind sectionKind(const llvm::object::SectionRef &Section,
                        SectionPurpose Purpose) noexcept {
  if (Section.isText()) {
    return SectionKind::Text;
  }
  if (Section.isBSS() || Section.isVirtual()) {
    return SectionKind::BSS;
  }
  if (Purpose == SectionPurpose::EHFrame ||
      Purpose == SectionPurpose::ARMExidx || Purpose == SectionPurpose::PData) {
    return SectionKind::Unwind;
  }
  if (Purpose == SectionPurpose::XData ||
      Purpose == SectionPurpose::CompactUnwind)
    return SectionKind::ReadOnly;
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

ObjectFormat objectFormat(const llvm::object::ObjectFile &Object) noexcept {
  if (Object.isMachO()) {
    return ObjectFormat::MachO;
  }
  if (Object.isCOFF()) {
    return ObjectFormat::COFF;
  }
  return ObjectFormat::ELF;
}

std::optional<uint32_t>
elfLinkedSection(const llvm::object::ObjectFile &Object,
                 const llvm::object::SectionRef &Section) noexcept {
  const auto Reference = Section.getRawDataRefImpl();
  if (const auto *ELF =
          llvm::dyn_cast<llvm::object::ELF32LEObjectFile>(&Object))
    return ELF->getSection(Reference)->sh_link;
  if (const auto *ELF =
          llvm::dyn_cast<llvm::object::ELF32BEObjectFile>(&Object))
    return ELF->getSection(Reference)->sh_link;
  if (const auto *ELF =
          llvm::dyn_cast<llvm::object::ELF64LEObjectFile>(&Object))
    return ELF->getSection(Reference)->sh_link;
  if (const auto *ELF =
          llvm::dyn_cast<llvm::object::ELF64BEObjectFile>(&Object))
    return ELF->getSection(Reference)->sh_link;
  return std::nullopt;
}

struct RelocationMetadata {
  uint8_t PatchSize = BytePatch;
  bool PCRelative = false;
  bool External = false;
  bool Scattered = false;
};

} // namespace

bool Internal::supportsMachORelocationMetadata(Target TargetValue,
                                               bool Scattered) noexcept {
  return !Scattered ||
         (TargetValue != Target::X86_64 && TargetValue != Target::AArch64);
}

namespace {

std::optional<RelocationMetadata>
relocationMetadata(const llvm::object::ObjectFile &Object,
                   const llvm::object::RelocationRef &Relocation,
                   Target TargetValue) noexcept {
  constexpr uint8_t WordPatch = 4;
  constexpr uint8_t DoubleWordPatch = 8;
  constexpr unsigned MachORelocationLengthMax = 3;
  RelocationMetadata Metadata;
  const uint32_t Type = static_cast<uint32_t>(Relocation.getType());
  if (const auto *MachO =
          llvm::dyn_cast<llvm::object::MachOObjectFile>(&Object)) {
    const auto Raw = MachO->getRelocation(Relocation.getRawDataRefImpl());
    Metadata.Scattered = MachO->isRelocationScattered(Raw);
    Metadata.PCRelative = MachO->getAnyRelocationPCRel(Raw) != 0;
    const unsigned Length = MachO->getAnyRelocationLength(Raw);
    if (Length > MachORelocationLengthMax) {
      return std::nullopt;
    }
    Metadata.PatchSize = static_cast<uint8_t>(BytePatch << Length);
    Metadata.External =
        !Metadata.Scattered && MachO->getPlainRelocationExternal(Raw);
    if (!Internal::supportsMachORelocationMetadata(TargetValue,
                                                   Metadata.Scattered)) {
      return std::nullopt;
    }
    if (TargetValue == Target::X86_64 &&
        Type == llvm::MachO::X86_64_RELOC_SIGNED &&
        (!Metadata.PCRelative || Metadata.PatchSize != WordPatch)) {
      return std::nullopt;
    }
    return Metadata;
  }
  if (TargetValue == Target::X86_64 && Object.isELF()) {
    if (Type == llvm::ELF::R_X86_64_64) {
      Metadata.PatchSize = DoubleWordPatch;
    } else if (Type == llvm::ELF::R_X86_64_PC32 ||
               Type == llvm::ELF::R_X86_64_PLT32 ||
               Type == llvm::ELF::R_X86_64_GOTPCRELX ||
               Type == llvm::ELF::R_X86_64_REX_GOTPCRELX) {
      Metadata.PatchSize = WordPatch;
    }
  } else if (TargetValue == Target::X86_64 && Object.isCOFF() &&
             Type >= llvm::COFF::IMAGE_REL_AMD64_REL32 &&
             Type <= llvm::COFF::IMAGE_REL_AMD64_REL32_5) {
    Metadata.PatchSize = WordPatch;
    Metadata.PCRelative = true;
  }
  Metadata.PCRelative =
      relocationIsPCRelative(objectFormat(Object), TargetValue, Type);
  return Metadata;
}

} // namespace

namespace Internal {

uint64_t normalizeSectionAlignment(uint64_t Alignment) noexcept {
  return std::max<uint64_t>(Alignment, 1);
}

std::optional<std::map<std::string, std::string>>
parseCOFFExports(std::string_view Input) {
  constexpr llvm::StringLiteral COFFExportPrefix = "/export:";
  constexpr size_t QuotedTokenDelimiterCount = 2;
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
      Directives = Directives.drop_front(End + QuotedTokenDelimiterCount);
    } else {
      std::tie(Token, Directives) = Directives.split(' ');
    }
    if (Token.size() < COFFExportPrefix.size() ||
#if LLVM_VERSION_MAJOR >= 19
        !Token.take_front(COFFExportPrefix.size())
             .equals_insensitive(COFFExportPrefix)) {
#else
        !Token.take_front(COFFExportPrefix.size())
             .equals_lower(COFFExportPrefix)) {
#endif
      continue;
    }
    Token = Token.drop_front(COFFExportPrefix.size());
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
                                     Target ExpectedTarget,
                                     ObjectReaderPolicy Policy,
                                     ObjectReaderInputPolicy InputPolicy) {
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

  LinkGraph Graph(*ActualTarget,
                  Object.isLittleEndian() ? Endianness::Little
                                          : Endianness::Big,
                  objectFormat(Object));
  if (!Graph.beginInput("object")) {
    return fail<LinkGraph>("cannot initialize link graph input");
  }
  if (const auto *ELF =
          llvm::dyn_cast<llvm::object::ELFObjectFileBase>(&Object)) {
    if (!Graph.setELFFlags(ELF->getPlatformFlags()))
      return fail<LinkGraph>("cannot preserve ELF flags");
  }
  std::map<uint64_t, SectionId> SectionIds;
  std::map<std::string, std::string> COFFExports;
  bool HasEHFrame = false;
  bool HasCompactUnwind = false;
  for (const auto &InputSection : Object.sections()) {
    llvm::StringRef Name;
    if (!take(InputSection.getName(), Name, "cannot read section name"))
      return Unexpect(ErrCode::Value::IllegalPath);
    const auto Purpose = sectionPurpose(Object, Name);
    HasEHFrame |= Purpose == SectionPurpose::EHFrame;
    HasCompactUnwind |= Purpose == SectionPurpose::CompactUnwind;
  }
  if (Policy == ObjectReaderPolicy::Universal && Object.isMachO() &&
      HasCompactUnwind && !HasEHFrame)
    return fail<LinkGraph>("Mach-O object lacks registered DWARF unwind");
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
    const auto Purpose = sectionPurpose(Object, Name);
    if (Policy == ObjectReaderPolicy::Universal &&
        Purpose == SectionPurpose::CompactUnwind)
      continue;
    constexpr uint64_t EHFrameTerminatorSize = 4;
    const uint64_t VirtualSize =
        InputSection.getSize() +
        (Object.isMachO() && Purpose == SectionPurpose::EHFrame
             ? EHFrameTerminatorSize
             : 0);
    if (VirtualSize < InputSection.getSize())
      return fail<LinkGraph>("section size overflows");
    if (VirtualSize != InputSection.getSize())
      Bytes.resize(static_cast<size_t>(VirtualSize));
    auto Added = Graph.addSection(
        Section{Name.str(), sectionKind(InputSection, Purpose),
                sectionAlignment(InputSection), VirtualSize, 0, 0,
                std::move(Bytes), Purpose, InputSection.getAddress()});
    if (!Added) {
      return fail<LinkGraph>(Added.error().Message);
    }
    SectionIds.emplace(InputSection.getIndex(), *Added);
  }
  for (const auto &InputSection : Object.sections()) {
    const auto Section = SectionIds.find(InputSection.getIndex());
    if (Section == SectionIds.end())
      continue;
    const auto &Value = Graph.sections()[Section->second];
    if (Value.Purpose != SectionPurpose::ARMExidx)
      continue;
    const auto LinkedInput = elfLinkedSection(Object, InputSection);
    if (!LinkedInput)
      return fail<LinkGraph>("cannot read linked ARM exidx section");
    const auto Linked = SectionIds.find(*LinkedInput);
    if (Linked == SectionIds.end() ||
        Graph.sections()[Linked->second].Kind != SectionKind::Text ||
        !Graph.setLinkedSection(Section->second, Linked->second))
      return fail<LinkGraph>("invalid linked ARM exidx section");
  }

  std::map<llvm::object::DataRefImpl, SymbolId> SymbolIds;
  std::set<llvm::object::DataRefImpl> IgnorableUndefinedSymbols;
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
        if (InputPolicy ==
                ObjectReaderInputPolicy::AllowUnreferencedMSVCFltused &&
            Object.isCOFF() && Name == "_fltused" &&
            (*ActualTarget == Target::X86_64 ||
             *ActualTarget == Target::AArch64)) {
          IgnorableUndefinedSymbols.insert(InputSymbol.getRawDataRefImpl());
          continue;
        }
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
    const bool Global = (Flags & llvm::object::SymbolRef::SF_Global) != 0;
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
    if (!Exported && std::any_of(Graph.symbols().begin(), Graph.symbols().end(),
                                 [&](const auto &Value) {
                                   return Value.Name == SymbolName;
                                 })) {
      SymbolName += "." + std::to_string((*InputSection)->getIndex()) + "." +
                    std::to_string(SymbolIds.size());
    }
    uint64_t SymbolSize = SymbolSizes[InputSymbol.getRawDataRefImpl()];
    if (const auto *COFF =
            llvm::dyn_cast<llvm::object::COFFObjectFile>(&Object);
        COFF && COFF->getCOFFSymbol(InputSymbol).isSectionDefinition())
      SymbolSize = 0;
    auto Added = Graph.addSymbol(Symbol{std::move(SymbolName), Section->second,
                                        Address - Base, SymbolSize, Exported,
                                        ExportName, Global});
    if (!Added) {
      return fail<LinkGraph>(Added.error().Message);
    }
    SymbolIds.emplace(InputSymbol.getRawDataRefImpl(), *Added);
  }

  if (!IgnorableUndefinedSymbols.empty()) {
    for (const auto &InputSection : Object.sections()) {
      for (const auto &InputRelocation : InputSection.relocations()) {
        const auto InputSymbol = InputRelocation.getSymbol();
        if (InputSymbol != Object.symbol_end() &&
            IgnorableUndefinedSymbols.count(InputSymbol->getRawDataRefImpl()) !=
                0)
          return fail<LinkGraph>("relocation targets MSVC CRT marker");
      }
    }
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
    if (Graph.sections()[Section->second].Purpose ==
        SectionPurpose::CompactUnwind)
      continue;
    if (Graph.sections()[Section->second].Purpose == SectionPurpose::XData &&
        InputSection.relocation_begin() != InputSection.relocation_end()) {
      return fail<LinkGraph>("personality relocation in .xdata is unsupported");
    }
    for (const auto &InputRelocation : InputSection.relocations()) {
      const auto Metadata =
          relocationMetadata(Object, InputRelocation, *ActualTarget);
      if (!Metadata) {
        return fail<LinkGraph>("malformed relocation metadata");
      }
      const auto InputSymbol = InputRelocation.getSymbol();
      if (InputSymbol == Object.symbol_end()) {
        return fail<LinkGraph>("relocation has no target symbol");
      }
      const auto Symbol = SymbolIds.find(InputSymbol->getRawDataRefImpl());
      if (Symbol == SymbolIds.end()) {
        return fail<LinkGraph>("relocation targets an unsupported symbol");
      }
      if (Object.isMachO() && Graph.sections()[Section->second].Purpose ==
                                  SectionPurpose::EHFrame) {
        if (*ActualTarget == Target::AArch64 &&
            InputRelocation.getType() == llvm::MachO::ARM64_RELOC_SUBTRACTOR)
          continue;
        if (*ActualTarget == Target::AArch64 &&
            InputRelocation.getType() == llvm::MachO::ARM64_RELOC_UNSIGNED) {
          if (!Graph.addEHFrameReference(
                  EHFrameReference{Section->second, InputRelocation.getOffset(),
                                   Symbol->second}))
            return fail<LinkGraph>("invalid Mach-O EH frame relocation");
          continue;
        }
      }
      const auto [Addend, Implicit] = relocationAddend(Object, InputRelocation);
      const auto PatchSize =
          relocationPatchSize(objectFormat(Object), *ActualTarget,
                              static_cast<uint32_t>(InputRelocation.getType()),
                              Metadata->PatchSize);
      if (!PatchSize) {
        return fail<LinkGraph>("unsupported relocation patch size");
      }
      auto Added = Graph.addRelocation(Relocation{
          Section->second, InputRelocation.getOffset(),
          static_cast<uint32_t>(InputRelocation.getType()), Symbol->second,
          Addend, Implicit, objectFormat(Object), *PatchSize,
          Metadata->PCRelative, Metadata->External, Metadata->Scattered});
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
