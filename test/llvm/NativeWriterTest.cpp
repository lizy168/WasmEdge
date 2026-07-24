// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/elf_writer.h"
#include "linker/relocation.h"

#include <gtest/gtest.h>

#include <llvm/BinaryFormat/ELF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBufferRef.h>

#include <array>
#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace {

using namespace WasmEdge::LLVM::Linker;

struct ELFCase {
  Target Architecture;
  Endianness Endian;
  uint16_t Machine;
  uint32_t RelativeType;
  bool Is64;
};

LinkGraph makeELFGraph(const ELFCase &Test) {
  LinkGraph Graph(Test.Architecture, Test.Endian);
  EXPECT_TRUE(Graph.beginInput("writer.o"));
  const uint8_t PointerSize = Test.Is64 ? 8 : 4;
  auto Text = Graph.addSection(
      Section{".text", SectionKind::Text, 16, 4, 0, 0, {0xC3, 0, 0, 0}});
  auto Rodata = Graph.addSection(
      Section{".rodata", SectionKind::ReadOnly, 8, 4, 0, 0, {1, 2, 3, 4}});
  auto EHFrame = Graph.addSection(Section{".eh_frame",
                                          SectionKind::Unwind,
                                          8,
                                          8,
                                          0,
                                          0,
                                          {0, 0, 0, 0, 0, 0, 0, 0},
                                          SectionPurpose::EHFrame});
  auto Data = Graph.addSection(
      Section{".data", SectionKind::Data, PointerSize, PointerSize, 0, 0,
              std::vector<WasmEdge::Byte>(PointerSize)});
  auto BSS = Graph.addSection(
      Section{".bss", SectionKind::BSS, PointerSize, PointerSize});
  EXPECT_TRUE(Text && Rodata && EHFrame && Data && BSS);
  EXPECT_TRUE(
      Graph.addSymbol(Symbol{"f0", *Text, 0, 4, true, std::nullopt, true}));
  EXPECT_TRUE(Graph.addSymbol(
      Symbol{"value", *Data, 0, PointerSize, true, std::nullopt, true}));
  EXPECT_TRUE(Graph.addRebase(
      Rebase{*Data, 0, Test.RelativeType, 0, PointerSize, ObjectFormat::ELF}));
  return Graph;
}

uint64_t readInteger(const std::vector<WasmEdge::Byte> &Bytes, size_t Offset,
                     uint8_t Width, Endianness Endian) {
  uint64_t Result = 0;
  for (uint8_t I = 0; I < Width; ++I) {
    const uint8_t Shift = Endian == Endianness::Little ? I : Width - I - 1;
    Result |= static_cast<uint64_t>(Bytes[Offset + I]) << (Shift * 8);
  }
  return Result;
}

TEST(ELFWriterTest, WritesLoadableImagesForEveryLinuxTarget) {
  const std::array<ELFCase, 5> Cases{{
      {Target::ARM, Endianness::Little, llvm::ELF::EM_ARM,
       llvm::ELF::R_ARM_RELATIVE, false},
      {Target::X86_64, Endianness::Little, llvm::ELF::EM_X86_64,
       llvm::ELF::R_X86_64_RELATIVE, true},
      {Target::AArch64, Endianness::Little, llvm::ELF::EM_AARCH64,
       llvm::ELF::R_AARCH64_RELATIVE, true},
      {Target::RISCV64, Endianness::Little, llvm::ELF::EM_RISCV,
       llvm::ELF::R_RISCV_RELATIVE, true},
      {Target::S390X, Endianness::Big, llvm::ELF::EM_S390,
       llvm::ELF::R_390_RELATIVE, true},
  }};
  for (const auto &Test : Cases) {
    auto Graph = makeELFGraph(Test);
    ASSERT_TRUE(ELFWriter::layout(Graph));
    if (!Test.Is64) {
      auto Data = Graph.sectionContent(3);
      ASSERT_TRUE(Data);
      for (uint8_t I = 0; I < 4; ++I)
        (*Data)[I] =
            static_cast<WasmEdge::Byte>(Graph.sections()[3].Address >> (I * 8));
    }
    ASSERT_TRUE(applyRelocations(Graph));
    std::vector<WasmEdge::Byte> Bytes;
    Writer Output(Bytes);
    ASSERT_TRUE(ELFWriter::write(Graph, Output));

    auto Object =
        llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
            llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                            Bytes.size()),
            "writer.so"));
    ASSERT_TRUE(static_cast<bool>(Object))
        << llvm::toString(Object.takeError());
    EXPECT_TRUE((*Object)->isELF());
    EXPECT_EQ((*Object)->getArch(),
              Test.Architecture == Target::ARM       ? llvm::Triple::arm
              : Test.Architecture == Target::X86_64  ? llvm::Triple::x86_64
              : Test.Architecture == Target::AArch64 ? llvm::Triple::aarch64
              : Test.Architecture == Target::RISCV64 ? llvm::Triple::riscv64
                                                     : llvm::Triple::systemz);
    std::set<std::string> Sections;
    for (const auto &Section : (*Object)->sections()) {
      auto Name = Section.getName();
      ASSERT_TRUE(static_cast<bool>(Name));
      Sections.emplace(Name->str());
    }
    for (const char *Name :
         {".text", ".rodata", ".eh_frame", ".eh_frame_hdr", ".data", ".bss",
          ".dynsym", ".dynstr", ".hash", ".dynamic", ".shstrtab"}) {
      EXPECT_TRUE(Sections.count(Name)) << Name;
    }
    EXPECT_TRUE(Sections.count(Test.Is64 ? ".rela.dyn" : ".rel.dyn"));
    std::set<std::string> Symbols;
    const auto *ELF =
        llvm::dyn_cast<llvm::object::ELFObjectFileBase>(&**Object);
    ASSERT_NE(ELF, nullptr);
    for (const auto &Symbol : ELF->getDynamicSymbolIterators()) {
      auto Name = Symbol.getName();
      ASSERT_TRUE(static_cast<bool>(Name));
      if (!Name->empty())
        Symbols.emplace(Name->str());
    }
    EXPECT_EQ(Symbols, (std::set<std::string>{"f0", "value"}));

    const uint64_t ProgramHeaderOffset =
        readInteger(Bytes, Test.Is64 ? 32 : 28, Test.Is64 ? 8 : 4, Test.Endian);
    const uint16_t ProgramHeaderSize = static_cast<uint16_t>(
        readInteger(Bytes, Test.Is64 ? 54 : 42, 2, Test.Endian));
    const uint16_t ProgramHeaderCount = static_cast<uint16_t>(
        readInteger(Bytes, Test.Is64 ? 56 : 44, 2, Test.Endian));
    bool HasDynamic = false;
    bool HasEHFrame = false;
    bool HasNonExecutableStack = false;
    bool HasInterpreter = false;
    for (uint16_t I = 0; I < ProgramHeaderCount; ++I) {
      const uint64_t Offset = ProgramHeaderOffset + I * ProgramHeaderSize;
      const uint32_t Type =
          static_cast<uint32_t>(readInteger(Bytes, Offset, 4, Test.Endian));
      const uint32_t Flags = static_cast<uint32_t>(
          readInteger(Bytes, Offset + (Test.Is64 ? 4 : 24), 4, Test.Endian));
      HasDynamic |= Type == llvm::ELF::PT_DYNAMIC;
      HasEHFrame |= Type == llvm::ELF::PT_GNU_EH_FRAME;
      HasNonExecutableStack |=
          Type == llvm::ELF::PT_GNU_STACK && (Flags & llvm::ELF::PF_X) == 0;
      HasInterpreter |= Type == llvm::ELF::PT_INTERP;
      if (Type == llvm::ELF::PT_LOAD) {
        const uint64_t FileOffset =
            readInteger(Bytes, Offset + (Test.Is64 ? 8 : 4), Test.Is64 ? 8 : 4,
                        Test.Endian);
        const uint64_t Address =
            readInteger(Bytes, Offset + (Test.Is64 ? 16 : 8), Test.Is64 ? 8 : 4,
                        Test.Endian);
        EXPECT_EQ(FileOffset % 4096, Address % 4096);
        EXPECT_NE(Flags & llvm::ELF::PF_R, 0U);
        EXPECT_FALSE((Flags & llvm::ELF::PF_X) != 0 &&
                     (Flags & llvm::ELF::PF_W) != 0);
      }
    }
    EXPECT_TRUE(HasDynamic);
    EXPECT_TRUE(HasEHFrame);
    EXPECT_TRUE(HasNonExecutableStack);
    EXPECT_FALSE(HasInterpreter);

    bool CheckedRelocation = false;
    for (const auto &Section : (*Object)->sections()) {
      auto Name = Section.getName();
      ASSERT_TRUE(static_cast<bool>(Name));
      if (*Name != (Test.Is64 ? ".rela.dyn" : ".rel.dyn"))
        continue;
      auto Content = Section.getContents();
      ASSERT_TRUE(static_cast<bool>(Content));
      ASSERT_EQ(Content->size(), Test.Is64 ? 24U : 8U);
      const auto *RelocationBytes =
          reinterpret_cast<const WasmEdge::Byte *>(Content->data());
      const uint64_t Info =
          readInteger(std::vector<WasmEdge::Byte>(
                          RelocationBytes, RelocationBytes + Content->size()),
                      Test.Is64 ? 8 : 4, Test.Is64 ? 8 : 4, Test.Endian);
      EXPECT_EQ(Test.Is64 ? static_cast<uint32_t>(Info)
                          : static_cast<uint32_t>(Info & 0xFF),
                Test.RelativeType);
      if (!Test.Is64) {
        EXPECT_EQ(
            readInteger(Bytes, Graph.sections()[3].FileOffset, 4, Test.Endian),
            Graph.sections()[3].Address);
      }
      CheckedRelocation = true;
    }
    EXPECT_TRUE(CheckedRelocation);
  }
}

TEST(ELFWriterTest, RejectsUnsupportedRebasesAndInvalidState) {
  const ELFCase Test{Target::X86_64, Endianness::Little, llvm::ELF::EM_X86_64,
                     llvm::ELF::R_X86_64_RELATIVE, true};
  auto Graph = makeELFGraph(Test);
  ASSERT_TRUE(ELFWriter::layout(Graph));
  ASSERT_TRUE(applyRelocations(Graph));
  auto &RebaseValue = const_cast<std::vector<Rebase> &>(Graph.rebases())[0];
  RebaseValue.Width = 4;
  std::vector<WasmEdge::Byte> Bytes;
  Writer Output(Bytes);
  EXPECT_FALSE(ELFWriter::write(Graph, Output));
  EXPECT_TRUE(Bytes.empty());

  LinkGraph WrongEndian(Target::X86_64, Endianness::Big);
  ASSERT_TRUE(WrongEndian.beginInput("wrong.o"));
  ASSERT_TRUE(WrongEndian.addSection(
      Section{".text", SectionKind::Text, 1, 1, 0, 0, {0}}));
  EXPECT_FALSE(ELFWriter::layout(WrongEndian));
}

} // namespace
