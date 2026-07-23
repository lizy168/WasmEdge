// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/layout.h"
#include "linker/link_graph.h"
#include "linker/object_reader.h"
#include "linker/relocation.h"

#include <gtest/gtest.h>

#include <llvm/Config/llvm-config.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/TargetRegistry.h>
#if LLVM_VERSION_MAJOR >= 19
#include <llvm/MC/MCELFExtras.h>
#endif
#include <llvm/Object/MachO.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/CodeGen.h>
#if LLVM_VERSION_MAJOR >= 19
#include <llvm/TargetParser/Host.h>
#else
#include <llvm/Support/Host.h>
#endif
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

namespace {

using namespace WasmEdge::LLVM::Linker;

std::vector<WasmEdge::Byte>
makeObject(const llvm::Triple &Triple, bool Undefined = false,
           bool DLLExport = false, std::string FunctionName = "f0",
           std::string Directives = {}, bool Hidden = false) {
  static const bool Initialized = [] {
    llvm::InitializeAllTargets();
    llvm::InitializeAllTargetMCs();
    llvm::InitializeAllAsmPrinters();
    llvm::InitializeAllAsmParsers();
    return true;
  }();
  (void)Initialized;
  std::string Error;
  const llvm::Target *NativeTarget =
      llvm::TargetRegistry::lookupTarget(Triple.str(), Error);
  EXPECT_NE(NativeTarget, nullptr) << Error;
  if (NativeTarget == nullptr) {
    return {};
  }
  llvm::TargetOptions Options;
  std::unique_ptr<llvm::TargetMachine> Machine(
      NativeTarget->createTargetMachine(
#if LLVM_VERSION_MAJOR >= 21
          Triple,
#else
          Triple.str(),
#endif
          "generic", "", Options, llvm::Reloc::PIC_));
  EXPECT_NE(Machine, nullptr);
  if (Machine == nullptr) {
    return {};
  }

  llvm::LLVMContext Context;
  llvm::Module Module("object-reader-test", Context);
#if LLVM_VERSION_MAJOR >= 21
  Module.setTargetTriple(Triple);
#else
  Module.setTargetTriple(Triple.str());
#endif
  Module.setDataLayout(Machine->createDataLayout());
  auto *I32 = llvm::Type::getInt32Ty(Context);
  auto *Value = new llvm::GlobalVariable(
      Module, I32, false, llvm::GlobalValue::ExternalLinkage,
      Undefined ? nullptr : llvm::ConstantInt::get(I32, 7), "value");
  auto *Zero = new llvm::GlobalVariable(Module, I32, false,
                                        llvm::GlobalValue::InternalLinkage,
                                        llvm::ConstantInt::get(I32, 0), "zero");
  Zero->setAlignment(llvm::Align(16));
  auto *F0 = llvm::Function::Create(llvm::FunctionType::get(I32, false),
                                    llvm::GlobalValue::ExternalLinkage,
                                    FunctionName, Module);
  F0->addFnAttr(llvm::Attribute::NoUnwind);
  F0->setVisibility(Hidden ? llvm::GlobalValue::HiddenVisibility
                           : llvm::GlobalValue::DefaultVisibility);
  if (DLLExport) {
    F0->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
  }
  llvm::IRBuilder<> Builder(llvm::BasicBlock::Create(Context, "entry", F0));
  Builder.CreateRet(Builder.CreateLoad(I32, Value));
  if (!Directives.empty()) {
    Module.setModuleInlineAsm(".section .drectve\n.ascii \" " + Directives +
                              "\"");
  }

  llvm::SmallVector<char, 0> Storage;
  llvm::raw_svector_ostream Stream(Storage);
  llvm::legacy::PassManager Passes;
#if LLVM_VERSION_MAJOR >= 18
  const auto FileType = llvm::CodeGenFileType::ObjectFile;
#else
  const auto FileType = llvm::CGFT_ObjectFile;
#endif
  EXPECT_FALSE(Machine->addPassesToEmitFile(Passes, Stream, nullptr, FileType));
  Passes.run(Module);
  return std::vector<WasmEdge::Byte>(Storage.begin(), Storage.end());
}

uint64_t read64le(const std::vector<WasmEdge::Byte> &Bytes, size_t Offset) {
  uint64_t Value = 0;
  for (size_t I = 0; I < 8; ++I) {
    Value |= static_cast<uint64_t>(Bytes[Offset + I]) << (I * 8);
  }
  return Value;
}

void write64le(std::vector<WasmEdge::Byte> &Bytes, size_t Offset,
               uint64_t Value) {
  for (size_t I = 0; I < 8; ++I) {
    Bytes[Offset + I] = static_cast<WasmEdge::Byte>(Value >> (I * 8));
  }
}

size_t elf64RelocationSectionHeader(const std::vector<WasmEdge::Byte> &Bytes) {
  auto Object =
      llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
          llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                          Bytes.size()),
          "test.o"));
  EXPECT_TRUE(static_cast<bool>(Object));
  if (!Object) {
    llvm::consumeError(Object.takeError());
    return 0;
  }
  uint64_t Index = 0;
  for (const auto &Section : (*Object)->sections()) {
    auto Name = Section.getName();
    EXPECT_TRUE(static_cast<bool>(Name));
    if (Name &&
#if LLVM_VERSION_MAJOR >= 19
        (Name->starts_with(".rela") || Name->starts_with(".rel"))) {
#else
        (Name->startswith(".rela") || Name->startswith(".rel"))) {
#endif
      Index = Section.getIndex();
      break;
    }
  }
  EXPECT_NE(Index, 0U);
  return static_cast<size_t>(read64le(Bytes, 40) + Index * 64);
}

#if LLVM_VERSION_MAJOR >= 19
std::vector<WasmEdge::Byte> makeX86_64CrelObject() {
  auto Bytes = makeObject(llvm::Triple("x86_64-unknown-linux-gnu"));
  const auto Header = elf64RelocationSectionHeader(Bytes);
  const auto Offset = read64le(Bytes, Header + 24);
  const auto Info = read64le(Bytes, Offset + 8);
  const auto Addend = static_cast<int64_t>(read64le(Bytes, Offset + 16));
  const std::array<llvm::ELF::Elf_Crel<true>, 1> Relocations{{
      {read64le(Bytes, Offset), static_cast<uint32_t>(Info >> 32),
       static_cast<uint32_t>(Info), Addend},
  }};
  llvm::SmallVector<char, 16> Encoded;
  llvm::raw_svector_ostream Stream(Encoded);
  llvm::ELF::encodeCrel<true>(
      Stream, Relocations, [](const auto &Relocation) { return Relocation; });
  std::copy(Encoded.begin(), Encoded.end(), Bytes.begin() + Offset);
  Bytes[Header + 4] = 0x14;
  Bytes[Header + 5] = 0x00;
  Bytes[Header + 6] = 0x00;
  Bytes[Header + 7] = 0x40;
  write64le(Bytes, Header + 32, Encoded.size());
  write64le(Bytes, Header + 56, 1);
  return Bytes;
}
#endif

std::vector<WasmEdge::Byte> makeNativeObject(bool Undefined = false) {
  return makeObject(llvm::Triple(llvm::sys::getDefaultTargetTriple()),
                    Undefined);
}

std::vector<WasmEdge::Byte> makeX86_64AssemblyObject(std::string Assembly) {
  static const bool Initialized = [] {
    llvm::InitializeAllTargets();
    llvm::InitializeAllTargetMCs();
    llvm::InitializeAllAsmPrinters();
    llvm::InitializeAllAsmParsers();
    return true;
  }();
  (void)Initialized;
  const llvm::Triple Triple("x86_64-unknown-linux-gnu");
  std::string Error;
  const llvm::Target *Target =
      llvm::TargetRegistry::lookupTarget(Triple.str(), Error);
  EXPECT_NE(Target, nullptr) << Error;
  if (Target == nullptr) {
    return {};
  }
  llvm::TargetOptions Options;
  std::unique_ptr<llvm::TargetMachine> Machine(Target->createTargetMachine(
#if LLVM_VERSION_MAJOR >= 21
      Triple,
#else
      Triple.str(),
#endif
      "generic", "", Options, llvm::Reloc::PIC_));
  EXPECT_NE(Machine, nullptr);
  if (Machine == nullptr) {
    return {};
  }
  llvm::LLVMContext Context;
  llvm::Module Module("x86-relocation-test", Context);
#if LLVM_VERSION_MAJOR >= 21
  Module.setTargetTriple(Triple);
#else
  Module.setTargetTriple(Triple.str());
#endif
  Module.setDataLayout(Machine->createDataLayout());
  Module.setModuleInlineAsm(std::move(Assembly));
  llvm::SmallVector<char, 0> Storage;
  llvm::raw_svector_ostream Stream(Storage);
  llvm::legacy::PassManager Passes;
#if LLVM_VERSION_MAJOR >= 18
  const auto FileType = llvm::CodeGenFileType::ObjectFile;
#else
  const auto FileType = llvm::CGFT_ObjectFile;
#endif
  EXPECT_FALSE(Machine->addPassesToEmitFile(Passes, Stream, nullptr, FileType));
  Passes.run(Module);
  return std::vector<WasmEdge::Byte>(Storage.begin(), Storage.end());
}

Target nativeTarget() {
#if defined(__x86_64__) || defined(_M_X64)
  return Target::X86_64;
#elif defined(__aarch64__) || defined(_M_ARM64)
  return Target::AArch64;
#elif defined(__arm__) || defined(_M_ARM)
  return Target::ARM;
#elif defined(__riscv) && __riscv_xlen == 64
  return Target::RISCV64;
#elif defined(__s390x__)
  return Target::S390X;
#else
#error Unsupported test host
#endif
}

static_assert(sizeof(Target) == sizeof(uint8_t));
static_assert(sizeof(Endianness) == sizeof(uint8_t));
static_assert(sizeof(SectionKind) == sizeof(uint8_t));
static_assert(sizeof(ObjectFormat) == sizeof(uint8_t));
static_assert(std::is_same_v<SectionId, uint32_t>);
static_assert(std::is_same_v<SymbolId, uint32_t>);
static_assert(
    std::is_same_v<decltype(Section::Content), std::vector<WasmEdge::Byte>>);
static_assert(std::is_same_v<decltype(Symbol::Section), SectionId>);

TEST(LinkGraphTest, OwnsContentAndUsesStableIds) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));

  std::vector<uint8_t> Content{0x48, 0x89, 0xE5};
  auto Text = Graph.addSection(
      Section{".text", SectionKind::Text, 16, 3, 0, 0, Content});
  ASSERT_TRUE(Text);
  EXPECT_EQ(*Text, 0U);

  Content[0] = 0;
  ASSERT_EQ(Graph.sections().size(), 1U);
  EXPECT_EQ(Graph.sections()[*Text].Content[0], 0x48U);

  auto Data = Graph.addSection(
      Section{".data", SectionKind::Data, 8, 4, 0, 0, {1, 2, 3, 4}});
  ASSERT_TRUE(Data);
  EXPECT_EQ(*Data, 1U);
  EXPECT_EQ(*Text, 0U);

  auto Entry = Graph.addSymbol(Symbol{"entry", *Text, 0, 3, true});
  ASSERT_TRUE(Entry);
  EXPECT_EQ(*Entry, 0U);
  EXPECT_EQ(Graph.target(), Target::X86_64);
  EXPECT_EQ(Graph.endianness(), Endianness::Little);
  EXPECT_TRUE(Graph.validate());
}

TEST(LinkGraphTest, RejectsSecondInputObject) {
  LinkGraph Graph(Target::ARM, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("first.o"));
  auto Result = Graph.beginInput("second.o");
  ASSERT_FALSE(Result);
  EXPECT_EQ(Result.error().Message,
            "link graph accepts exactly one input object");
}

TEST(LinkGraphTest, RejectsInvalidSectionAlignment) {
  LinkGraph Graph(Target::AArch64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));

  auto Zero = Graph.addSection(Section{"zero", SectionKind::Data, 0, 0});
  ASSERT_FALSE(Zero);
  EXPECT_EQ(Zero.error().SectionName, "zero");

  auto NonPowerOfTwo =
      Graph.addSection(Section{"three", SectionKind::Data, 3, 0});
  ASSERT_FALSE(NonPowerOfTwo);
  EXPECT_EQ(NonPowerOfTwo.error().Message,
            "section alignment must be a non-zero power of two");
}

TEST(LinkGraphTest, RejectsContentBeyondSectionVirtualSize) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));

  auto Result =
      Graph.addSection(Section{".data", SectionKind::Data, 1, 1, 0, 0, {1, 2}});
  ASSERT_FALSE(Result);
  EXPECT_EQ(Result.error().SectionName, ".data");
  EXPECT_EQ(Result.error().Message,
            "section content exceeds section virtual size");
}

TEST(LinkGraphTest, RejectsDuplicateSymbolDefinitions) {
  LinkGraph Graph(Target::RISCV64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Text = Graph.addSection(
      Section{".text", SectionKind::Text, 4, 4, 0, 0, {0, 0, 0, 0}});
  ASSERT_TRUE(Text);
  ASSERT_TRUE(Graph.addSymbol(Symbol{"same", *Text, 0, 1, false}));

  auto Duplicate = Graph.addSymbol(Symbol{"same", *Text, 1, 1, false});
  ASSERT_FALSE(Duplicate);
  EXPECT_EQ(Duplicate.error().SymbolName, "same");
  EXPECT_EQ(Duplicate.error().Message, "duplicate symbol definition");
}

TEST(LinkGraphTest, RejectsUndefinedSymbols) {
  LinkGraph Graph(Target::S390X, Endianness::Big);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Result =
      Graph.addSymbol(Symbol{"missing", InvalidSectionId, 0, 0, false});
  ASSERT_FALSE(Result);
  EXPECT_EQ(Result.error().SymbolName, "missing");
  EXPECT_EQ(Result.error().Message, "undefined symbol");
  EXPECT_TRUE(Graph.symbols().empty());
}

TEST(LinkGraphTest, RejectsZeroInputObjects) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  auto Result = Graph.validate();
  ASSERT_FALSE(Result);
  EXPECT_EQ(Result.error().Message, "link graph requires one input object");
}

TEST(LinkGraphTest, RejectsInvalidSectionIds) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));

  auto Result = Graph.addSymbol(Symbol{"bad", 7, 0, 0, false});
  ASSERT_FALSE(Result);
  ASSERT_TRUE(Result.error().Section);
  EXPECT_EQ(*Result.error().Section, 7U);
  EXPECT_EQ(Result.error().Message, "invalid section ID");
}

TEST(LinkGraphTest, RejectsSymbolsBeyondSectionVirtualSize) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Bss = Graph.addSection(Section{".bss", SectionKind::BSS, 8, 8});
  ASSERT_TRUE(Bss);

  auto Result = Graph.addSymbol(Symbol{"too_large", *Bss, 7, 2, false});
  ASSERT_FALSE(Result);
  EXPECT_EQ(Result.error().SymbolName, "too_large");
  EXPECT_EQ(Result.error().Offset, 7U);
  EXPECT_EQ(Result.error().Message,
            "symbol extends beyond section virtual size");
}

TEST(LinkGraphTest, StoresRelocationsAndRebases) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Text = Graph.addSection(
      Section{".text", SectionKind::Text, 4, 4, 0, 0, {0, 0, 0, 0}});
  ASSERT_TRUE(Text);
  auto TargetSymbol = Graph.addSymbol(Symbol{"target", *Text, 0, 4, false});
  ASSERT_TRUE(TargetSymbol);

  ASSERT_TRUE(Graph.addRelocation(Relocation{*Text, 1, 42, *TargetSymbol, -4}));
  ASSERT_TRUE(Graph.addRebase(Rebase{*Text, 2, 7, 8}));
  ASSERT_EQ(Graph.relocations().size(), 1U);
  EXPECT_EQ(Graph.relocations()[0].Symbol, *TargetSymbol);
  ASSERT_EQ(Graph.rebases().size(), 1U);
  EXPECT_EQ(Graph.rebases()[0].Addend, 8);
}

TEST(LinkGraphTest, RejectsOverlappingRelocationsRegardlessOfOrder) {
  for (const bool Reverse : {false, true}) {
    LinkGraph Graph(Target::X86_64, Endianness::Little);
    ASSERT_TRUE(Graph.beginInput("input.o"));
    auto Text = Graph.addSection(Section{
        ".text", SectionKind::Text, 1, 8, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}});
    ASSERT_TRUE(Text);
    auto TargetSymbol = Graph.addSymbol(Symbol{"target", *Text, 0, 1, false});
    ASSERT_TRUE(TargetSymbol);
    Relocation First{*Text, 1, 2, *TargetSymbol, 0};
    First.PatchSize = 4;
    Relocation Second{*Text, 3, 2, *TargetSymbol, 0};
    Second.PatchSize = 4;
    ASSERT_TRUE(Graph.addRelocation(Reverse ? Second : First));
    auto Result = Graph.addRelocation(Reverse ? First : Second);
    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Message, "overlapping relocation patches");
  }
}

TEST(LinkGraphTest, RejectsOverlappingRebasesRegardlessOfOrder) {
  for (const bool Reverse : {false, true}) {
    LinkGraph Graph(Target::X86_64, Endianness::Little);
    ASSERT_TRUE(Graph.beginInput("input.o"));
    auto Data = Graph.addSection(Section{".data",
                                         SectionKind::Data,
                                         1,
                                         12,
                                         0,
                                         0,
                                         {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}});
    ASSERT_TRUE(Data);
    const Rebase First{*Data, 1, 1, 0, 8};
    const Rebase Second{*Data, 7, 1, 0, 4};
    ASSERT_TRUE(Graph.addRebase(Reverse ? Second : First));
    auto Result = Graph.addRebase(Reverse ? First : Second);
    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Message, "overlapping rebase patches");
  }
}

TEST(LinkGraphTest, RejectsInvalidPatchSections) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Text =
      Graph.addSection(Section{".text", SectionKind::Text, 1, 1, 0, 0, {0}});
  ASSERT_TRUE(Text);
  auto TargetSymbol = Graph.addSymbol(Symbol{"target", *Text, 0, 1, false});
  ASSERT_TRUE(TargetSymbol);

  auto RelocationResult = Graph.addRelocation(
      Relocation{InvalidSectionId, 0, 42, *TargetSymbol, 0});
  ASSERT_FALSE(RelocationResult);
  EXPECT_EQ(RelocationResult.error().Message, "invalid section ID");
  auto RebaseResult = Graph.addRebase(Rebase{InvalidSectionId, 0, 7, 0});
  ASSERT_FALSE(RebaseResult);
  EXPECT_EQ(RebaseResult.error().Message, "invalid section ID");
}

TEST(LinkGraphTest, RejectsPatchOffsetsOutsideSectionContent) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Text =
      Graph.addSection(Section{".text", SectionKind::Text, 1, 4, 0, 0, {0}});
  ASSERT_TRUE(Text);
  auto TargetSymbol = Graph.addSymbol(Symbol{"target", *Text, 0, 1, false});
  ASSERT_TRUE(TargetSymbol);

  auto RelocationResult =
      Graph.addRelocation(Relocation{*Text, 1, 42, *TargetSymbol, 0});
  ASSERT_FALSE(RelocationResult);
  EXPECT_EQ(RelocationResult.error().Offset, 1U);
  EXPECT_EQ(RelocationResult.error().Message,
            "relocation offset is outside section content");
  auto RebaseResult = Graph.addRebase(Rebase{*Text, 1, 7, 0});
  ASSERT_FALSE(RebaseResult);
  EXPECT_EQ(RebaseResult.error().Offset, 1U);
  EXPECT_EQ(RebaseResult.error().Message,
            "rebase offset is outside section content");
}

TEST(LinkGraphTest, ProvidesCheckedMutableGraphAccess) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Text =
      Graph.addSection(Section{".text", SectionKind::Text, 1, 2, 0, 0, {0, 0}});
  ASSERT_TRUE(Text);
  auto TargetSymbol = Graph.addSymbol(Symbol{"target", *Text, 0, 1, false});
  ASSERT_TRUE(TargetSymbol);
  ASSERT_TRUE(Graph.addRelocation(Relocation{*Text, 0, 42, *TargetSymbol, 0}));
  ASSERT_TRUE(Graph.addRebase(Rebase{*Text, 1, 7, 0}));

  ASSERT_TRUE(Graph.setSectionAddress(*Text, 64));
  ASSERT_TRUE(Graph.setSectionFileOffset(*Text, 32));
  auto Content = Graph.sectionContent(*Text);
  ASSERT_TRUE(Content);
  (*Content)[0] = 0xCC;
  const_cast<std::vector<Relocation> &>(Graph.relocations())[0].Addend = 8;
  const_cast<std::vector<Rebase> &>(Graph.rebases())[0].Addend = 16;
  EXPECT_EQ(Graph.sections()[*Text].Address, 64U);
  EXPECT_EQ(Graph.sections()[*Text].FileOffset, 32U);
  EXPECT_EQ(Graph.sections()[*Text].Content[0], 0xCCU);
  EXPECT_EQ(Graph.relocations()[0].Addend, 8);
  EXPECT_EQ(Graph.rebases()[0].Addend, 16);

  EXPECT_FALSE(Graph.setSectionAddress(InvalidSectionId, 0));
  EXPECT_FALSE(Graph.setSectionFileOffset(InvalidSectionId, 0));
  EXPECT_FALSE(Graph.sectionContent(InvalidSectionId));
}

TEST(LinkGraphTest, ValidatesMutatedSectionInvariants) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Text =
      Graph.addSection(Section{".text", SectionKind::Text, 1, 2, 0, 0, {0}});
  ASSERT_TRUE(Text);

  auto Content = Graph.sectionContent(*Text);
  ASSERT_TRUE(Content);
  auto &Sections = const_cast<std::vector<Section> &>(Graph.sections());
  Sections[*Text].Alignment = 0;
  auto AlignmentResult = Graph.validate();
  ASSERT_FALSE(AlignmentResult);
  EXPECT_EQ(AlignmentResult.error().Message,
            "section alignment must be a non-zero power of two");

  Sections[*Text].Alignment = 1;
  Sections[*Text].VirtualSize = 0;
  auto SizeResult = Graph.validate();
  ASSERT_FALSE(SizeResult);
  EXPECT_EQ(SizeResult.error().Message,
            "section content exceeds section virtual size");
}

TEST(LinkGraphTest, ValidatesMutatedPatchOffsets) {
  LinkGraph RelocationGraph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(RelocationGraph.beginInput("input.o"));
  auto Text = RelocationGraph.addSection(
      Section{".text", SectionKind::Text, 1, 1, 0, 0, {0}});
  ASSERT_TRUE(Text);
  auto TargetSymbol =
      RelocationGraph.addSymbol(Symbol{"target", *Text, 0, 1, false});
  ASSERT_TRUE(TargetSymbol);
  ASSERT_TRUE(RelocationGraph.addRelocation(
      Relocation{*Text, 0, 42, *TargetSymbol, 0}));
  const_cast<std::vector<Relocation> &>(RelocationGraph.relocations())[0]
      .Offset = 1;
  auto RelocationResult = RelocationGraph.validate();
  ASSERT_FALSE(RelocationResult);
  EXPECT_EQ(RelocationResult.error().Message,
            "relocation offset is outside section content");

  LinkGraph RebaseGraph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(RebaseGraph.beginInput("input.o"));
  Text = RebaseGraph.addSection(
      Section{".text", SectionKind::Text, 1, 1, 0, 0, {0}});
  ASSERT_TRUE(Text);
  ASSERT_TRUE(RebaseGraph.addRebase(Rebase{*Text, 0, 7, 0}));
  const_cast<std::vector<Rebase> &>(RebaseGraph.rebases())[0].Offset = 1;
  auto RebaseResult = RebaseGraph.validate();
  ASSERT_FALSE(RebaseResult);
  EXPECT_EQ(RebaseResult.error().Message,
            "rebase offset is outside section content");
}

TEST(LinkGraphTest, SymbolIdsRemainStableAcrossVectorGrowth) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Bss = Graph.addSection(Section{".bss", SectionKind::BSS, 1, 64});
  ASSERT_TRUE(Bss);

  auto First = Graph.addSymbol(Symbol{"first", *Bss, 0, 1, false});
  ASSERT_TRUE(First);
  for (uint32_t I = 1; I < 64; ++I) {
    ASSERT_TRUE(Graph.addSymbol(
        Symbol{"symbol" + std::to_string(I), *Bss, I, 1, false}));
  }

  EXPECT_EQ(*First, 0U);
  EXPECT_EQ(Graph.symbols()[*First].Name, "first");
}

TEST(LinkGraphTest, SectionOffsetsDefaultToZero) {
  Section Value{".data", SectionKind::Data, 4};
  EXPECT_EQ(Value.Address, 0U);
  EXPECT_EQ(Value.FileOffset, 0U);
  EXPECT_EQ(Value.VirtualSize, 0U);
}

TEST(LayoutTest, GroupsAndAlignsSections) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Data = Graph.addSection(
      Section{".data", SectionKind::Data, 8, 4, 0, 0, {1, 2, 3, 4}});
  auto Unwind = Graph.addSection(
      Section{".eh_frame", SectionKind::Unwind, 4, 3, 0, 0, {1, 2, 3}});
  auto ReadOnly = Graph.addSection(
      Section{".rodata", SectionKind::ReadOnly, 2, 2, 0, 0, {1, 2}});
  auto TextZ = Graph.addSection(
      Section{".text.z", SectionKind::Text, 4, 3, 0, 0, {1, 2, 3}});
  auto TextA =
      Graph.addSection(Section{".text.a", SectionKind::Text, 8, 1, 0, 0, {1}});
  ASSERT_TRUE(Data && Unwind && ReadOnly && TextZ && TextA);

  ASSERT_TRUE(layout(Graph));
  EXPECT_EQ(Graph.sections()[*TextA].Address, 0U);
  EXPECT_EQ(Graph.sections()[*TextA].FileOffset, 0U);
  EXPECT_EQ(Graph.sections()[*TextZ].Address, 4U);
  EXPECT_EQ(Graph.sections()[*TextZ].FileOffset, 4U);
  EXPECT_EQ(Graph.sections()[*ReadOnly].Address, 8U);
  EXPECT_EQ(Graph.sections()[*ReadOnly].FileOffset, 8U);
  EXPECT_EQ(Graph.sections()[*Unwind].Address, 12U);
  EXPECT_EQ(Graph.sections()[*Unwind].FileOffset, 12U);
  EXPECT_EQ(Graph.sections()[*Data].Address, 16U);
  EXPECT_EQ(Graph.sections()[*Data].FileOffset, 16U);
}

TEST(LayoutTest, BssConsumesVirtualButNotFileSpace) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto First =
      Graph.addSection(Section{"a", SectionKind::Data, 1, 3, 0, 0, {1, 2, 3}});
  auto Second =
      Graph.addSection(Section{"z", SectionKind::Data, 4, 1, 0, 0, {1}});
  auto Bss = Graph.addSection(Section{"b", SectionKind::BSS, 8, 9});
  ASSERT_TRUE(First && Second && Bss);

  ASSERT_TRUE(layout(Graph));
  EXPECT_EQ(Graph.sections()[*First].Address, 0U);
  EXPECT_EQ(Graph.sections()[*Second].Address, 4U);
  EXPECT_EQ(Graph.sections()[*Second].FileOffset, 4U);
  EXPECT_EQ(Graph.sections()[*Bss].Address, 8U);
  EXPECT_EQ(Graph.sections()[*Bss].FileOffset, 0U);
  EXPECT_EQ(Graph.sections()[*Bss].Address + Graph.sections()[*Bss].VirtualSize,
            17U);

  ASSERT_TRUE(Graph.setSectionFileOffset(*Bss, 123));
  ASSERT_TRUE(layout(Graph));
  EXPECT_EQ(Graph.sections()[*Second].FileOffset, 4U);
  EXPECT_EQ(Graph.sections()[*Bss].FileOffset, 0U);
}

TEST(LayoutTest, IsIndependentOfInsertionOrderForUniqueNames) {
  auto MakeGraph = [](bool Reverse) {
    LinkGraph Graph(Target::X86_64, Endianness::Little);
    EXPECT_TRUE(Graph.beginInput("input.o"));
    Section A{"a", SectionKind::ReadOnly, 4, 2, 0, 0, {1, 2}};
    Section Z{"z", SectionKind::ReadOnly, 8, 3, 0, 0, {1, 2, 3}};
    EXPECT_TRUE(Graph.addSection(Reverse ? Z : A));
    EXPECT_TRUE(Graph.addSection(Reverse ? A : Z));
    return Graph;
  };
  auto First = MakeGraph(false);
  auto Second = MakeGraph(true);

  ASSERT_TRUE(layout(First));
  ASSERT_TRUE(layout(Second));
  for (const auto &Section : First.sections()) {
    const auto Other = std::find_if(
        Second.sections().begin(), Second.sections().end(),
        [&](const auto &Value) { return Value.Name == Section.Name; });
    ASSERT_NE(Other, Second.sections().end());
    EXPECT_EQ(Other->Address, Section.Address);
    EXPECT_EQ(Other->FileOffset, Section.FileOffset);
  }
}

TEST(LayoutTest, OrdersDuplicateNamesByOriginalOrdinal) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto First =
      Graph.addSection(Section{"same", SectionKind::Text, 1, 2, 0, 0, {1, 2}});
  auto Second =
      Graph.addSection(Section{"same", SectionKind::Text, 4, 1, 0, 0, {1}});
  ASSERT_TRUE(First && Second);

  ASSERT_TRUE(layout(Graph));
  EXPECT_EQ(Graph.sections()[*First].Address, 0U);
  EXPECT_EQ(Graph.sections()[*Second].Address, 4U);
}

TEST(LayoutTest, AppliesNonzeroImageBase) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto Text =
      Graph.addSection(Section{"text", SectionKind::Text, 16, 2, 0, 0, {1, 2}});
  ASSERT_TRUE(Text);

  ASSERT_TRUE(layout(Graph, 0x1003));
  EXPECT_EQ(Graph.sections()[*Text].Address, 0x1010U);
  EXPECT_EQ(Graph.sections()[*Text].FileOffset, 0U);
}

TEST(LayoutTest, IsIdempotent) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  ASSERT_TRUE(Graph.addSection(
      Section{"text", SectionKind::Text, 8, 3, 0, 0, {1, 2, 3}}));
  ASSERT_TRUE(Graph.addSection(Section{"bss", SectionKind::BSS, 16, 7}));
  ASSERT_TRUE(layout(Graph, 0x1000));
  const auto Sections = Graph.sections();

  ASSERT_TRUE(layout(Graph, 0x1000));
  EXPECT_EQ(Graph.sections()[0].Address, Sections[0].Address);
  EXPECT_EQ(Graph.sections()[0].FileOffset, Sections[0].FileOffset);
  EXPECT_EQ(Graph.sections()[1].Address, Sections[1].Address);
  EXPECT_EQ(Graph.sections()[1].FileOffset, Sections[1].FileOffset);
}

TEST(LayoutTest, RejectsAlignmentOverflow) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  ASSERT_TRUE(Graph.addSection(Section{"text", SectionKind::Text, 2, 0}));

  auto Result = layout(Graph, std::numeric_limits<uint64_t>::max());
  ASSERT_FALSE(Result);
  EXPECT_EQ(Result.error().Message, "section address alignment overflows");
  EXPECT_EQ(Result.error().SectionName, "text");
}

TEST(LayoutTest, RejectsSectionSizeAndImageBaseOverflow) {
  LinkGraph SizeGraph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(SizeGraph.beginInput("input.o"));
  ASSERT_TRUE(SizeGraph.addSection(Section{
      "first", SectionKind::Text, 1, std::numeric_limits<uint64_t>::max()}));
  ASSERT_TRUE(SizeGraph.addSection(Section{"second", SectionKind::Text, 1, 1}));
  auto SizeResult = layout(SizeGraph);
  ASSERT_FALSE(SizeResult);
  EXPECT_EQ(SizeResult.error().Message, "section virtual size overflows");
  EXPECT_EQ(SizeResult.error().SectionName, "second");

  LinkGraph BaseGraph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(BaseGraph.beginInput("input.o"));
  ASSERT_TRUE(BaseGraph.addSection(Section{"text", SectionKind::Text, 1, 3}));
  auto BaseResult = layout(BaseGraph, std::numeric_limits<uint64_t>::max() - 1);
  ASSERT_FALSE(BaseResult);
  EXPECT_EQ(BaseResult.error().Message, "section virtual size overflows");
  EXPECT_EQ(BaseResult.error().SectionName, "text");
}

TEST(LayoutTest, RejectsInvalidMutatedGraphBeforeLayout) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  ASSERT_TRUE(Graph.addSection(Section{"text", SectionKind::Text, 1, 0}));
  auto &Sections = const_cast<std::vector<Section> &>(Graph.sections());
  Sections[0].Alignment = 0;

  auto Result = layout(Graph);
  ASSERT_FALSE(Result);
  EXPECT_EQ(Result.error().Message,
            "section alignment must be a non-zero power of two");
}

TEST(LayoutTest, RetainsAllSectionsIncludingEmptySections) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  ASSERT_TRUE(Graph.addSection(Section{"empty", SectionKind::Text, 8, 0}));
  ASSERT_TRUE(Graph.addSection(
      Section{"unused", SectionKind::ReadOnly, 4, 1, 0, 0, {1}}));
  ASSERT_TRUE(Graph.addSection(Section{"zero", SectionKind::BSS, 16, 0}));

  ASSERT_TRUE(layout(Graph));
  ASSERT_EQ(Graph.sections().size(), 3U);
  EXPECT_EQ(Graph.sections()[0].Address, 0U);
  EXPECT_EQ(Graph.sections()[1].Address, 0U);
  EXPECT_EQ(Graph.sections()[2].Address, 16U);
}

TEST(RelocationFieldTest, ReadsAndWritesUnsignedBoundariesWithExactBytes) {
  struct Case {
    uint8_t Width;
    uint64_t Maximum;
  };
  const std::array<Case, 4> Cases{
      {{1, UINT8_MAX}, {2, UINT16_MAX}, {4, UINT32_MAX}, {8, UINT64_MAX}}};
  for (const auto Endian : {Endianness::Little, Endianness::Big}) {
    for (const auto &Test : Cases) {
      for (const uint64_t Value : {UINT64_C(0), Test.Maximum}) {
        std::array<WasmEdge::Byte, 10> Bytes{};
        ASSERT_TRUE(
            Internal::writeUnsigned(Bytes, 1, Test.Width, Endian, Value));
        for (uint8_t I = 0; I < Test.Width; ++I) {
          EXPECT_EQ(Bytes[1 + I], Value == 0 ? 0 : 0xFF);
        }
        auto Read = Internal::readUnsigned(Bytes, 1, Test.Width, Endian);
        ASSERT_TRUE(Read);
        EXPECT_EQ(*Read, Value);
      }
    }
  }
  std::array<WasmEdge::Byte, 4> Bytes{};
  ASSERT_TRUE(Internal::writeUnsigned(Bytes, 0, 4, Endianness::Little,
                                      UINT32_C(0x12345678)));
  EXPECT_EQ(Bytes, (std::array<WasmEdge::Byte, 4>{0x78, 0x56, 0x34, 0x12}));
  ASSERT_TRUE(Internal::writeUnsigned(Bytes, 0, 4, Endianness::Big,
                                      UINT32_C(0x12345678)));
  EXPECT_EQ(Bytes, (std::array<WasmEdge::Byte, 4>{0x12, 0x34, 0x56, 0x78}));
}

TEST(RelocationFieldTest, ReadsAndWritesSignedBoundariesInEitherEndianness) {
  struct Case {
    uint8_t Width;
    int64_t Minimum;
    int64_t Maximum;
  };
  const std::array<Case, 4> Cases{{{1, INT8_MIN, INT8_MAX},
                                   {2, INT16_MIN, INT16_MAX},
                                   {4, INT32_MIN, INT32_MAX},
                                   {8, INT64_MIN, INT64_MAX}}};
  for (const auto &Test : Cases) {
    for (const auto Endian : {Endianness::Little, Endianness::Big}) {
      for (const auto Value : {Test.Minimum, Test.Maximum}) {
        std::array<WasmEdge::Byte, 10> Bytes{};
        ASSERT_TRUE(Internal::writeSigned(Bytes, 1, Test.Width, Endian, Value));
        for (uint8_t I = 0; I < Test.Width; ++I) {
          const bool SignByte =
              Endian == Endianness::Little ? I == Test.Width - 1 : I == 0;
          const uint8_t Expected = Value == Test.Minimum
                                       ? SignByte ? 0x80 : 0x00
                                   : SignByte ? 0x7F
                                              : 0xFF;
          EXPECT_EQ(Bytes[1 + I], Expected);
        }
        auto Read = Internal::readSigned(Bytes, 1, Test.Width, Endian);
        ASSERT_TRUE(Read);
        EXPECT_EQ(*Read, Value);
      }
    }
  }
}

TEST(RelocationFieldTest, AllowsMisalignmentAndRejectsBoundsAndOverflow) {
  std::array<WasmEdge::Byte, 8> Bytes{};
  ASSERT_TRUE(Internal::writeUnsigned(Bytes, 1, 4, Endianness::Little,
                                      UINT32_C(0x12345678)));
  EXPECT_EQ(*Internal::readUnsigned(Bytes, 1, 4, Endianness::Little),
            UINT32_C(0x12345678));
  EXPECT_FALSE(Internal::readUnsigned(Bytes, 0, 3, Endianness::Little));
  EXPECT_FALSE(
      Internal::readUnsigned(Bytes, UINT64_MAX, 1, Endianness::Little));
  for (const uint8_t Width : {1, 2, 4, 8}) {
    const uint64_t Offset = Bytes.size() - Width + 1;
    EXPECT_FALSE(
        Internal::readUnsigned(Bytes, Offset, Width, Endianness::Little));
    EXPECT_FALSE(Internal::readSigned(Bytes, Offset, Width, Endianness::Big));
    EXPECT_FALSE(
        Internal::writeUnsigned(Bytes, Offset, Width, Endianness::Little, 0));
    EXPECT_FALSE(
        Internal::writeSigned(Bytes, Offset, Width, Endianness::Big, 0));
  }
  EXPECT_FALSE(Internal::writeUnsigned(Bytes, 0, 1, Endianness::Little, 256));
  EXPECT_FALSE(Internal::writeSigned(Bytes, 0, 1, Endianness::Little, 128));
  EXPECT_FALSE(Internal::writeSigned(Bytes, 0, 1, Endianness::Little, -129));
  for (const uint8_t Width : {1, 2, 4}) {
    const uint8_t Bits = Width * 8;
    EXPECT_FALSE(Internal::writeUnsigned(Bytes, 0, Width, Endianness::Little,
                                         UINT64_C(1) << Bits));
    const int64_t Maximum = (INT64_C(1) << (Bits - 1)) - 1;
    const int64_t Minimum = -(INT64_C(1) << (Bits - 1));
    EXPECT_FALSE(
        Internal::writeSigned(Bytes, 0, Width, Endianness::Big, Maximum + 1));
    EXPECT_FALSE(
        Internal::writeSigned(Bytes, 0, Width, Endianness::Big, Minimum - 1));
  }
}

LinkGraph makeRelocationGraph(uint32_t Type, int64_t Addend,
                              bool Implicit = false,
                              uint64_t TargetAddress = 0x1100,
                              uint64_t PatchAddress = 0x1000,
                              ObjectFormat Format = ObjectFormat::ELF) {
  LinkGraph Graph(Target::X86_64, Endianness::Little);
  EXPECT_TRUE(Graph.beginInput("input.o"));
  auto Patch = Graph.addSection(Section{
      ".text", SectionKind::Text, 1, 24, PatchAddress, 0, {0, 0, 0, 0, 0, 0,
                                                           0, 0, 0, 0, 0, 0,
                                                           0, 0, 0, 0, 0, 0,
                                                           0, 0, 0, 0, 0, 0}});
  auto TargetSection = Graph.addSection(
      Section{".data", SectionKind::Data, 1, 1, TargetAddress, 0, {0}});
  EXPECT_TRUE(Patch && TargetSection);
  auto TargetSymbol =
      Graph.addSymbol(Symbol{"target", *TargetSection, 0, 1, false});
  EXPECT_TRUE(TargetSymbol);
  Relocation Value{*Patch, 1, Type, *TargetSymbol, Addend, Implicit, Format};
  Value.PatchSize = Type == 1 ? 8 : 4;
  EXPECT_TRUE(Graph.addRelocation(Value));
  return Graph;
}

void expectGraphStateEquals(const LinkGraph &Actual,
                            const LinkGraph &Expected) {
  EXPECT_EQ(Actual.target(), Expected.target());
  EXPECT_EQ(Actual.endianness(), Expected.endianness());
  EXPECT_EQ(Actual.relocationsApplied(), Expected.relocationsApplied());
  ASSERT_EQ(Actual.sections().size(), Expected.sections().size());
  for (size_t I = 0; I < Actual.sections().size(); ++I) {
    const auto &Left = Actual.sections()[I];
    const auto &Right = Expected.sections()[I];
    EXPECT_EQ(Left.Name, Right.Name);
    EXPECT_EQ(Left.Kind, Right.Kind);
    EXPECT_EQ(Left.Alignment, Right.Alignment);
    EXPECT_EQ(Left.VirtualSize, Right.VirtualSize);
    EXPECT_EQ(Left.Address, Right.Address);
    EXPECT_EQ(Left.FileOffset, Right.FileOffset);
    EXPECT_EQ(Left.Content, Right.Content);
  }
  ASSERT_EQ(Actual.symbols().size(), Expected.symbols().size());
  for (size_t I = 0; I < Actual.symbols().size(); ++I) {
    const auto &Left = Actual.symbols()[I];
    const auto &Right = Expected.symbols()[I];
    EXPECT_EQ(Left.Name, Right.Name);
    EXPECT_EQ(Left.Section, Right.Section);
    EXPECT_EQ(Left.Offset, Right.Offset);
    EXPECT_EQ(Left.Size, Right.Size);
    EXPECT_EQ(Left.Exported, Right.Exported);
    EXPECT_EQ(Left.ExportName, Right.ExportName);
  }
  ASSERT_EQ(Actual.relocations().size(), Expected.relocations().size());
  for (size_t I = 0; I < Actual.relocations().size(); ++I) {
    const auto &Left = Actual.relocations()[I];
    const auto &Right = Expected.relocations()[I];
    EXPECT_EQ(Left.Section, Right.Section);
    EXPECT_EQ(Left.Offset, Right.Offset);
    EXPECT_EQ(Left.Type, Right.Type);
    EXPECT_EQ(Left.Symbol, Right.Symbol);
    EXPECT_EQ(Left.Addend, Right.Addend);
    EXPECT_EQ(Left.AddendIsImplicit, Right.AddendIsImplicit);
    EXPECT_EQ(Left.Format, Right.Format);
    EXPECT_EQ(Left.PatchSize, Right.PatchSize);
    EXPECT_EQ(Left.PCRelative, Right.PCRelative);
    EXPECT_EQ(Left.External, Right.External);
    EXPECT_EQ(Left.Scattered, Right.Scattered);
  }
  ASSERT_EQ(Actual.rebases().size(), Expected.rebases().size());
  for (size_t I = 0; I < Actual.rebases().size(); ++I) {
    const auto &Left = Actual.rebases()[I];
    const auto &Right = Expected.rebases()[I];
    EXPECT_EQ(Left.Section, Right.Section);
    EXPECT_EQ(Left.Offset, Right.Offset);
    EXPECT_EQ(Left.Type, Right.Type);
    EXPECT_EQ(Left.Addend, Right.Addend);
    EXPECT_EQ(Left.Width, Right.Width);
    EXPECT_EQ(Left.Format, Right.Format);
  }
}

TEST(RelocationTest, AppliesX86_64AbsoluteAndRecordsOneRebase) {
  auto Graph = makeRelocationGraph(1, 5);
  ASSERT_TRUE(applyRelocations(Graph));
  auto Value = Internal::readUnsigned(Graph.sections()[0].Content, 1, 8,
                                      Endianness::Little);
  ASSERT_TRUE(Value);
  EXPECT_EQ(*Value, 0x1105U);
  ASSERT_EQ(Graph.rebases().size(), 1U);
  EXPECT_EQ(Graph.rebases()[0].Section, 0U);
  EXPECT_EQ(Graph.rebases()[0].Offset, 1U);
  EXPECT_EQ(Graph.rebases()[0].Width, 8U);
  EXPECT_EQ(Graph.rebases()[0].Type, 1U);
  EXPECT_EQ(Graph.rebases()[0].Format, ObjectFormat::ELF);
  const auto Snapshot = Graph;
  EXPECT_FALSE(applyRelocations(Graph));
  expectGraphStateEquals(Graph, Snapshot);
}

TEST(RelocationTest, RejectsBigEndianX86_64WithoutMutation) {
  LinkGraph Graph(Target::X86_64, Endianness::Big);
  ASSERT_TRUE(Graph.beginInput("input.o"));
  auto DataSection = Graph.addSection(Section{
      ".data", SectionKind::Data, 1, 8, 0x1000, 0, {1, 2, 3, 4, 5, 6, 7, 8}});
  ASSERT_TRUE(DataSection);
  auto TargetSymbol =
      Graph.addSymbol(Symbol{"target", *DataSection, 0, 8, false});
  ASSERT_TRUE(TargetSymbol);
  ASSERT_TRUE(Graph.addRelocation(Relocation{*DataSection, 0, 1, *TargetSymbol,
                                             0, false, ObjectFormat::ELF}));
  const auto Content = Graph.sections()[0].Content;
  EXPECT_FALSE(applyRelocations(Graph));
  EXPECT_EQ(Graph.sections()[0].Content, Content);
  EXPECT_TRUE(Graph.rebases().empty());
  EXPECT_FALSE(Graph.relocationsApplied());
}

TEST(RelocationTest, ChecksX86_64AbsoluteOverflowAndUnderflow) {
  for (const auto &[Address, Addend] :
       std::array<std::pair<uint64_t, int64_t>, 2>{
           {{0, -1}, {UINT64_MAX, 1}}}) {
    auto Graph = makeRelocationGraph(1, Addend, false, Address);
    const auto Content = Graph.sections()[0].Content;
    EXPECT_FALSE(applyRelocations(Graph));
    EXPECT_EQ(Graph.sections()[0].Content, Content);
    EXPECT_TRUE(Graph.rebases().empty());
  }
}

TEST(RelocationTest, ChecksPC32AndPLT32SignedBoundaries) {
  struct Case {
    int64_t Displacement;
    bool Accepted;
  };
  const std::array<Case, 6> Cases{{{INT32_MIN, true},
                                   {INT32_MAX, true},
                                   {static_cast<int64_t>(INT32_MIN) - 1, false},
                                   {static_cast<int64_t>(INT32_MAX) + 1, false},
                                   {-256, true},
                                   {256, true}}};
  constexpr uint64_t PatchAddress = UINT64_C(0x100000000);
  constexpr uint64_t Place = PatchAddress + 1;
  for (const uint32_t Type : {2U, 4U}) {
    for (const auto &Test : Cases) {
      const uint64_t Target =
          Test.Displacement < 0
              ? Place - static_cast<uint64_t>(-Test.Displacement)
              : Place + static_cast<uint64_t>(Test.Displacement);
      auto Graph = makeRelocationGraph(Type, 0, false, Target, PatchAddress);
      auto Result = applyRelocations(Graph);
      EXPECT_EQ(static_cast<bool>(Result), Test.Accepted);
      if (Test.Accepted) {
        auto Value = Internal::readSigned(Graph.sections()[0].Content, 1, 4,
                                          Endianness::Little);
        ASSERT_TRUE(Value);
        EXPECT_EQ(*Value, Test.Displacement);
      }
    }
  }
}

TEST(RelocationTest, AppliesExplicitAndImplicitPC32AndPLT32) {
  struct Case {
    uint32_t Type;
    int64_t Addend;
    bool Implicit;
    uint64_t Target;
    int32_t Expected;
  };
  const std::array<Case, 4> Cases{{{2, -4, false, 0x1100, 0xFB},
                                   {4, -4, false, 0x0F00, -0x105},
                                   {2, 0, true, 0x1100, 0xFB},
                                   {4, 0, true, 0x0F00, -0x105}}};
  for (const auto &Test : Cases) {
    auto Graph =
        makeRelocationGraph(Test.Type, Test.Addend, Test.Implicit, Test.Target);
    if (Test.Implicit) {
      auto Content = Graph.sectionContent(0);
      ASSERT_TRUE(Content);
      ASSERT_TRUE(
          Internal::writeSigned(*Content, 1, 4, Endianness::Little, -4));
    }
    ASSERT_TRUE(applyRelocations(Graph));
    auto Value = Internal::readSigned(Graph.sections()[0].Content, 1, 4,
                                      Endianness::Little);
    ASSERT_TRUE(Value);
    EXPECT_EQ(*Value, Test.Expected);
  }
}

TEST(RelocationTest, DecodesImplicitAddendForX86_64Absolute) {
  auto Graph = makeRelocationGraph(1, 0, true);
  auto Content = Graph.sectionContent(0);
  ASSERT_TRUE(Content);
  ASSERT_TRUE(Internal::writeSigned(*Content, 1, 8, Endianness::Little, -5));
  ASSERT_TRUE(applyRelocations(Graph));
  auto Value = Internal::readUnsigned(Graph.sections()[0].Content, 1, 8,
                                      Endianness::Little);
  ASSERT_TRUE(Value);
  EXPECT_EQ(*Value, 0x10FBU);
}

TEST(RelocationTest, RejectsOverflowAndDoesNotPartiallyModifyGraph) {
  auto Graph = makeRelocationGraph(1, 5);
  auto FarSection = Graph.addSection(Section{
      ".far", SectionKind::Data, 1, 1, UINT64_C(0x8000000000000001), 0, {0}});
  ASSERT_TRUE(FarSection);
  auto SecondSymbol =
      Graph.addSymbol(Symbol{"second", *FarSection, 0, 1, false});
  ASSERT_TRUE(SecondSymbol);
  ASSERT_TRUE(Graph.addRelocation(Relocation{0, 12, 1, *SecondSymbol, INT64_MAX,
                                             false, ObjectFormat::ELF, 8}));
  const auto Snapshot = Graph;
  auto Result = applyRelocations(Graph);
  EXPECT_FALSE(Result);
  expectGraphStateEquals(Graph, Snapshot);
}

TEST(RelocationTest, RejectsGeneratedRebaseOverlappingExistingRebase) {
  auto Graph = makeRelocationGraph(1, 5);
  ASSERT_TRUE(Graph.addRebase(Rebase{0, 4, 1, 0, 8}));
  const auto Snapshot = Graph;
  EXPECT_FALSE(applyRelocations(Graph));
  expectGraphStateEquals(Graph, Snapshot);
}

TEST(RelocationTest, RejectsInvalidGraphUnsupportedTargetTypeAndFormat) {
  auto InvalidSection = makeRelocationGraph(2, -4);
  const_cast<std::vector<Relocation> &>(InvalidSection.relocations())[0]
      .Section = InvalidSectionId;
  EXPECT_FALSE(applyRelocations(InvalidSection));

  auto InvalidSymbol = makeRelocationGraph(2, -4);
  const_cast<std::vector<Relocation> &>(InvalidSymbol.relocations())[0].Symbol =
      InvalidSymbolId;
  EXPECT_FALSE(applyRelocations(InvalidSymbol));

  LinkGraph UnsupportedTarget(Target::AArch64, Endianness::Little);
  ASSERT_TRUE(UnsupportedTarget.beginInput("input.o"));
  EXPECT_FALSE(applyRelocations(UnsupportedTarget));

  auto UnsupportedType = makeRelocationGraph(0xFFFF, 0);
  EXPECT_FALSE(applyRelocations(UnsupportedType));
  auto UnsupportedFormat =
      makeRelocationGraph(2, -4, false, 0x1100, 0x1000, ObjectFormat::COFF);
  EXPECT_FALSE(applyRelocations(UnsupportedFormat));
}

TEST(RelocationTest, RelaxesX86_64RexGotpcrelxForDefinedSymbol) {
  auto Graph = makeRelocationGraph(42, -4);
  auto Content = Graph.sectionContent(0);
  ASSERT_TRUE(Content);
  auto &RelocationValue =
      const_cast<std::vector<Relocation> &>(Graph.relocations())[0];
  RelocationValue.PatchSize = 4;
  (*Content)[0] = 0x48;
  (*Content)[1] = 0x8B;
  (*Content)[2] = 0x05;
  RelocationValue.Offset = 3;
  ASSERT_TRUE(applyRelocations(Graph));
  EXPECT_EQ(Graph.sections()[0].Content[1], 0x8DU);
  auto Value = Internal::readSigned(Graph.sections()[0].Content, 3, 4,
                                    Endianness::Little);
  ASSERT_TRUE(Value);
  EXPECT_EQ(*Value, 0xF9);
}

TEST(RelocationTest, ValidatesGotpcrelxInstructionAndAddend) {
  struct Case {
    uint32_t Type;
    int64_t Addend;
    std::array<WasmEdge::Byte, 3> Prefix;
    uint64_t Offset;
    bool Accepted;
  };
  const std::array<Case, 7> Cases{{
      {41, -4, {0, 0x8B, 0x05}, 3, true},
      {42, -4, {0x48, 0x8B, 0x05}, 3, true},
      {42, 0, {0x48, 0x8B, 0x05}, 3, false},
      {42, -4, {0x48, 0x89, 0x05}, 3, false},
      {42, -4, {0x48, 0x8B, 0x04}, 3, false},
      {42, -4, {0x90, 0x8B, 0x05}, 3, false},
      {41, -4, {0x8B, 0x05, 0x90}, 2, true},
  }};
  for (const auto &Test : Cases) {
    auto Graph = makeRelocationGraph(Test.Type, Test.Addend);
    auto Content = Graph.sectionContent(0);
    ASSERT_TRUE(Content);
    std::copy(Test.Prefix.begin(), Test.Prefix.end(), Content->begin());
    auto &RelocationValue =
        const_cast<std::vector<Relocation> &>(Graph.relocations())[0];
    RelocationValue.Offset = Test.Offset;
    RelocationValue.PatchSize = 4;
    EXPECT_EQ(static_cast<bool>(applyRelocations(Graph)), Test.Accepted);
  }
}

TEST(RelocationTest, RelaxesExactGotpcrelxIndirectCallAndJump) {
  struct Case {
    WasmEdge::Byte ModRM;
    std::array<WasmEdge::Byte, 6> ExpectedPrefixAndPatch;
  };
  const std::array<Case, 2> Cases{{
      {0x15, {0x67, 0xE8, 0xFA, 0x00, 0x00, 0x00}},
      {0x25, {0xE9, 0xFB, 0x00, 0x00, 0x00, 0x90}},
  }};
  for (const auto &Test : Cases) {
    auto Graph = makeRelocationGraph(41, -4);
    auto Content = Graph.sectionContent(0);
    ASSERT_TRUE(Content);
    (*Content)[0] = 0xFF;
    (*Content)[1] = Test.ModRM;
    auto &RelocationValue =
        const_cast<std::vector<Relocation> &>(Graph.relocations())[0];
    RelocationValue.Offset = 2;
    RelocationValue.PatchSize = 4;
    ASSERT_TRUE(applyRelocations(Graph));
    EXPECT_TRUE(std::equal(Test.ExpectedPrefixAndPatch.begin(),
                           Test.ExpectedPrefixAndPatch.end(),
                           Graph.sections()[0].Content.begin()));
  }
}

TEST(RelocationTest, RejectsGotpcrelxIndirectBranchAboveUint32) {
  auto Graph = makeRelocationGraph(41, -4, false, UINT64_C(0x100000100),
                                   UINT64_C(0x100000000));
  auto Content = Graph.sectionContent(0);
  ASSERT_TRUE(Content);
  (*Content)[0] = 0xFF;
  (*Content)[1] = 0x15;
  auto &RelocationValue =
      const_cast<std::vector<Relocation> &>(Graph.relocations())[0];
  RelocationValue.Offset = 2;
  RelocationValue.PatchSize = 4;
  EXPECT_FALSE(applyRelocations(Graph));
}

TEST(RelocationTest, RejectsMutationAndLayoutAfterRelocation) {
  auto Graph = makeRelocationGraph(2, -4);
  ASSERT_TRUE(applyRelocations(Graph));
  const auto ExpectRelocated = [](const auto &Result) {
    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Message, "link graph relocations already applied");
  };
  ExpectRelocated(Graph.beginInput("again.o"));
  ExpectRelocated(Graph.addSection(Section{"new", SectionKind::Data, 1, 0}));
  ExpectRelocated(Graph.addSymbol(Symbol{"new", 0, 0, 0, false}));
  ExpectRelocated(Graph.addRelocation(Relocation{0, 8, 2, 0, -4}));
  ExpectRelocated(Graph.addRebase(Rebase{0, 8, 1, 0, 8}));
  ExpectRelocated(Graph.setSectionAddress(0, 3));
  ExpectRelocated(Graph.setSectionFileOffset(0, 3));
  ExpectRelocated(Graph.sectionContent(0));
  auto LayoutResult = layout(Graph);
  ASSERT_FALSE(LayoutResult);
  EXPECT_EQ(LayoutResult.error().Message, "cannot layout relocated link graph");
}

TEST(RelocationTest, ReadsLayoutsAndRelocatesX86_64ObjectEndToEnd) {
  auto Graph = ObjectReader::read(
      makeObject(llvm::Triple("x86_64-unknown-linux-gnu")), Target::X86_64);
  ASSERT_TRUE(Graph);
  ASSERT_TRUE(layout(*Graph, 0x1000));
  ASSERT_TRUE(applyRelocations(*Graph));
  const auto Text =
      std::find_if(Graph->sections().begin(), Graph->sections().end(),
                   [](const Section &Value) { return Value.Name == ".text"; });
  ASSERT_NE(Text, Graph->sections().end());
  ASSERT_GE(Text->Content.size(), 7U);
  EXPECT_EQ(Text->Content[1], 0x8DU);
  auto Displacement =
      Internal::readSigned(Text->Content, 3, 4, Endianness::Little);
  ASSERT_TRUE(Displacement);
  const auto &Relocation = Graph->relocations()[0];
  const auto &Symbol = Graph->symbols()[Relocation.Symbol];
  EXPECT_EQ(*Displacement,
            static_cast<int64_t>(Graph->sections()[Symbol.Section].Address +
                                 Symbol.Offset) -
                static_cast<int64_t>(Text->Address + Relocation.Offset) - 4);
}

TEST(RelocationTest, AppliesGeneratedELF64PC32AndPLT32RelocationsExactly) {
  auto Graph = ObjectReader::read(
      makeX86_64AssemblyObject(
          ".data\n.globl target_data\ntarget_data:\n.quad 0\n"
          ".globl absolute\nabsolute:\n.quad target_data + 5\n"
          ".text\n.globl caller\ncaller:\n"
          "movl target_data(%rip), %eax\ncall target_func\nret\n"
          ".section .text.target,\"ax\",@progbits\n"
          ".globl target_func\ntarget_func:\nret\n"),
      Target::X86_64);
  ASSERT_TRUE(Graph);
  ASSERT_EQ(Graph->relocations().size(), 3U);
  std::array<bool, 3> Seen{};
  for (const auto &Relocation : Graph->relocations()) {
    ASSERT_TRUE(Relocation.Type == 1 || Relocation.Type == 2 ||
                Relocation.Type == 4);
    Seen[Relocation.Type == 1 ? 0 : Relocation.Type == 2 ? 1 : 2] = true;
    EXPECT_EQ(Relocation.Format, ObjectFormat::ELF);
    EXPECT_EQ(Relocation.PatchSize, Relocation.Type == 1 ? 8U : 4U);
    EXPECT_EQ(Relocation.PCRelative, Relocation.Type != 1);
    EXPECT_FALSE(Relocation.AddendIsImplicit);
    EXPECT_EQ(Relocation.Addend, Relocation.Type == 1 ? 5 : -4);
  }
  EXPECT_EQ(Seen, (std::array<bool, 3>{true, true, true}));
  ASSERT_TRUE(layout(*Graph, 0x1000));
  struct ExpectedPatch {
    SectionId Section;
    uint64_t Offset;
    uint8_t Width;
    uint64_t Bits;
  };
  std::vector<ExpectedPatch> Expected;
  for (const auto &Relocation : Graph->relocations()) {
    const auto &Symbol = Graph->symbols()[Relocation.Symbol];
    const uint64_t S =
        Graph->sections()[Symbol.Section].Address + Symbol.Offset;
    const uint64_t P =
        Graph->sections()[Relocation.Section].Address + Relocation.Offset;
    Expected.push_back(ExpectedPatch{
        Relocation.Section, Relocation.Offset,
        static_cast<uint8_t>(Relocation.Type == 1 ? 8 : 4),
        Relocation.Type == 1 ? S + static_cast<uint64_t>(Relocation.Addend)
                             : static_cast<uint32_t>(static_cast<int64_t>(S) +
                                                     Relocation.Addend -
                                                     static_cast<int64_t>(P))});
  }
  ASSERT_TRUE(applyRelocations(*Graph));
  for (const auto &Patch : Expected) {
    auto Value =
        Internal::readUnsigned(Graph->sections()[Patch.Section].Content,
                               Patch.Offset, Patch.Width, Endianness::Little);
    ASSERT_TRUE(Value);
    EXPECT_EQ(*Value, Patch.Bits);
  }
  ASSERT_EQ(Graph->rebases().size(), 1U);
  EXPECT_EQ(Graph->rebases()[0].Width, 8U);
}

TEST(RelocationTest, ReadsLayoutsAndRelocatesCurrentMachOAndCOFFForms) {
  struct Case {
    llvm::Triple Triple;
    ObjectFormat Format;
    uint32_t Type;
  };
  const std::array<Case, 2> Cases{
      {{llvm::Triple("x86_64-apple-macosx"), ObjectFormat::MachO, 1},
       {llvm::Triple("x86_64-pc-windows-msvc"), ObjectFormat::COFF, 4}}};
  for (const auto &Test : Cases) {
    auto Graph = ObjectReader::read(makeObject(Test.Triple), Target::X86_64);
    ASSERT_TRUE(Graph);
    ASSERT_EQ(Graph->relocations().size(), 1U);
    EXPECT_EQ(Graph->relocations()[0].Format, Test.Format);
    EXPECT_EQ(Graph->relocations()[0].Type, Test.Type);
    EXPECT_EQ(Graph->relocations()[0].PatchSize, 4U);
    EXPECT_TRUE(Graph->relocations()[0].PCRelative);
    ASSERT_TRUE(layout(*Graph, 0x1000));
    const auto &Relocation = Graph->relocations()[0];
    const auto &Symbol = Graph->symbols()[Relocation.Symbol];
    const int64_t S = static_cast<int64_t>(
        Graph->sections()[Symbol.Section].Address + Symbol.Offset);
    const int64_t P = static_cast<int64_t>(
        Graph->sections()[Relocation.Section].Address + Relocation.Offset);
    auto Before =
        Internal::readSigned(Graph->sections()[Relocation.Section].Content,
                             Relocation.Offset, 4, Endianness::Little);
    ASSERT_TRUE(Before);
    ASSERT_TRUE(applyRelocations(*Graph));
    auto After =
        Internal::readSigned(Graph->sections()[Relocation.Section].Content,
                             Relocation.Offset, 4, Endianness::Little);
    ASSERT_TRUE(After);
    EXPECT_EQ(*After,
              S + *Before - P + (Test.Format == ObjectFormat::COFF ? -4 : 0));
  }
}

TEST(ObjectReaderTest, RejectsMalformedBytes) {
  const std::vector<WasmEdge::Byte> Bytes{0x01, 0x02, 0x03, 0x04};
  EXPECT_FALSE(ObjectReader::read(Bytes, Target::X86_64));
}

TEST(ObjectReaderTest, NormalizesZeroSectionAlignment) {
  EXPECT_EQ(Internal::normalizeSectionAlignment(0), 1U);
  EXPECT_EQ(Internal::normalizeSectionAlignment(16), 16U);
}

TEST(ObjectReaderTest, ParsesCOFFExportDirectives) {
  auto Exports = Internal::parseCOFFExports(
      " /DEFAULTLIB:libcmt /EXPORT:f0 /EXPORT:data,DATA "
      "/EXPORT:ordinal,NONAME /EXPORT:alias=real");
  ASSERT_TRUE(Exports);
  EXPECT_EQ(Exports->at("alias"), "real");
  EXPECT_EQ(Exports->at("data"), "data");
  EXPECT_EQ(Exports->at("f0"), "f0");
  EXPECT_EQ(Exports->at("ordinal"), "ordinal");
}

TEST(ObjectReaderTest, RejectsMalformedCOFFExportDirectives) {
  EXPECT_FALSE(Internal::parseCOFFExports("/EXPORT:"));
  EXPECT_FALSE(Internal::parseCOFFExports("\"/EXPORT:f0"));
}

TEST(ObjectReaderTest, NormalizesX86_64ELFRelaObject) {
  const auto Bytes = makeObject(llvm::Triple("x86_64-unknown-linux-gnu"));
  auto Result = ObjectReader::read(Bytes, Target::X86_64);
  ASSERT_TRUE(Result);
  EXPECT_EQ(Result->target(), Target::X86_64);
  EXPECT_EQ(Result->endianness(), Endianness::Little);
  EXPECT_FALSE(Result->sections().empty());
  const auto Text =
      std::find_if(Result->sections().begin(), Result->sections().end(),
                   [](const Section &Value) { return Value.Name == ".text"; });
  ASSERT_NE(Text, Result->sections().end());
  EXPECT_EQ(Text->Kind, SectionKind::Text);
  EXPECT_EQ(Text->VirtualSize, Text->Content.size());
  EXPECT_GT(Text->Alignment, 0U);
  const auto Bss = std::find_if(
      Result->sections().begin(), Result->sections().end(),
      [](const Section &Value) { return Value.Kind == SectionKind::BSS; });
  ASSERT_NE(Bss, Result->sections().end());
  EXPECT_TRUE(Bss->Content.empty());
  EXPECT_GE(Bss->VirtualSize, 4U);
  EXPECT_GE(Bss->Alignment, 16U);
  const auto F0 =
      std::find_if(Result->symbols().begin(), Result->symbols().end(),
                   [](const Symbol &Value) { return Value.Name == "f0"; });
  ASSERT_NE(F0, Result->symbols().end());
  const auto TextId = static_cast<SectionId>(Text - Result->sections().begin());
  const auto F0Id = static_cast<SymbolId>(F0 - Result->symbols().begin());
  EXPECT_EQ(F0->Section, TextId);
  EXPECT_EQ(F0->Offset, 0U);
  EXPECT_TRUE(F0->Exported);
  EXPECT_GT(F0->Size, 0U);
  ASSERT_FALSE(Result->relocations().empty());
  const auto &Relocation = Result->relocations()[0];
  EXPECT_EQ(Relocation.Section, TextId);
  EXPECT_LT(Relocation.Offset, Text->Content.size());
  EXPECT_NE(Relocation.Type, 0U);
  EXPECT_LT(Relocation.Symbol, Result->symbols().size());
  EXPECT_EQ(Relocation.Offset, 3U);
  EXPECT_EQ(Relocation.Type, 42U);
  EXPECT_EQ(Relocation.Format, ObjectFormat::ELF);
  EXPECT_EQ(Relocation.PatchSize, 4U);
  EXPECT_TRUE(Relocation.PCRelative);
  EXPECT_EQ(Result->symbols()[Relocation.Symbol].Name, "value");
  EXPECT_EQ(Relocation.Addend, -4);
  EXPECT_FALSE(Relocation.AddendIsImplicit);
  EXPECT_NE(Relocation.Symbol, F0Id);
}

TEST(ObjectReaderTest, ReadsCOFFExportsFromDirectives) {
  auto Result = ObjectReader::read(
      makeObject(llvm::Triple("x86_64-pc-windows-msvc"), false, true),
      Target::X86_64);
  ASSERT_TRUE(Result);
  const auto F0 =
      std::find_if(Result->symbols().begin(), Result->symbols().end(),
                   [](const Symbol &Value) { return Value.Name == "f0"; });
  ASSERT_NE(F0, Result->symbols().end());
  EXPECT_TRUE(F0->Exported);
}

TEST(ObjectReaderTest, NormalizesRenamedCOFFExport) {
  auto Result =
      ObjectReader::read(makeObject(llvm::Triple("x86_64-pc-windows-msvc"),
                                    false, false, "real", "/EXPORT:alias=real"),
                         Target::X86_64);
  ASSERT_TRUE(Result);
  const auto Real =
      std::find_if(Result->symbols().begin(), Result->symbols().end(),
                   [](const Symbol &Value) { return Value.Name == "real"; });
  ASSERT_NE(Real, Result->symbols().end());
  EXPECT_TRUE(Real->Exported);
  ASSERT_TRUE(Real->ExportName);
  EXPECT_EQ(*Real->ExportName, "alias");
}

TEST(ObjectReaderTest, ExportsMachOExternalDefinedSymbols) {
  auto Result = ObjectReader::read(
      makeObject(llvm::Triple("x86_64-apple-macosx")), Target::X86_64);
  ASSERT_TRUE(Result);
  const auto F0 =
      std::find_if(Result->symbols().begin(), Result->symbols().end(),
                   [](const Symbol &Value) { return Value.Name == "_f0"; });
  ASSERT_NE(F0, Result->symbols().end());
  EXPECT_TRUE(F0->Exported);
  ASSERT_EQ(Result->relocations().size(), 1U);
  EXPECT_TRUE(Result->relocations()[0].PCRelative);
  EXPECT_EQ(Result->relocations()[0].PatchSize, 4U);
  EXPECT_TRUE(Result->relocations()[0].External);
  EXPECT_FALSE(Result->relocations()[0].Scattered);
}

TEST(ObjectReaderTest, RejectsMalformedX86_64MachOSignedMetadata) {
  auto Bytes = makeObject(llvm::Triple("x86_64-apple-macosx"));
  auto Object =
      llvm::object::ObjectFile::createObjectFile(llvm::MemoryBufferRef(
          llvm::StringRef(reinterpret_cast<const char *>(Bytes.data()),
                          Bytes.size()),
          "test.o"));
  ASSERT_TRUE(static_cast<bool>(Object));
  const auto *MachO = llvm::dyn_cast<llvm::object::MachOObjectFile>(&**Object);
  ASSERT_NE(MachO, nullptr);
  size_t RelocationOffset = 0;
  for (const auto &Section : MachO->sections()) {
    if (Section.relocation_begin() != Section.relocation_end()) {
      const auto Ref = Section.relocation_begin()->getRawDataRefImpl();
      llvm::object::DataRefImpl SectionRef;
      SectionRef.d.a = Ref.d.a;
      RelocationOffset = MachO->getSection64(SectionRef).reloff + Ref.d.b * 8;
      break;
    }
  }
  ASSERT_NE(RelocationOffset, 0U);
  for (const uint32_t Mask : {UINT32_C(1) << 24, UINT32_C(1) << 25}) {
    auto Malformed = Bytes;
    uint32_t Word = 0;
    std::memcpy(&Word, Malformed.data() + RelocationOffset + 4, sizeof(Word));
    Word ^= Mask;
    std::memcpy(Malformed.data() + RelocationOffset + 4, &Word, sizeof(Word));
    EXPECT_FALSE(ObjectReader::read(Malformed, Target::X86_64));
  }
  auto Scattered = Bytes;
  uint32_t AddressWord = 0;
  std::memcpy(&AddressWord, Scattered.data() + RelocationOffset,
              sizeof(AddressWord));
  AddressWord |= UINT32_C(1) << 31;
  std::memcpy(Scattered.data() + RelocationOffset, &AddressWord,
              sizeof(AddressWord));
  EXPECT_FALSE(ObjectReader::read(Scattered, Target::X86_64));
}

TEST(ObjectReaderTest, DoesNotExportHiddenMachOSymbols) {
  auto Result =
      ObjectReader::read(makeObject(llvm::Triple("x86_64-apple-macosx"), false,
                                    false, "hidden", {}, true),
                         Target::X86_64);
  ASSERT_TRUE(Result);
  const auto Hidden =
      std::find_if(Result->symbols().begin(), Result->symbols().end(),
                   [](const Symbol &Value) { return Value.Name == "_hidden"; });
  ASSERT_NE(Hidden, Result->symbols().end());
  EXPECT_FALSE(Hidden->Exported);
}

TEST(ObjectReaderTest, RejectsELFRelocationWithInvalidSectionLink) {
  auto Bytes = makeObject(llvm::Triple("x86_64-unknown-linux-gnu"));
  const auto Header = elf64RelocationSectionHeader(Bytes);
  Bytes[Header + 40] = 0xFF;
  Bytes[Header + 41] = 0xFF;
  Bytes[Header + 42] = 0xFF;
  Bytes[Header + 43] = 0x7F;
  EXPECT_FALSE(ObjectReader::read(Bytes, Target::X86_64));
}

TEST(ObjectReaderTest, RejectsELFRelocationWithZeroEntrySize) {
  auto Bytes = makeObject(llvm::Triple("x86_64-unknown-linux-gnu"));
  const auto Header = elf64RelocationSectionHeader(Bytes);
  write64le(Bytes, Header + 56, 0);
  EXPECT_FALSE(ObjectReader::read(Bytes, Target::X86_64));
}

TEST(ObjectReaderTest, RejectsTruncatedELFRelocationTable) {
  auto Bytes = makeObject(llvm::Triple("x86_64-unknown-linux-gnu"));
  const auto Header = elf64RelocationSectionHeader(Bytes);
  write64le(Bytes, Header + 32, read64le(Bytes, Header + 32) - 1);
  EXPECT_FALSE(ObjectReader::read(Bytes, Target::X86_64));
}

TEST(ObjectReaderTest, RejectsELFRelocationWithInvalidSymbolIndex) {
  auto Bytes = makeObject(llvm::Triple("x86_64-unknown-linux-gnu"));
  const auto Header = elf64RelocationSectionHeader(Bytes);
  const auto RelocationOffset = read64le(Bytes, Header + 24);
  write64le(Bytes, RelocationOffset + 8, UINT64_C(0xFFFFFFFF00000000));
  EXPECT_FALSE(ObjectReader::read(Bytes, Target::X86_64));
}

#if LLVM_VERSION_MAJOR >= 19
TEST(ObjectReaderTest, NormalizesELFCrelRelocation) {
  auto Result = ObjectReader::read(makeX86_64CrelObject(), Target::X86_64);
  ASSERT_TRUE(Result);
  ASSERT_EQ(Result->relocations().size(), 1U);
  EXPECT_EQ(Result->relocations()[0].Offset, 3U);
  EXPECT_EQ(Result->relocations()[0].Type, 42U);
  EXPECT_EQ(Result->relocations()[0].Addend, -4);
  EXPECT_FALSE(Result->relocations()[0].AddendIsImplicit);
}

TEST(ObjectReaderTest, RejectsTruncatedELFCrelRelocation) {
  auto Bytes = makeX86_64CrelObject();
  const auto Header = elf64RelocationSectionHeader(Bytes);
  write64le(Bytes, Header + 32, 1);
  EXPECT_FALSE(ObjectReader::read(Bytes, Target::X86_64));
}
#endif

TEST(ObjectReaderTest, MarksELFRelAddendsImplicit) {
  auto Result = ObjectReader::read(
      makeObject(llvm::Triple("armv7-unknown-linux-gnueabihf")), Target::ARM);
  ASSERT_TRUE(Result);
  ASSERT_FALSE(Result->relocations().empty());
  EXPECT_TRUE(Result->relocations()[0].AddendIsImplicit);
  EXPECT_EQ(Result->relocations()[0].Addend, 0);
}

TEST(ObjectReaderTest, RejectsNonRelocatableELFObject) {
  auto Bytes = makeObject(llvm::Triple("x86_64-unknown-linux-gnu"));
  ASSERT_GT(Bytes.size(), 18U);
  Bytes[16] = 3;
  Bytes[17] = 0;
  EXPECT_FALSE(ObjectReader::read(Bytes, Target::X86_64));
  Bytes[16] = 2;
  EXPECT_FALSE(ObjectReader::read(Bytes, Target::X86_64));
}

TEST(ObjectReaderTest, RejectsUnsupportedObjectFormat) {
  EXPECT_FALSE(ObjectReader::read(
      makeObject(llvm::Triple("wasm32-unknown-unknown")), Target::X86_64));
}

TEST(ObjectReaderTest, RejectsUnsupportedArchitecture) {
  EXPECT_FALSE(ObjectReader::read(
      makeObject(llvm::Triple("i386-unknown-linux-gnu")), Target::X86_64));
}

TEST(ObjectReaderTest, RejectsUndefinedExternal) {
  EXPECT_FALSE(ObjectReader::read(makeNativeObject(true), nativeTarget()));
}

TEST(ObjectReaderTest, RejectsTargetMismatch) {
  const Target Other =
      nativeTarget() == Target::X86_64 ? Target::AArch64 : Target::X86_64;
  EXPECT_FALSE(ObjectReader::read(makeNativeObject(), Other));
}

TEST(ObjectReaderTest, RejectsEmptyAndArchiveBuffers) {
  EXPECT_FALSE(ObjectReader::read({}, nativeTarget()));
  const std::string Archive = "!<arch>\n";
  EXPECT_FALSE(ObjectReader::read(
      WasmEdge::Span<const WasmEdge::Byte>(
          reinterpret_cast<const WasmEdge::Byte *>(Archive.data()),
          Archive.size()),
      nativeTarget()));
}

} // namespace
