// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/link_graph.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

namespace {

using namespace WasmEdge::LLVM::Linker;

static_assert(sizeof(Target) == sizeof(uint8_t));
static_assert(sizeof(Endianness) == sizeof(uint8_t));
static_assert(sizeof(SectionKind) == sizeof(uint8_t));
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

} // namespace
