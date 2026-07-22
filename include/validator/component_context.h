// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

//===-- wasmedge/validator/component_context.h - Component context --------===//
//
// Part of the WasmEdge Project.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the context class used by component-model validation.
///
/// The context is organized around three ideas:
///  1. Every index-space entry is a *resolved view* whose leaves are AST
///     pointers. External types are resolved once, at definition time; raw
///     type indices are never stored and never re-resolved in a different
///     scope.
///  2. An entity's external type is a *shape*: ordered imports plus named
///     exports. There is one shape per level -- CoreShape for core modules
///     and core instances, ComponentShape for components and instances --
///     because an instance is just a shape without imports.
///  3. Scopes (components and type-declaration contexts) live in an arena and
///     stay alive after they pop, so views created in inner scopes (e.g. an
///     instancetype's export table) remain valid wherever they flow.
///
/// Resource identity is a session-global registry; the index is the id.
/// Instantiation freshens defined resources and substitutes imported ones via
/// immutable remap tables attached to the AST-typed leaf views.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "ast/component/canonical.h"
#include "ast/component/instance.h"
#include "ast/component/sort.h"
#include "ast/component/type.h"
#include "ast/module.h"
#include "ast/type.h"
#include "common/errcode.h"
#include "common/span.h"
#include "validator/component_name.h"
#include "validator/formchecker.h"

#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace WasmEdge {
namespace Validator {

class ComponentContext {
public:
  struct Scope;
  struct ComponentShape;

  // ==========================================================================
  // Resolved views. Leaves are pointers into the AST (or into this context's
  // arenas for synthesized core types); all referenced storage outlives
  // validation.
  // ==========================================================================

  /// Resolved core:importdesc / core export type. Kind discriminates; Func
  /// doubles as the tag signature for Kind == Tag.
  struct CoreExternInfo {
    ExternalType Kind = ExternalType::Function;
    const AST::SubType *Func = nullptr;
    const AST::TableType *Table = nullptr;
    const AST::MemoryType *Memory = nullptr;
    const AST::GlobalType *Global = nullptr;
  };

  /// External shape of a core-level entity: ordered imports and named
  /// exports. Core modules use both; core instances only export, so their
  /// Imports stay empty. Synthetic marks inline-export instances
  /// (diagnostics differ from instantiated ones).
  struct CoreShape {
    std::vector<std::tuple<std::string, std::string, CoreExternInfo>> Imports;
    std::map<std::string, CoreExternInfo, std::less<>> Exports;
    bool Synthetic = false;
  };

  /// Entry of the core:type index space: a rectype member or a moduletype.
  struct CoreTypeEntry {
    const AST::SubType *Func = nullptr;
    const CoreShape *Mod = nullptr;
  };

  /// Immutable resource-id remap: one flat table taking the ids a view was
  /// written against to the ids it denotes here. Crossing several
  /// instantiation boundaries composes tables, but the composition is
  /// evaluated when it is built (see composeRemap), so a lookup is always a
  /// single hash probe and ids absent from the table map to themselves.
  struct ResourceMap {
    std::unordered_map<uint32_t, uint32_t> Map;

    uint32_t apply(uint32_t Id) const noexcept {
      auto It = Map.find(Id);
      return It != Map.end() ? It->second : Id;
    }

    static uint32_t apply(const ResourceMap *M, uint32_t Id) noexcept {
      return M != nullptr ? M->apply(Id) : Id;
    }
  };

  /// A valtype together with the scope its type indices resolve in and the
  /// remap chain in effect for resource identities reached through it.
  struct QualValType {
    ComponentValType VT{};
    const Scope *Home = nullptr;
    const ResourceMap *Remap = nullptr;
  };

  /// A component-level function type view.
  struct FuncInfo {
    const AST::Component::FuncType *FT = nullptr;
    const Scope *Home = nullptr;
    const ResourceMap *Remap = nullptr;
  };

  /// Entry of the type index space. DT is null for abstract resources
  /// introduced by `(sub resource)` bounds. ResourceId is set iff the entry
  /// is a resource (already remapped; direct reads need no Remap).
  struct TypeEntry {
    const AST::Component::DefType *DT = nullptr;
    const Scope *Home = nullptr;
    const ResourceMap *Remap = nullptr;
    // Materialized shape of an instancetype / componenttype entry. Unlike
    // ExternInfo these stay two fields: a type entry carries no sort tag of
    // its own, so which one is set *is* the discriminator.
    const ComponentShape *Inst = nullptr;
    const ComponentShape *Comp = nullptr;
    std::optional<uint32_t> ResourceId;
    // Naming identity for resources: re-exports mint a fresh NameId while
    // keeping ResourceId, so matching and the named-types rule can differ.
    std::optional<uint32_t> NameId;
  };

  /// Resolved externdesc: the typed identity of an import/export/entity.
  /// Exactly one member is live, selected by K.
  struct ExternInfo {
    enum class Kind : uint8_t {
      CoreModule,
      Func,
      Value,
      Type,
      Instance,
      Component
    };
    Kind K = Kind::Func;
    const CoreShape *CoreMod = nullptr;
    FuncInfo Func;
    QualValType Value;
    TypeEntry Type;
    // Instance and component externs share one field: K discriminates.
    const ComponentShape *Shape = nullptr;
  };

  using ExternMap = std::map<std::string, ExternInfo, std::less<>>;

  /// External shape of a component-level entity: ordered imports and named
  /// exports. Components use both (imports stay ordered because argument
  /// matching accumulates resource substitutions left to right); instances
  /// only export, so their Imports stay empty. DeclScope is the scope whose
  /// resource ids the shape binds (its own declarations).
  struct ComponentShape {
    std::vector<std::pair<std::string, ExternInfo>> Imports;
    ExternMap Exports;
    // Export names in declaration order (introduction order matters for the
    // named-types rule).
    std::vector<std::string> Order;
    const Scope *DeclScope = nullptr;
    // Instances: created by an inline-export definition rather than by
    // instantiation (diagnostics differ).
    bool Synthetic = false;
    // Components: built from a componenttype declaration (imported shapes);
    // inline bodies keep plain diagnostics on their instances.
    bool FromDecl = false;
  };

  /// Entry of the value index space; linearity requires Consumed once.
  struct ValueEntry {
    QualValType Type;
    bool Consumed = false;
  };

  // ==========================================================================
  // Resource registry: index is the identity.
  // ==========================================================================

  struct ResourceEntry {
    const AST::Component::ResourceType *RT = nullptr;
    const Scope *Origin = nullptr;
    bool FromImport = false;
    uint32_t NameId = 0;
  };

  // ==========================================================================
  // Import/export name record for the strong-uniqueness rule.
  // ==========================================================================

  struct NameRecord {
    std::string Original;      // the full name as written
    std::string Stripped;      // annotation removed, acronyms lowercased
    std::string StrippedExact; // annotation removed, case preserved
    std::string DottedFirst;   // first label of a dotted annotated name
    bool HasAnnotation = false;
    bool IsConstructor = false;
    bool IsPlainLabel = false;
    bool IsDottedSame = false; // [*]l.l with the same label twice
    bool IsPlainish = false;   // label or annotated label (not interface/dep)
  };

  /// Result of adding a name: exact duplicate vs strong-uniqueness conflict.
  enum class NameClash : uint8_t { None, Duplicate, Conflict };

  // ==========================================================================
  // Scope: one per component / componenttype / instancetype / moduletype.
  // ==========================================================================

  struct Scope {
    enum class Kind : uint8_t {
      Component,
      ComponentType,
      InstanceType,
      ModuleType
    };

    Scope(Kind K, const Scope *P) noexcept : K(K), Parent(P) {}

    Kind K;
    const Scope *Parent;
    // Set for component bodies: the external view being materialized while
    // this scope's import/export sections validate.
    ComponentShape *SelfInfo = nullptr;

    // Core index spaces.
    std::vector<const CoreShape *> CoreModules;
    std::vector<const CoreShape *> CoreInstances;
    std::vector<CoreTypeEntry> CoreTypes;
    std::vector<const AST::SubType *> CoreFuncs;
    std::vector<const AST::TableType *> CoreTables;
    std::vector<const AST::MemoryType *> CoreMemories;
    std::vector<const AST::GlobalType *> CoreGlobals;
    std::vector<const AST::SubType *> CoreTags;

    // Component index spaces.
    std::vector<TypeEntry> Types;
    std::vector<FuncInfo> Funcs;
    std::vector<ValueEntry> Values;
    std::vector<const ComponentShape *> Components;
    std::vector<const ComponentShape *> Instances;

    // Naming state.
    std::vector<NameRecord> ImportNames;
    std::vector<NameRecord> ExportNames;
    // Plain resource label -> resource id, per side, for
    // [constructor]/[method]/[static] name checks.
    std::unordered_map<std::string, uint32_t> ImportResourceLabels;
    std::unordered_map<std::string, uint32_t> ExportResourceLabels;
    std::unordered_map<uint32_t, std::string> ImportResourceNames;
    std::unordered_map<uint32_t, std::string> ExportResourceNames;
    // Resource ids introduced by preceding imports/exports (nameability).
    std::unordered_set<uint32_t> ImportNamedResources;
    std::unordered_set<uint32_t> ExportNamedResources;
    // Composite defined types introduced by preceding imports/exports,
    // with the scope their inner indices resolve in.
    std::unordered_map<const AST::Component::DefType *, const Scope *>
        ImportNamedTypes;
    std::unordered_map<const AST::Component::DefType *, const Scope *>
        ExportNamedTypes;
    // Naming identities of introduced types: local references must name the
    // introduced identity, not merely a structurally identical definition.
    std::unordered_set<uint32_t> ImportNamedIds;
    std::unordered_set<uint32_t> ExportNamedIds;

    uint32_t getSortSize(AST::Component::Sort::SortType ST) const noexcept;
    uint32_t
    getCoreSortSize(AST::Component::Sort::CoreSortType ST) const noexcept;

    const TypeEntry *getType(uint32_t Idx) const noexcept {
      return Idx < Types.size() ? &Types[Idx] : nullptr;
    }
    const FuncInfo *getFunc(uint32_t Idx) const noexcept {
      return Idx < Funcs.size() ? &Funcs[Idx] : nullptr;
    }
    const ComponentShape *getInstance(uint32_t Idx) const noexcept {
      return Idx < Instances.size() ? Instances[Idx] : nullptr;
    }
    const ComponentShape *getComponent(uint32_t Idx) const noexcept {
      return Idx < Components.size() ? Components[Idx] : nullptr;
    }
    const CoreShape *getCoreModule(uint32_t Idx) const noexcept {
      return Idx < CoreModules.size() ? CoreModules[Idx] : nullptr;
    }
    const CoreShape *getCoreInstance(uint32_t Idx) const noexcept {
      return Idx < CoreInstances.size() ? CoreInstances[Idx] : nullptr;
    }
    const CoreTypeEntry *getCoreType(uint32_t Idx) const noexcept {
      return Idx < CoreTypes.size() ? &CoreTypes[Idx] : nullptr;
    }
    const AST::SubType *getCoreFunc(uint32_t Idx) const noexcept {
      return Idx < CoreFuncs.size() ? CoreFuncs[Idx] : nullptr;
    }
  };

  // ==========================================================================
  // Scope stack management. A scope is allocated in the arena (so views that
  // reference it stay valid after it pops) and pushed onto the active stack;
  // exitScope pops it. Balance across early returns is not required: a failed
  // validation unwinds without reading the stack again, and the next
  // validate() call resets it.
  // ==========================================================================

  Scope &enterScope(Scope::Kind K) noexcept {
    const Scope *Parent = Stack.empty() ? nullptr : Stack.back();
    ScopeArena.emplace_back(K, Parent);
    Stack.push_back(&ScopeArena.back());
    return ScopeArena.back();
  }

  void exitScope() noexcept {
    assuming(!Stack.empty());
    Stack.pop_back();
  }

  Scope &top() noexcept {
    assuming(!Stack.empty());
    return *Stack.back();
  }
  const Scope &top() const noexcept {
    assuming(!Stack.empty());
    return *Stack.back();
  }

  uint32_t depth() const noexcept {
    return static_cast<uint32_t>(Stack.size());
  }

  /// The scope Ct hops up from the current one; nullptr if out of range.
  Scope *scopeUp(uint32_t Ct) noexcept {
    if (Ct >= Stack.size()) {
      return nullptr;
    }
    return Stack[Stack.size() - 1 - Ct];
  }

  /// The scope one level inside the outer-alias target (Ct > 0): if it is a
  /// real component, the alias crosses a component boundary.
  const Scope *scopeInsideTarget(uint32_t Ct) const noexcept {
    if (Ct == 0 || Ct > Stack.size()) {
      return nullptr;
    }
    return Stack[Stack.size() - Ct];
  }

  // ==========================================================================
  // Resource registry.
  // ==========================================================================

  uint32_t newNameId() noexcept { return NextNameId++; }

  uint32_t addResource(const AST::Component::ResourceType *RT,
                       const Scope *Origin, bool FromImport) noexcept {
    uint32_t Id = static_cast<uint32_t>(Resources.size());
    Resources.push_back({RT, Origin, FromImport, newNameId()});
    return Id;
  }

  const ResourceEntry &getResource(uint32_t Id) const noexcept {
    assuming(Id < Resources.size());
    return Resources[Id];
  }

  // ==========================================================================
  // Arenas for synthesized views.
  // ==========================================================================

  /// Composition of two remaps: apply Inner first, then Outer. The result is
  /// evaluated into one table right here and memoized, so views resolved
  /// repeatedly share it. Either side may be null.
  const ResourceMap *composeRemap(const ResourceMap *Outer,
                                  const ResourceMap *Inner) noexcept {
    if (Outer == nullptr) {
      return Inner;
    }
    if (Inner == nullptr) {
      return Outer;
    }
    auto Key = std::make_pair(Outer, Inner);
    auto It = RemapCompose.find(Key);
    if (It != RemapCompose.end()) {
      return It->second;
    }
    auto *Node = &RemapArena.emplace_back();
    // What Inner moves lands on its Outer image; what only Outer knows keeps
    // that image; everything else is already identity in both.
    for (const auto &[From, To] : Inner->Map) {
      Node->Map.emplace(From, Outer->apply(To));
    }
    for (const auto &[From, To] : Outer->Map) {
      Node->Map.emplace(From, To);
    }
    RemapCompose.emplace(Key, Node);
    return Node;
  }

  CoreShape *newCoreShape() noexcept { return &CoreShapeArena.emplace_back(); }
  ComponentShape *newComponentShape() noexcept {
    return &ComponentShapeArena.emplace_back();
  }
  ResourceMap *newResourceMap() noexcept { return &RemapArena.emplace_back(); }

  /// Synthesize a core function type owned by the context (canon lower and
  /// the resource built-ins produce core funcs with no AST-backed type).
  const AST::SubType *makeCoreFuncType(Span<const ValType> Params,
                                       Span<const ValType> Results) noexcept {
    SynthCoreTypes.push_back(
        std::make_unique<AST::SubType>(AST::FunctionType(Params, Results)));
    return SynthCoreTypes.back().get();
  }

  // ==========================================================================
  // Strong-uniqueness of import/export names.
  // ==========================================================================

  /// Builds the comparison record for a parsed name.
  static NameRecord makeNameRecord(const ComponentName &Name) noexcept;

  /// Appends N to Names, reporting how it clashes with an earlier name.
  static NameClash addUniqueName(std::vector<NameRecord> &Names,
                                 const NameRecord &N) noexcept;

  // ==========================================================================
  // Structural matching (MVP: equality modulo resource identity) and the
  // resource-id walkers. Substitution maps supertype-side abstract resource
  // ids to subtype ids; the deeper internals are private below.
  // ==========================================================================

  using ResourceSubst = std::unordered_map<uint32_t, uint32_t>;

  bool matchValType(const QualValType &Sub, const QualValType &Sup,
                    ResourceSubst &Subst) noexcept;
  bool matchCoreExtern(const CoreExternInfo &Sub,
                       const CoreExternInfo &Sup) const noexcept;

  // Transitive borrow check on value types.
  bool containsBorrow(const QualValType &Q) noexcept;
  // Collect resource ids reachable from a view (for free-variable rules).
  void collectResources(const ExternInfo &Info,
                        std::unordered_set<uint32_t> &Out) noexcept;
  void collectResources(const QualValType &Q,
                        std::unordered_set<uint32_t> &Out) noexcept;
  // True iff the id originates in S or one of its descendants.
  bool originatesIn(uint32_t Id, const Scope &S) const noexcept;

  // Rebuilds an instance view minting fresh identities for the resources its
  // own declarations introduced.
  const ComponentShape *freshenDeclaredResources(const ComponentShape *Inst,
                                                 bool FromImport) noexcept;
  // Instantiation: match args against CI.Imports, then produce the
  // instance's export view with substituted + freshened resource ids.
  Expect<const ComponentShape *> instantiateComponentShape(
      const ComponentShape &CI,
      Span<const AST::Component::InstantiateArg<AST::Component::SortIndex>>
          Args) noexcept;
  // Resolve a sortidx to its typed view in the current scope.
  Expect<ExternInfo>
  resolveSortIndex(const AST::Component::SortIndex &SI) noexcept;

  // ==========================================================================
  // Effective type-size and nesting-depth limits.
  // ==========================================================================

  static inline constexpr const uint64_t MaxTypeSize = 1000000;
  uint64_t sizeOfExtern(const ExternInfo &Info) noexcept;
  uint64_t depthOfExtern(const ExternInfo &Info) noexcept;
  Expect<void> checkTypeSize(uint64_t Size) noexcept;
  Expect<void> checkTypeDepth(uint64_t Depth) noexcept;

  // ==========================================================================
  // Canonical ABI flattening (spec `flatten_functype`).
  // ==========================================================================

  static inline constexpr const uint32_t MaxFlatParams = 16;
  static inline constexpr const uint32_t MaxFlatAsyncParams = 4;
  static inline constexpr const uint32_t MaxFlatResults = 1;
  // Appends the flat core types of Q to Out; false on invalid type. Ptr is
  // the index type of the selected canonical memory (pointer-bearing slots
  // widen to i64 under a 64-bit memory).
  bool flattenValType(const QualValType &Q, std::vector<ValType> &Out,
                      const ValType &Ptr) noexcept;
  // True iff the type transitively contains a list or string.
  bool needsMemory(const QualValType &Q) noexcept;
  // True iff the canonical `memory` option selects a 64-bit memory.
  bool canonMemoryIs64(const AST::Component::Canonical &Canon) const noexcept;

  // ==========================================================================
  // Import/export definition: name grammar, strong uniqueness, annotated
  // names, the named-types rule, and index-space registration.
  // ==========================================================================

  // Import/export name grammar + position checks.
  static Expect<ComponentName> parseImportName(std::string_view Name) noexcept;
  static Expect<ComponentName> parseExportName(std::string_view Name) noexcept;
  // The `implements` annotation: values must be interface names, the
  // annotated name must be plain, and the extern must be instance-typed.
  static Expect<void> checkImplements(const ComponentName &CN,
                                      Span<const std::string> Impls,
                                      bool IsInstance) noexcept;
  // Annotated plainname rules ([constructor]/[method]/[static]).
  Expect<void> checkAnnotatedName(const ComponentName &Name,
                                  const ExternInfo &Info,
                                  bool IsImport) noexcept;
  // Track plain resource labels for later annotated-name checks.
  void recordResourceLabel(const ComponentName &Name, const ExternInfo &Info,
                           bool IsImport) noexcept;
  // Named-types rule: flags/enums/records/variants/resources referenced by
  // an extern must have been introduced by a preceding import/export.
  Expect<void> checkResourceNameability(const ExternInfo &Info,
                                        bool IsImport) noexcept;

  // Push the entity described by a resolved view into its index space.
  void defineExtern(const ExternInfo &Info) noexcept;
  // Check an import's name and define the (already resolved) entity it
  // introduces.
  Expect<ExternInfo> defineImport(std::string_view Name,
                                  const ExternInfo &Resolved,
                                  Span<const std::string> Impls = {}) noexcept;
  // Check an export's name/uniqueness/annotations and record it; the
  // (optionally ascribed) entity is defined afterwards via defineExport.
  Expect<ComponentName>
  registerExportName(std::string_view Name, bool IsInstance,
                     Span<const std::string> Impls = {}) noexcept;
  // Apply the optional ascription and define the re-exported index.
  Expect<ExternInfo>
  defineExport(const ComponentName &CN, const ExternInfo &Inferred,
               const std::optional<ExternInfo> &Ascribed) noexcept;

  // Build the external view of an inline core module.
  Expect<const CoreShape *> buildCoreShape(const AST::Module &Mod) noexcept;

  /// Core-module code sections whose function bodies are deferred to the end
  /// of the root component, each paired with the checker state captured at
  /// its definition so the module validates in a single pass.
  std::vector<std::pair<const AST::Module *, FormChecker>> DeferredModules;

  void reset() noexcept {
    NextNameId = 0;
    MatchWhy = ErrCode::Value::Success;
    DeferredModules.clear();
    Stack.clear();
    ScopeArena.clear();
    Resources.clear();
    CoreShapeArena.clear();
    ComponentShapeArena.clear();
    RemapArena.clear();
    RemapCompose.clear();
    SynthCoreTypes.clear();
    TypeSizeMemo.clear();
    TypeDepthMemo.clear();
  }

private:
  // ==========================================================================
  // Matching internals.
  // ==========================================================================

  // Normalized value type: a primitive code or a composite defvaltype with
  // its resolution frame. Shared by the matchers and walkers.
  struct NormalVal {
    ComponentTypeCode Prim = ComponentTypeCode::TypeIndex;
    const AST::Component::DefValType *DVT = nullptr;
    const Scope *Home = nullptr;
    const ResourceMap *Remap = nullptr;
    bool Valid = false;
  };

  // Resolve a valtype's type index to its entry (nullptr for primitives or
  // out-of-bounds). Composes the view's remap into Storage.
  const TypeEntry *resolveQualType(const QualValType &Q,
                                   TypeEntry &Storage) noexcept;
  NormalVal normalizeValType(const QualValType &Q) noexcept;
  NormalVal normalizeEntry(const TypeEntry &E) const noexcept;
  bool matchNormalVal(const NormalVal &NSub, const NormalVal &NSup,
                      ResourceSubst &Subst) noexcept;
  bool matchFunc(const FuncInfo &Sub, const FuncInfo &Sup,
                 ResourceSubst &Subst) noexcept;
  bool matchTypeEntry(const TypeEntry &Sub, const TypeEntry &Sup,
                      ResourceSubst &Subst) noexcept;
  // Instances match on exports only; components also match imports
  // contravariantly, so the two relations stay separate.
  bool matchInstanceShape(const ComponentShape &Sub, const ComponentShape &Sup,
                          ResourceSubst &Subst) noexcept;
  bool matchComponentShape(const ComponentShape &Sub, const ComponentShape &Sup,
                           ResourceSubst &Subst) noexcept;
  bool matchExtern(const ExternInfo &Sub, const ExternInfo &Sup,
                   ResourceSubst &Subst) noexcept;
  bool matchCoreFuncType(const AST::SubType *Sub,
                         const AST::SubType *Sup) const noexcept;
  void resetNestedMatchWhy() noexcept;
  void collectResourcesNormal(const NormalVal &N,
                              std::unordered_set<uint32_t> &Out) noexcept;
  uint64_t sizeOfValType(const QualValType &Q) noexcept;
  uint64_t depthOfValType(const QualValType &Q) noexcept;

  // Named-types rule internals.
  bool namedExtern(const ExternInfo &Info, bool IsImport) noexcept;
  bool namedValType(const QualValType &Q, bool IsImport) noexcept;
  bool namedTypeEntry(const TypeEntry &E, bool IsImport) noexcept;
  bool allValTypesNamed(const TypeEntry &E, bool IsImport) noexcept;

  // Most-specific reason recorded by the innermost failing matcher; sites
  // report it when set, falling back to their generic mismatch code.
  ErrCode::Value MatchWhy = ErrCode::Value::Success;
  std::unordered_map<const void *, uint64_t> TypeSizeMemo;
  std::unordered_map<const void *, uint64_t> TypeDepthMemo;

  struct PtrPairHash {
    size_t operator()(const std::pair<const ResourceMap *, const ResourceMap *>
                          &P) const noexcept {
      return std::hash<const void *>{}(P.first) ^
             (std::hash<const void *>{}(P.second) << 1);
    }
  };

  uint32_t NextNameId = 0;
  std::vector<Scope *> Stack;
  std::deque<Scope> ScopeArena;
  std::vector<ResourceEntry> Resources;
  std::deque<CoreShape> CoreShapeArena;
  std::deque<ComponentShape> ComponentShapeArena;
  std::deque<ResourceMap> RemapArena;
  std::unordered_map<std::pair<const ResourceMap *, const ResourceMap *>,
                     const ResourceMap *, PtrPairHash>
      RemapCompose;
  std::vector<std::unique_ptr<AST::SubType>> SynthCoreTypes;
};

} // namespace Validator
} // namespace WasmEdge
