// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2025 Second State INC

//===-- component_match.cpp - Structural matching and instantiation -------===//
//
// The component-model subtype relation (MVP: structural equality modulo
// resource identity), resource-id walkers, and the instantiation engine that
// substitutes imported resources and freshens defined ones.
//
//===----------------------------------------------------------------------===//

#include "common/errinfo.h"
#include "common/spdlog.h"
#include "validator/component_context.h"

#include <string>
#include <unordered_map>
#include <unordered_set>

namespace WasmEdge {
namespace Validator {

using namespace std::literals;

// NOLINTBEGIN(misc-no-recursion) -- type structures are finitely nested.

const ComponentContext::TypeEntry *ComponentContext::resolveQualType(
    const ComponentContext::QualValType &Q,
    ComponentContext::TypeEntry &Storage) noexcept {
  if (Q.VT.isPrimValType() || Q.Home == nullptr) {
    return nullptr;
  }
  const auto *Entry = Q.Home->getType(Q.VT.getTypeIndex());
  if (Entry == nullptr) {
    return nullptr;
  }
  Storage = *Entry;
  if (Entry->ResourceId.has_value()) {
    Storage.ResourceId =
        ComponentContext::ResourceMap::apply(Q.Remap, *Entry->ResourceId);
  }
  Storage.Remap = composeRemap(Q.Remap, Entry->Remap);
  return &Storage;
}

namespace {
// Effective resource id behind an own/borrow handle index.
std::optional<uint32_t>
handleResourceId(const ComponentContext::Scope *Home,
                 const ComponentContext::ResourceMap *Remap,
                 uint32_t Idx) noexcept {
  if (Home == nullptr) {
    return std::nullopt;
  }
  const auto *Entry = Home->getType(Idx);
  if (Entry == nullptr || !Entry->ResourceId.has_value()) {
    return std::nullopt;
  }
  return ComponentContext::ResourceMap::apply(Remap, *Entry->ResourceId);
}
} // namespace

// Resolves through type-index and prim-alias indirections.
ComponentContext::NormalVal ComponentContext::normalizeValType(
    const ComponentContext::QualValType &Q) noexcept {
  if (Q.VT.isPrimValType()) {
    return {Q.VT.getCode(), nullptr, nullptr, nullptr, true};
  }
  ComponentContext::TypeEntry Storage;
  const auto *Entry = resolveQualType(Q, Storage);
  if (Entry == nullptr) {
    return {};
  }
  return normalizeEntry(*Entry);
}

ComponentContext::NormalVal ComponentContext::normalizeEntry(
    const ComponentContext::TypeEntry &E) const noexcept {
  if (E.DT == nullptr || !E.DT->isDefValType()) {
    return {};
  }
  const auto &DVT = E.DT->getDefValType();
  if (DVT.isPrimValType()) {
    return {static_cast<ComponentTypeCode>(DVT.getPrimValType()), nullptr,
            nullptr, nullptr, true};
  }
  return {ComponentTypeCode::TypeIndex, &DVT, E.Home, E.Remap, true};
}

bool ComponentContext::matchValType(const ComponentContext::QualValType &Sub,
                                    const ComponentContext::QualValType &Sup,
                                    ResourceSubst &Subst) noexcept {
  return matchNormalVal(normalizeValType(Sub), normalizeValType(Sup), Subst);
}

bool ComponentContext::matchNormalVal(const NormalVal &NSub,
                                      const NormalVal &NSup,
                                      ResourceSubst &Subst) noexcept {
  if (!NSub.Valid || !NSup.Valid) {
    return false;
  }
  if (NSub.DVT == nullptr && NSup.DVT == nullptr) {
    if (NSub.Prim != NSup.Prim) {
      // Only class-level differences (string vs scalar) name the primitive;
      // scalar-vs-scalar mismatches keep the positional diagnostic.
      if ((NSub.Prim == ComponentTypeCode::String) !=
          (NSup.Prim == ComponentTypeCode::String)) {
        MatchWhy = ErrCode::Value::ComponentPrimitiveMismatch;
      }
      return false;
    }
    return true;
  }
  if (NSub.DVT == nullptr || NSup.DVT == nullptr) {
    return false;
  }
  const auto &A = *NSub.DVT;
  const auto &B = *NSup.DVT;
  auto MatchSub = [&](const ComponentValType &VA,
                      const ComponentValType &VB) noexcept {
    return matchValType({VA, NSub.Home, NSub.Remap},
                        {VB, NSup.Home, NSup.Remap}, Subst);
  };
  auto MatchOpt = [&](const std::optional<ComponentValType> &VA,
                      const std::optional<ComponentValType> &VB) noexcept {
    if (VA.has_value() != VB.has_value()) {
      return false;
    }
    return !VA.has_value() || MatchSub(*VA, *VB);
  };
  if (A.isRecordTy() && B.isRecordTy()) {
    const auto &RA = A.getRecord().LabelTypes;
    const auto &RB = B.getRecord().LabelTypes;
    if (RA.size() != RB.size()) {
      return false;
    }
    for (size_t I = 0; I < RA.size(); ++I) {
      if (RA[I].getLabel() != RB[I].getLabel() ||
          !MatchSub(RA[I].getValType(), RB[I].getValType())) {
        return false;
      }
    }
    return true;
  }
  if (A.isVariantTy() && B.isVariantTy()) {
    const auto &VA = A.getVariant().Cases;
    const auto &VB = B.getVariant().Cases;
    if (VA.size() != VB.size()) {
      return false;
    }
    for (size_t I = 0; I < VA.size(); ++I) {
      if (VA[I].first != VB[I].first || !MatchOpt(VA[I].second, VB[I].second)) {
        return false;
      }
    }
    return true;
  }
  if (A.isListTy() && B.isListTy()) {
    if (A.getList().Len != B.getList().Len) {
      return false;
    }
    return MatchSub(A.getList().ValTy, B.getList().ValTy);
  }
  if (A.isTupleTy() && B.isTupleTy()) {
    const auto &TA = A.getTuple().Types;
    const auto &TB = B.getTuple().Types;
    if (TA.size() != TB.size()) {
      return false;
    }
    for (size_t I = 0; I < TA.size(); ++I) {
      if (!MatchSub(TA[I], TB[I])) {
        return false;
      }
    }
    return true;
  }
  if (A.isFlagsTy() && B.isFlagsTy()) {
    return A.getFlags().Labels == B.getFlags().Labels;
  }
  if (A.isEnumTy() && B.isEnumTy()) {
    if (A.getEnum().Labels != B.getEnum().Labels) {
      MatchWhy = ErrCode::Value::ComponentEnumMismatch;
      return false;
    }
    return true;
  }
  if (A.isOptionTy() && B.isOptionTy()) {
    return MatchSub(A.getOption().ValTy, B.getOption().ValTy);
  }
  if (A.isResultTy() && B.isResultTy()) {
    const auto &RA = A.getResult();
    const auto &RB = B.getResult();
    if (RA.ValTy.has_value() && !RB.ValTy.has_value()) {
      MatchWhy = ErrCode::Value::ComponentExpectedNoOkType;
      return false;
    }
    if (RA.ErrTy.has_value() && !RB.ErrTy.has_value()) {
      MatchWhy = ErrCode::Value::ComponentExpectedNoErrType;
      return false;
    }
    return MatchOpt(RA.ValTy, RB.ValTy) && MatchOpt(RA.ErrTy, RB.ErrTy);
  }
  if ((A.isStreamTy() && B.isStreamTy()) ||
      (A.isFutureTy() && B.isFutureTy())) {
    const auto &EA = A.isStreamTy() ? A.getStream().ValTy : A.getFuture().ValTy;
    const auto &EB = B.isStreamTy() ? B.getStream().ValTy : B.getFuture().ValTy;
    return MatchOpt(EA, EB);
  }
  if (A.isBorrowTy() && B.isOwnTy()) {
    MatchWhy = ErrCode::Value::ComponentExpectedOwn;
    return false;
  }
  if (A.isOwnTy() && B.isBorrowTy()) {
    MatchWhy = ErrCode::Value::ComponentExpectedBorrow;
    return false;
  }
  if ((A.isOwnTy() && B.isOwnTy()) || (A.isBorrowTy() && B.isBorrowTy())) {
    const uint32_t IA = A.isOwnTy() ? A.getOwn().Idx : A.getBorrow().Idx;
    const uint32_t IB = B.isOwnTy() ? B.getOwn().Idx : B.getBorrow().Idx;
    const auto RA = handleResourceId(NSub.Home, NSub.Remap, IA);
    const auto RB = handleResourceId(NSup.Home, NSup.Remap, IB);
    if (!RA.has_value() || !RB.has_value()) {
      return false;
    }
    uint32_t SupId = *RB;
    auto It = Subst.find(SupId);
    if (It != Subst.end()) {
      SupId = It->second;
    }
    if (*RA != SupId) {
      MatchWhy = ErrCode::Value::ComponentResourceMismatch;
      return false;
    }
    return true;
  }
  return false;
}

bool ComponentContext::matchFunc(const ComponentContext::FuncInfo &Sub,
                                 const ComponentContext::FuncInfo &Sup,
                                 ResourceSubst &Subst) noexcept {
  if (Sub.FT == nullptr || Sup.FT == nullptr) {
    return false;
  }
  const auto PA = Sub.FT->getParamList();
  const auto PB = Sup.FT->getParamList();
  if (PA.size() != PB.size()) {
    return false;
  }
  for (size_t I = 0; I < PA.size(); ++I) {
    if (PA[I].getLabel() != PB[I].getLabel() ||
        !matchValType({PA[I].getValType(), Sub.Home, Sub.Remap},
                      {PB[I].getValType(), Sup.Home, Sup.Remap}, Subst)) {
      return false;
    }
  }
  const auto RA = Sub.FT->getResultList();
  const auto RB = Sup.FT->getResultList();
  if (RA.size() != RB.size()) {
    MatchWhy = ErrCode::Value::ComponentExpectedResult;
    return false;
  }
  for (size_t I = 0; I < RA.size(); ++I) {
    if (!matchValType({RA[I].getValType(), Sub.Home, Sub.Remap},
                      {RB[I].getValType(), Sup.Home, Sup.Remap}, Subst)) {
      return false;
    }
  }
  return true;
}

bool ComponentContext::matchTypeEntry(const ComponentContext::TypeEntry &Sub,
                                      const ComponentContext::TypeEntry &Sup,
                                      ResourceSubst &Subst) noexcept {
  // Abstract resource supertype: binds (or re-checks) the substitution.
  if (Sup.ResourceId.has_value() && Sup.DT == nullptr) {
    if (!Sub.ResourceId.has_value()) {
      MatchWhy = ErrCode::Value::ComponentExpectedResource;
      return false;
    }
    auto [It, New] = Subst.emplace(*Sup.ResourceId, *Sub.ResourceId);
    if (!New && It->second != *Sub.ResourceId) {
      MatchWhy = ErrCode::Value::ComponentResourceMismatch;
      return false;
    }
    // Abstract-to-abstract bindings work in both directions (component
    // shapes are matched contravariantly on imports).
    if (Sub.DT == nullptr) {
      Subst.emplace(*Sub.ResourceId, *Sup.ResourceId);
    }
    return true;
  }
  if (Sup.ResourceId.has_value()) {
    if (!Sub.ResourceId.has_value()) {
      MatchWhy = ErrCode::Value::ComponentExpectedResource;
      return false;
    }
    uint32_t SupId = *Sup.ResourceId;
    auto It = Subst.find(SupId);
    if (It != Subst.end()) {
      SupId = It->second;
    }
    return *Sub.ResourceId == SupId;
  }
  if (Sub.ResourceId.has_value()) {
    if (Sup.DT != nullptr && Sup.DT->isDefValType()) {
      MatchWhy = ErrCode::Value::ComponentExpectedDefinedType;
    }
    return false;
  }
  if (Sup.Inst != nullptr) {
    return Sub.Inst != nullptr &&
           matchInstanceShape(*Sub.Inst, *Sup.Inst, Subst);
  }
  if (Sup.Comp != nullptr) {
    return Sub.Comp != nullptr &&
           matchComponentShape(*Sub.Comp, *Sup.Comp, Subst);
  }
  if (Sup.DT == nullptr || Sub.DT == nullptr) {
    return false;
  }
  if (Sup.DT->isFuncType()) {
    if (!Sub.DT->isFuncType()) {
      return false;
    }
    return matchFunc({&Sub.DT->getFuncType(), Sub.Home, Sub.Remap},
                     {&Sup.DT->getFuncType(), Sup.Home, Sup.Remap}, Subst);
  }
  if (Sup.DT->isDefValType()) {
    if (!Sub.DT->isDefValType()) {
      return false;
    }
    return matchNormalVal(normalizeEntry(Sub), normalizeEntry(Sup), Subst);
  }
  return false;
}

// Positional diagnostics ("type mismatch in instance export") beat leaf
// reasons when the failure is nested inside an instance/component shape.
void ComponentContext::resetNestedMatchWhy() noexcept {
  switch (MatchWhy) {
  case ErrCode::Value::InstanceMissingExpectedExport:
  case ErrCode::Value::ComponentMissingExpectedImport:
  case ErrCode::Value::ComponentResourceMismatch:
  case ErrCode::Value::ComponentExpectedResource:
  case ErrCode::Value::ComponentExpectedDefinedType:
  case ErrCode::Value::ComponentExpectedOwn:
  case ErrCode::Value::ComponentExpectedBorrow:
    break;
  default:
    MatchWhy = ErrCode::Value::Success;
    break;
  }
}

bool ComponentContext::matchInstanceShape(
    const ComponentContext::ComponentShape &Sub,
    const ComponentContext::ComponentShape &Sup,
    ResourceSubst &Subst) noexcept {
  // Walk expected exports in declaration order: abstract resources must
  // bind before the functions that reference them.
  auto MatchOne = [&](const std::string &Name,
                      const ComponentContext::ExternInfo &SupE) noexcept {
    auto It = Sub.Exports.find(Name);
    if (It == Sub.Exports.end()) {
      MatchWhy = ErrCode::Value::InstanceMissingExpectedExport;
      return false;
    }
    if (!matchExtern(It->second, SupE, Subst)) {
      resetNestedMatchWhy();
      return false;
    }
    return true;
  };
  if (!Sup.Order.empty()) {
    for (const auto &Name : Sup.Order) {
      auto SupIt = Sup.Exports.find(Name);
      if (SupIt != Sup.Exports.end() && !MatchOne(Name, SupIt->second)) {
        return false;
      }
    }
    return true;
  }
  for (const auto &[Name, SupE] : Sup.Exports) {
    if (!MatchOne(Name, SupE)) {
      return false;
    }
  }
  return true;
}

bool ComponentContext::matchComponentShape(
    const ComponentContext::ComponentShape &Sub,
    const ComponentContext::ComponentShape &Sup,
    ResourceSubst &Subst) noexcept {
  // Imports contravariant: everything Sub requires, Sup must require
  // compatibly (so args satisfying Sup satisfy Sub).
  for (const auto &[Name, SubImp] : Sub.Imports) {
    const ComponentContext::ExternInfo *SupImp = nullptr;
    for (const auto &[SupName, E] : Sup.Imports) {
      if (SupName == Name) {
        SupImp = &E;
        break;
      }
    }
    if (SupImp == nullptr) {
      MatchWhy = ErrCode::Value::ComponentMissingExpectedImport;
      return false;
    }
    if (!matchExtern(*SupImp, SubImp, Subst)) {
      resetNestedMatchWhy();
      return false;
    }
  }
  // Exports covariant.
  for (const auto &[Name, SupE] : Sup.Exports) {
    auto It = Sub.Exports.find(Name);
    if (It == Sub.Exports.end()) {
      MatchWhy = ErrCode::Value::InstanceMissingExpectedExport;
      return false;
    }
    if (!matchExtern(It->second, SupE, Subst)) {
      resetNestedMatchWhy();
      return false;
    }
  }
  return true;
}

bool ComponentContext::matchExtern(const ComponentContext::ExternInfo &Sub,
                                   const ComponentContext::ExternInfo &Sup,
                                   ResourceSubst &Subst) noexcept {
  if (Sub.K != Sup.K) {
    if (Sup.K == ComponentContext::ExternInfo::Kind::Func) {
      MatchWhy = ErrCode::Value::ComponentExpectedFunc;
    } else if (Sup.K == ComponentContext::ExternInfo::Kind::Component) {
      MatchWhy = ErrCode::Value::ComponentExpectedComponent;
    }
    return false;
  }
  switch (Sup.K) {
  case ComponentContext::ExternInfo::Kind::CoreModule: {
    if (Sub.CoreMod == nullptr || Sup.CoreMod == nullptr) {
      return false;
    }
    // Imports contravariant by (module, name); exports covariant.
    for (const auto &[Mod, Name, SubExt] : Sub.CoreMod->Imports) {
      const ComponentContext::CoreExternInfo *SupExt = nullptr;
      for (const auto &[SMod, SName, E] : Sup.CoreMod->Imports) {
        if (SMod == Mod && SName == Name) {
          SupExt = &E;
          break;
        }
      }
      if (SupExt == nullptr) {
        MatchWhy = ErrCode::Value::ComponentMissingExpectedImport;
        return false;
      }
      if (!matchCoreExtern(*SupExt, SubExt)) {
        return false;
      }
    }
    for (const auto &[Name, SupExt] : Sup.CoreMod->Exports) {
      auto It = Sub.CoreMod->Exports.find(Name);
      if (It == Sub.CoreMod->Exports.end()) {
        MatchWhy = ErrCode::Value::InstanceMissingExpectedExport;
        return false;
      }
      if (!matchCoreExtern(It->second, SupExt)) {
        return false;
      }
    }
    return true;
  }
  case ComponentContext::ExternInfo::Kind::Func: {
    if (matchFunc(Sub.Func, Sup.Func, Subst)) {
      return true;
    }
    // Value-leaf reasons stay internal to function signatures; the
    // diagnostic names the parameter/result position instead.
    if (MatchWhy == ErrCode::Value::ComponentPrimitiveMismatch ||
        MatchWhy == ErrCode::Value::ComponentEnumMismatch ||
        MatchWhy == ErrCode::Value::ComponentExpectedNoOkType ||
        MatchWhy == ErrCode::Value::ComponentExpectedNoErrType) {
      MatchWhy = ErrCode::Value::Success;
    }
    return false;
  }
  case ComponentContext::ExternInfo::Kind::Value:
    return matchValType(Sub.Value, Sup.Value, Subst);
  case ComponentContext::ExternInfo::Kind::Type:
    return matchTypeEntry(Sub.Type, Sup.Type, Subst);
  case ComponentContext::ExternInfo::Kind::Instance:
    return Sub.Shape != nullptr && Sup.Shape != nullptr &&
           matchInstanceShape(*Sub.Shape, *Sup.Shape, Subst);
  case ComponentContext::ExternInfo::Kind::Component:
    return Sub.Shape != nullptr && Sup.Shape != nullptr &&
           matchComponentShape(*Sub.Shape, *Sup.Shape, Subst);
  }
  return false;
}

bool ComponentContext::matchCoreFuncType(
    const AST::SubType *Sub, const AST::SubType *Sup) const noexcept {
  if (Sub == nullptr || Sup == nullptr) {
    return false;
  }
  const auto &CA = Sub->getCompositeType();
  const auto &CB = Sup->getCompositeType();
  if (!CA.isFunc() || !CB.isFunc()) {
    return false;
  }
  return CA.getFuncType().getParamTypes() == CB.getFuncType().getParamTypes() &&
         CA.getFuncType().getReturnTypes() == CB.getFuncType().getReturnTypes();
}

bool ComponentContext::matchCoreExtern(
    const ComponentContext::CoreExternInfo &Sub,
    const ComponentContext::CoreExternInfo &Sup) const noexcept {
  if (Sub.Kind != Sup.Kind) {
    return false;
  }
  auto MatchLimits = [](const AST::Limit &LA, const AST::Limit &LB) noexcept {
    if (LA.is64() != LB.is64() || LA.isShared() != LB.isShared()) {
      return false;
    }
    if (LA.getMin() < LB.getMin()) {
      return false;
    }
    if (LB.hasMax()) {
      return LA.hasMax() && LA.getMax() <= LB.getMax();
    }
    return true;
  };
  switch (Sup.Kind) {
  case ExternalType::Function:
  case ExternalType::Tag:
    return matchCoreFuncType(Sub.Func, Sup.Func);
  case ExternalType::Table:
    return Sub.Table != nullptr && Sup.Table != nullptr &&
           Sub.Table->getRefType() == Sup.Table->getRefType() &&
           MatchLimits(Sub.Table->getLimit(), Sup.Table->getLimit());
  case ExternalType::Memory:
    return Sub.Memory != nullptr && Sup.Memory != nullptr &&
           MatchLimits(Sub.Memory->getLimit(), Sup.Memory->getLimit());
  case ExternalType::Global:
    return Sub.Global != nullptr && Sup.Global != nullptr &&
           Sub.Global->getValType() == Sup.Global->getValType() &&
           Sub.Global->getValMut() == Sup.Global->getValMut();
  default:
    return false;
  }
}

bool ComponentContext::containsBorrow(
    const ComponentContext::QualValType &Q) noexcept {
  const auto N = normalizeValType(Q);
  if (!N.Valid || N.DVT == nullptr) {
    return false;
  }
  const auto &D = *N.DVT;
  auto Sub = [&](const ComponentValType &VT) noexcept {
    return containsBorrow({VT, N.Home, N.Remap});
  };
  if (D.isBorrowTy()) {
    return true;
  }
  if (D.isRecordTy()) {
    for (const auto &LT : D.getRecord().LabelTypes) {
      if (Sub(LT.getValType())) {
        return true;
      }
    }
    return false;
  }
  if (D.isVariantTy()) {
    for (const auto &[Label, Ty] : D.getVariant().Cases) {
      if (Ty.has_value() && Sub(*Ty)) {
        return true;
      }
    }
    return false;
  }
  if (D.isListTy()) {
    return Sub(D.getList().ValTy);
  }
  if (D.isTupleTy()) {
    for (const auto &Ty : D.getTuple().Types) {
      if (Sub(Ty)) {
        return true;
      }
    }
    return false;
  }
  if (D.isOptionTy()) {
    return Sub(D.getOption().ValTy);
  }
  if (D.isResultTy()) {
    const auto &R = D.getResult();
    return (R.ValTy.has_value() && Sub(*R.ValTy)) ||
           (R.ErrTy.has_value() && Sub(*R.ErrTy));
  }
  return false;
}

void ComponentContext::collectResources(
    const ComponentContext::QualValType &Q,
    std::unordered_set<uint32_t> &Out) noexcept {
  collectResourcesNormal(normalizeValType(Q), Out);
}

void ComponentContext::collectResourcesNormal(
    const NormalVal &N, std::unordered_set<uint32_t> &Out) noexcept {
  if (!N.Valid || N.DVT == nullptr) {
    return;
  }
  const auto &D = *N.DVT;
  auto Sub = [&](const ComponentValType &VT) noexcept {
    collectResources({VT, N.Home, N.Remap}, Out);
  };
  if (D.isOwnTy() || D.isBorrowTy()) {
    const uint32_t Idx = D.isOwnTy() ? D.getOwn().Idx : D.getBorrow().Idx;
    if (auto Id = handleResourceId(N.Home, N.Remap, Idx)) {
      Out.insert(*Id);
    }
    return;
  }
  if (D.isRecordTy()) {
    for (const auto &LT : D.getRecord().LabelTypes) {
      Sub(LT.getValType());
    }
  } else if (D.isVariantTy()) {
    for (const auto &[Label, Ty] : D.getVariant().Cases) {
      if (Ty.has_value()) {
        Sub(*Ty);
      }
    }
  } else if (D.isListTy()) {
    Sub(D.getList().ValTy);
  } else if (D.isTupleTy()) {
    for (const auto &Ty : D.getTuple().Types) {
      Sub(Ty);
    }
  } else if (D.isOptionTy()) {
    Sub(D.getOption().ValTy);
  } else if (D.isResultTy()) {
    if (D.getResult().ValTy.has_value()) {
      Sub(*D.getResult().ValTy);
    }
    if (D.getResult().ErrTy.has_value()) {
      Sub(*D.getResult().ErrTy);
    }
  }
}

void ComponentContext::collectResources(
    const ComponentContext::ExternInfo &Info,
    std::unordered_set<uint32_t> &Out) noexcept {
  switch (Info.K) {
  case ComponentContext::ExternInfo::Kind::CoreModule:
    return;
  case ComponentContext::ExternInfo::Kind::Func: {
    if (Info.Func.FT == nullptr) {
      return;
    }
    for (const auto &P : Info.Func.FT->getParamList()) {
      collectResources({P.getValType(), Info.Func.Home, Info.Func.Remap}, Out);
    }
    for (const auto &R : Info.Func.FT->getResultList()) {
      collectResources({R.getValType(), Info.Func.Home, Info.Func.Remap}, Out);
    }
    return;
  }
  case ComponentContext::ExternInfo::Kind::Value:
    collectResources(Info.Value, Out);
    return;
  case ComponentContext::ExternInfo::Kind::Type: {
    const auto &E = Info.Type;
    if (E.ResourceId.has_value()) {
      Out.insert(*E.ResourceId);
      return;
    }
    if (E.Inst != nullptr) {
      for (const auto &[Name, Sub] : E.Inst->Exports) {
        collectResources(Sub, Out);
      }
      return;
    }
    if (E.Comp != nullptr) {
      for (const auto &[Name, Sub] : E.Comp->Imports) {
        collectResources(Sub, Out);
      }
      for (const auto &[Name, Sub] : E.Comp->Exports) {
        collectResources(Sub, Out);
      }
      return;
    }
    if (E.DT != nullptr && E.DT->isDefValType()) {
      collectResourcesNormal(normalizeEntry(E), Out);
      return;
    }
    if (E.DT != nullptr && E.DT->isFuncType()) {
      for (const auto &P : E.DT->getFuncType().getParamList()) {
        collectResources({P.getValType(), E.Home, E.Remap}, Out);
      }
      for (const auto &R : E.DT->getFuncType().getResultList()) {
        collectResources({R.getValType(), E.Home, E.Remap}, Out);
      }
    }
    return;
  }
  case ComponentContext::ExternInfo::Kind::Instance:
  case ComponentContext::ExternInfo::Kind::Component:
    // Instances carry no imports, so one walk covers both shapes.
    if (Info.Shape != nullptr) {
      for (const auto &[Name, Sub] : Info.Shape->Imports) {
        collectResources(Sub, Out);
      }
      for (const auto &[Name, Sub] : Info.Shape->Exports) {
        collectResources(Sub, Out);
      }
    }
    return;
  }
}

bool ComponentContext::originatesIn(
    uint32_t Id, const ComponentContext::Scope &Scope) const noexcept {
  const auto &Entry = getResource(Id);
  for (const auto *S = Entry.Origin; S != nullptr; S = S->Parent) {
    if (S == &Scope) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Instantiation.
// ---------------------------------------------------------------------------

namespace {
// Rebuilds info graphs across an instantiation boundary, remapping resource
// ids eagerly in direct fields and lazily (via remap chains) in AST leaves.
struct Freshener {
  ComponentContext &Ctx;
  const ComponentContext::ResourceMap
      *Node; // combined substitution + freshening
  std::unordered_map<const ComponentContext::ComponentShape *,
                     const ComponentContext::ComponentShape *>
      ShapeMemo;

  // NOLINTBEGIN(misc-no-recursion)
  ComponentContext::ExternInfo
  rebuild(const ComponentContext::ExternInfo &E) noexcept {
    ComponentContext::ExternInfo R = E;
    switch (E.K) {
    case ComponentContext::ExternInfo::Kind::CoreModule:
      break;
    case ComponentContext::ExternInfo::Kind::Func:
      R.Func.Remap = Ctx.composeRemap(Node, E.Func.Remap);
      break;
    case ComponentContext::ExternInfo::Kind::Value:
      R.Value.Remap = Ctx.composeRemap(Node, E.Value.Remap);
      break;
    case ComponentContext::ExternInfo::Kind::Type:
      R.Type = rebuildEntry(E.Type);
      break;
    case ComponentContext::ExternInfo::Kind::Instance:
    case ComponentContext::ExternInfo::Kind::Component:
      R.Shape = rebuildShape(E.Shape);
      break;
    }
    return R;
  }

  ComponentContext::TypeEntry
  rebuildEntry(const ComponentContext::TypeEntry &E) noexcept {
    ComponentContext::TypeEntry R = E;
    if (E.ResourceId.has_value()) {
      R.ResourceId = Node->apply(*E.ResourceId);
      if (*R.ResourceId != *E.ResourceId) {
        R.NameId = Ctx.getResource(*R.ResourceId).NameId;
      }
    }
    R.Remap = Ctx.composeRemap(Node, E.Remap);
    if (E.Inst != nullptr) {
      R.Inst = rebuildShape(E.Inst);
    }
    if (E.Comp != nullptr) {
      R.Comp = rebuildShape(E.Comp);
    }
    return R;
  }

  // One walk for both shapes: instances have no imports, components no
  // declaration order, so each loop is a no-op for the other kind.
  const ComponentContext::ComponentShape *
  rebuildShape(const ComponentContext::ComponentShape *S) noexcept {
    if (S == nullptr) {
      return nullptr;
    }
    auto It = ShapeMemo.find(S);
    if (It != ShapeMemo.end()) {
      return It->second;
    }
    auto *R = Ctx.newComponentShape();
    ShapeMemo.emplace(S, R);
    R->DeclScope = S->DeclScope;
    R->Order = S->Order;
    for (const auto &[Name, E] : S->Imports) {
      R->Imports.emplace_back(Name, rebuild(E));
    }
    for (const auto &[Name, E] : S->Exports) {
      R->Exports.emplace(Name, rebuild(E));
    }
    return R;
  }
  // NOLINTEND(misc-no-recursion)
};
} // namespace

// Rebuilds an instance view minting fresh identities for the resources its
// own declarations introduced (each import/export of an instance shape is a
// distinct instantiation of its declared resources).
const ComponentContext::ComponentShape *
ComponentContext::freshenDeclaredResources(
    const ComponentContext::ComponentShape *Inst, bool FromImport) noexcept {
  // Only declaration-built shapes carry their own declared resources;
  // concrete instances' resources belong to the enclosing component.
  if (Inst == nullptr || Inst->DeclScope == nullptr ||
      Inst->DeclScope->K != ComponentContext::Scope::Kind::InstanceType) {
    return Inst;
  }
  std::unordered_set<uint32_t> Ids;
  ComponentContext::ExternInfo Probe;
  Probe.K = ComponentContext::ExternInfo::Kind::Instance;
  Probe.Shape = Inst;
  collectResources(Probe, Ids);
  auto *Node = newResourceMap();
  for (const uint32_t Id : Ids) {
    if (originatesIn(Id, *Inst->DeclScope)) {
      Node->Map.emplace(Id, addResource(nullptr, &top(), FromImport));
    }
  }
  if (Node->Map.empty()) {
    return Inst;
  }
  Freshener F{*this, Node, {}};
  return F.rebuildShape(Inst);
}

Expect<const ComponentContext::ComponentShape *>
ComponentContext::instantiateComponentShape(
    const ComponentContext::ComponentShape &CI,
    Span<const AST::Component::InstantiateArg<AST::Component::SortIndex>>
        Args) noexcept {
  // Resolve arguments; names must be unique.
  std::unordered_map<std::string_view, ComponentContext::ExternInfo> ArgMap;
  for (const auto &Arg : Args) {
    EXPECTED_TRY(auto Info, resolveSortIndex(Arg.getIndex()));
    if (!ArgMap.emplace(Arg.getName(), Info).second) {
      spdlog::error(ErrCode::Value::ComponentDuplicateArg);
      spdlog::error("    Duplicate instantiation argument '{}'."sv,
                    Arg.getName());
      return Unexpect(ErrCode::Value::ComponentDuplicateArg);
    }
    // Values are consumed by being passed as arguments.
    if (!Arg.getIndex().getSort().isCore() &&
        Arg.getIndex().getSort().getSortType() ==
            AST::Component::Sort::SortType::Value) {
      auto &VE = top().Values[Arg.getIndex().getIdx()];
      if (VE.Consumed) {
        spdlog::error(ErrCode::Value::ComponentValueAlreadyConsumed);
        return Unexpect(ErrCode::Value::ComponentValueAlreadyConsumed);
      }
      VE.Consumed = true;
    }
  }
  // Match every import; accumulate the resource substitution.
  ResourceSubst Subst;
  for (const auto &[Name, Req] : CI.Imports) {
    auto It = ArgMap.find(Name);
    if (It == ArgMap.end()) {
      spdlog::error(ErrCode::Value::ComponentMissingImport);
      spdlog::error("    Missing instantiation argument '{}'."sv, Name);
      return Unexpect(ErrCode::Value::ComponentMissingImport);
    }
    MatchWhy = ErrCode::Value::Success;
    if (!matchExtern(It->second, Req, Subst)) {
      const auto Code = MatchWhy != ErrCode::Value::Success
                            ? MatchWhy
                            : ErrCode::Value::ArgTypeMismatch;
      spdlog::error(Code);
      spdlog::error("    Instantiation argument '{}' has an incompatible "
                    "type."sv,
                    Name);
      return Unexpect(Code);
    }
  }

  // Combined remap: substituted imports + freshened defined resources.
  std::unordered_set<uint32_t> Reachable;
  for (const auto &[Name, E] : CI.Exports) {
    collectResources(E, Reachable);
  }
  auto *Node = newResourceMap();
  Node->Map = Subst;
  for (const uint32_t Id : Reachable) {
    if (Node->Map.count(Id) != 0) {
      continue;
    }
    const auto &Entry = getResource(Id);
    if (!Entry.FromImport && CI.DeclScope != nullptr &&
        originatesIn(Id, *CI.DeclScope)) {
      // Freshened ids carry no definition body: the fresh resource belongs
      // to the created instance, so it is never canon-local here.
      Node->Map.emplace(Id, addResource(nullptr, &top(), false));
    }
  }

  Freshener F{*this, Node, {}};
  auto *Result = newComponentShape();
  Result->DeclScope = CI.DeclScope;
  Result->Synthetic = !CI.FromDecl;
  for (const auto &[Name, E] : CI.Exports) {
    Result->Exports.emplace(Name, F.rebuild(E));
    Result->Order.emplace_back(Name);
  }
  ComponentContext::ExternInfo Probe;
  Probe.K = ComponentContext::ExternInfo::Kind::Instance;
  Probe.Shape = Result;
  EXPECTED_TRY(checkTypeSize(sizeOfExtern(Probe)));
  EXPECTED_TRY(checkTypeDepth(depthOfExtern(Probe)));
  return Result;
}

Expect<ComponentContext::ExternInfo> ComponentContext::resolveSortIndex(
    const AST::Component::SortIndex &SI) noexcept {
  ComponentContext::ExternInfo Info;
  const auto &S = top();
  const auto &Sort = SI.getSort();
  const uint32_t Idx = SI.getIdx();
  if (Sort.isCore()) {
    if (Sort.getCoreSortType() == AST::Component::Sort::CoreSortType::Module) {
      const auto *Mod = S.getCoreModule(Idx);
      if (Mod == nullptr) {
        spdlog::error(ErrCode::Value::DefTypeIndexOutOfBounds);
        spdlog::error("    Core module index {} out of bounds (size {})."sv,
                      Idx, S.CoreModules.size());
        return Unexpect(ErrCode::Value::DefTypeIndexOutOfBounds);
      }
      Info.K = ComponentContext::ExternInfo::Kind::CoreModule;
      Info.CoreMod = Mod;
      return Info;
    }
    spdlog::error(ErrCode::Value::InvalidTypeReference);
    spdlog::error(
        "    Core sorts other than module cannot be used at component level."sv);
    return Unexpect(ErrCode::Value::InvalidTypeReference);
  }
  switch (Sort.getSortType()) {
  case AST::Component::Sort::SortType::Func: {
    const auto *F = S.getFunc(Idx);
    if (F == nullptr) {
      spdlog::error(ErrCode::Value::DefTypeIndexOutOfBounds);
      spdlog::error("    Function index {} out of bounds (size {})."sv, Idx,
                    S.Funcs.size());
      return Unexpect(ErrCode::Value::DefTypeIndexOutOfBounds);
    }
    Info.K = ComponentContext::ExternInfo::Kind::Func;
    Info.Func = *F;
    return Info;
  }
  case AST::Component::Sort::SortType::Value: {
    if (Idx >= S.Values.size()) {
      spdlog::error(ErrCode::Value::DefTypeIndexOutOfBounds);
      spdlog::error("    Value index {} out of bounds (size {})."sv, Idx,
                    S.Values.size());
      return Unexpect(ErrCode::Value::DefTypeIndexOutOfBounds);
    }
    Info.K = ComponentContext::ExternInfo::Kind::Value;
    Info.Value = S.Values[Idx].Type;
    return Info;
  }
  case AST::Component::Sort::SortType::Type: {
    const auto *E = S.getType(Idx);
    if (E == nullptr) {
      spdlog::error(ErrCode::Value::DefTypeIndexOutOfBounds);
      spdlog::error("    Type index {} out of bounds (size {})."sv, Idx,
                    S.Types.size());
      return Unexpect(ErrCode::Value::DefTypeIndexOutOfBounds);
    }
    Info.K = ComponentContext::ExternInfo::Kind::Type;
    Info.Type = *E;
    return Info;
  }
  case AST::Component::Sort::SortType::Component: {
    const auto *C = S.getComponent(Idx);
    if (C == nullptr) {
      spdlog::error(ErrCode::Value::DefTypeIndexOutOfBounds);
      spdlog::error("    Component index {} out of bounds (size {})."sv, Idx,
                    S.Components.size());
      return Unexpect(ErrCode::Value::DefTypeIndexOutOfBounds);
    }
    Info.K = ComponentContext::ExternInfo::Kind::Component;
    Info.Shape = C;
    return Info;
  }
  case AST::Component::Sort::SortType::Instance: {
    const auto *I = S.getInstance(Idx);
    if (I == nullptr) {
      spdlog::error(ErrCode::Value::DefTypeIndexOutOfBounds);
      spdlog::error("    Instance index {} out of bounds (size {})."sv, Idx,
                    S.Instances.size());
      return Unexpect(ErrCode::Value::DefTypeIndexOutOfBounds);
    }
    Info.K = ComponentContext::ExternInfo::Kind::Instance;
    Info.Shape = I;
    return Info;
  }
  default:
    spdlog::error(ErrCode::Value::DefTypeIndexOutOfBounds);
    return Unexpect(ErrCode::Value::DefTypeIndexOutOfBounds);
  }
}

// Effective size of a value type (spec-limit metric; memoized per node).
uint64_t ComponentContext::sizeOfValType(
    const ComponentContext::QualValType &Q) noexcept {
  const auto N = normalizeValType(Q);
  if (!N.Valid || N.DVT == nullptr) {
    return 1;
  }
  auto It = TypeSizeMemo.find(N.DVT);
  if (It != TypeSizeMemo.end()) {
    return It->second;
  }
  TypeSizeMemo.emplace(N.DVT, 1); // Break cycles defensively.
  const auto &D = *N.DVT;
  uint64_t Size = 1;
  auto Add = [&](const ComponentValType &VT) noexcept {
    Size += sizeOfValType({VT, N.Home, N.Remap});
  };
  if (D.isRecordTy()) {
    for (const auto &LT : D.getRecord().LabelTypes) {
      Add(LT.getValType());
    }
  } else if (D.isVariantTy()) {
    for (const auto &[Label, Ty] : D.getVariant().Cases) {
      if (Ty.has_value()) {
        Add(*Ty);
      } else {
        Size += 1;
      }
    }
  } else if (D.isListTy()) {
    Add(D.getList().ValTy);
  } else if (D.isTupleTy()) {
    for (const auto &Ty : D.getTuple().Types) {
      Add(Ty);
    }
  } else if (D.isOptionTy()) {
    Add(D.getOption().ValTy);
  } else if (D.isResultTy()) {
    if (D.getResult().ValTy.has_value()) {
      Add(*D.getResult().ValTy);
    }
    if (D.getResult().ErrTy.has_value()) {
      Add(*D.getResult().ErrTy);
    }
  } else if (D.isFlagsTy()) {
    Size += D.getFlags().Labels.size();
  } else if (D.isEnumTy()) {
    Size += D.getEnum().Labels.size();
  }
  TypeSizeMemo[N.DVT] = Size;
  return Size;
}

uint64_t ComponentContext::sizeOfExtern(
    const ComponentContext::ExternInfo &Info) noexcept {
  switch (Info.K) {
  case ComponentContext::ExternInfo::Kind::CoreModule:
    return Info.CoreMod != nullptr
               ? 1 + Info.CoreMod->Imports.size() + Info.CoreMod->Exports.size()
               : 1;
  case ComponentContext::ExternInfo::Kind::Func: {
    if (Info.Func.FT == nullptr) {
      return 1;
    }
    auto It = TypeSizeMemo.find(Info.Func.FT);
    if (It != TypeSizeMemo.end()) {
      return It->second;
    }
    uint64_t Size = 1;
    for (const auto &P : Info.Func.FT->getParamList()) {
      Size += sizeOfValType({P.getValType(), Info.Func.Home, Info.Func.Remap});
    }
    for (const auto &R : Info.Func.FT->getResultList()) {
      Size += sizeOfValType({R.getValType(), Info.Func.Home, Info.Func.Remap});
    }
    TypeSizeMemo.emplace(Info.Func.FT, Size);
    return Size;
  }
  case ComponentContext::ExternInfo::Kind::Value:
    return 1 + sizeOfValType(Info.Value);
  case ComponentContext::ExternInfo::Kind::Type: {
    const auto &E = Info.Type;
    if (E.ResourceId.has_value()) {
      return 1;
    }
    if (E.Inst != nullptr || E.Comp != nullptr) {
      const void *Key = E.Inst != nullptr ? static_cast<const void *>(E.Inst)
                                          : static_cast<const void *>(E.Comp);
      auto It = TypeSizeMemo.find(Key);
      if (It != TypeSizeMemo.end()) {
        return It->second;
      }
      TypeSizeMemo.emplace(Key, 1);
      uint64_t Size = 1;
      if (E.Inst != nullptr) {
        for (const auto &[Name, Sub] : E.Inst->Exports) {
          Size += 1 + sizeOfExtern(Sub);
        }
      } else {
        for (const auto &[Name, Sub] : E.Comp->Imports) {
          Size += 1 + sizeOfExtern(Sub);
        }
        for (const auto &[Name, Sub] : E.Comp->Exports) {
          Size += 1 + sizeOfExtern(Sub);
        }
      }
      TypeSizeMemo[Key] = Size;
      return Size;
    }
    if (E.DT != nullptr && E.DT->isDefValType()) {
      const auto N = normalizeEntry(E);
      if (N.DVT == nullptr) {
        return 1;
      }
      // Reuse the valtype metric through the composite node directly.
      auto It = TypeSizeMemo.find(N.DVT);
      if (It != TypeSizeMemo.end()) {
        return It->second;
      }
      uint64_t Size = 1;
      const auto &D = *N.DVT;
      auto Add = [&](const ComponentValType &VT) noexcept {
        Size += sizeOfValType({VT, N.Home, N.Remap});
      };
      if (D.isRecordTy()) {
        for (const auto &LT : D.getRecord().LabelTypes) {
          Add(LT.getValType());
        }
      } else if (D.isVariantTy()) {
        for (const auto &[Label, Ty] : D.getVariant().Cases) {
          if (Ty.has_value()) {
            Add(*Ty);
          } else {
            Size += 1;
          }
        }
      } else if (D.isListTy()) {
        Add(D.getList().ValTy);
      } else if (D.isTupleTy()) {
        for (const auto &Ty : D.getTuple().Types) {
          Add(Ty);
        }
      } else if (D.isOptionTy()) {
        Add(D.getOption().ValTy);
      } else if (D.isResultTy()) {
        if (D.getResult().ValTy.has_value()) {
          Add(*D.getResult().ValTy);
        }
        if (D.getResult().ErrTy.has_value()) {
          Add(*D.getResult().ErrTy);
        }
      } else if (D.isFlagsTy()) {
        Size += D.getFlags().Labels.size();
      } else if (D.isEnumTy()) {
        Size += D.getEnum().Labels.size();
      }
      TypeSizeMemo[N.DVT] = Size;
      return Size;
    }
    if (E.DT != nullptr && E.DT->isFuncType()) {
      ComponentContext::ExternInfo FI;
      FI.K = ComponentContext::ExternInfo::Kind::Func;
      FI.Func = {&E.DT->getFuncType(), E.Home, E.Remap};
      return sizeOfExtern(FI);
    }
    return 1;
  }
  case ComponentContext::ExternInfo::Kind::Instance:
  case ComponentContext::ExternInfo::Kind::Component: {
    // Instances carry no imports, so one walk covers both shapes.
    if (Info.Shape == nullptr) {
      return 1;
    }
    auto It = TypeSizeMemo.find(Info.Shape);
    if (It != TypeSizeMemo.end()) {
      return It->second;
    }
    TypeSizeMemo.emplace(Info.Shape, 1);
    uint64_t Size = 1;
    for (const auto &[Name, Sub] : Info.Shape->Imports) {
      Size += 1 + sizeOfExtern(Sub);
    }
    for (const auto &[Name, Sub] : Info.Shape->Exports) {
      Size += 1 + sizeOfExtern(Sub);
    }
    TypeSizeMemo[Info.Shape] = Size;
    return Size;
  }
  }
  return 1;
}

// Depth of a value type: primitives and leaves count 1; wrappers add 1.
// Guards the recursive canonical-ABI walkers (matches the reference
// engine's nesting limit).
// NOLINTNEXTLINE(misc-no-recursion)
uint64_t ComponentContext::depthOfValType(
    const ComponentContext::QualValType &Q) noexcept {
  const auto N = normalizeValType(Q);
  if (!N.Valid || N.DVT == nullptr) {
    return 1;
  }
  auto It = TypeDepthMemo.find(N.DVT);
  if (It != TypeDepthMemo.end()) {
    return It->second;
  }
  TypeDepthMemo.emplace(N.DVT, 1); // Break cycles defensively.
  const auto &D = *N.DVT;
  uint64_t Max = 0;
  auto Sub = [&](const ComponentValType &VT) noexcept {
    Max = std::max(Max, depthOfValType({VT, N.Home, N.Remap}));
  };
  if (D.isRecordTy()) {
    for (const auto &LT : D.getRecord().LabelTypes) {
      Sub(LT.getValType());
    }
  } else if (D.isVariantTy()) {
    for (const auto &[Name, VT] : D.getVariant().Cases) {
      if (VT.has_value()) {
        Sub(*VT);
      }
    }
  } else if (D.isListTy()) {
    Sub(D.getList().ValTy);
  } else if (D.isTupleTy()) {
    for (const auto &VT : D.getTuple().Types) {
      Sub(VT);
    }
  } else if (D.isOptionTy()) {
    Sub(D.getOption().ValTy);
  } else if (D.isResultTy()) {
    if (D.getResult().ValTy.has_value()) {
      Sub(*D.getResult().ValTy);
    }
    if (D.getResult().ErrTy.has_value()) {
      Sub(*D.getResult().ErrTy);
    }
  }
  const uint64_t Depth = Max + 1;
  TypeDepthMemo[N.DVT] = Depth;
  return Depth;
}

// NOLINTNEXTLINE(misc-no-recursion)
uint64_t ComponentContext::depthOfExtern(
    const ComponentContext::ExternInfo &Info) noexcept {
  uint64_t Max = 0;
  switch (Info.K) {
  case ComponentContext::ExternInfo::Kind::Func:
    if (Info.Func.FT != nullptr) {
      for (const auto &P : Info.Func.FT->getParamList()) {
        Max = std::max(Max, depthOfValType({P.getValType(), Info.Func.Home,
                                            Info.Func.Remap}));
      }
      for (const auto &R : Info.Func.FT->getResultList()) {
        Max = std::max(Max, depthOfValType({R.getValType(), Info.Func.Home,
                                            Info.Func.Remap}));
      }
    }
    break;
  case ComponentContext::ExternInfo::Kind::Type:
    if (Info.Type.DT != nullptr && Info.Type.DT->isDefValType()) {
      const auto &D = Info.Type.DT->getDefValType();
      auto Sub = [&](const ComponentValType &VT) noexcept {
        Max = std::max(
            Max, depthOfValType({VT, Info.Type.Home, Info.Type.Remap}) + 1);
      };
      if (D.isListTy()) {
        Sub(D.getList().ValTy);
      } else if (D.isOptionTy()) {
        Sub(D.getOption().ValTy);
      } else if (D.isRecordTy()) {
        for (const auto &LT : D.getRecord().LabelTypes) {
          Sub(LT.getValType());
        }
      } else if (D.isTupleTy()) {
        for (const auto &VT : D.getTuple().Types) {
          Sub(VT);
        }
      } else if (D.isVariantTy()) {
        for (const auto &[Name, VT] : D.getVariant().Cases) {
          if (VT.has_value()) {
            Sub(*VT);
          }
        }
      } else if (D.isResultTy()) {
        if (D.getResult().ValTy.has_value()) {
          Sub(*D.getResult().ValTy);
        }
        if (D.getResult().ErrTy.has_value()) {
          Sub(*D.getResult().ErrTy);
        }
      }
    }
    break;
  case ComponentContext::ExternInfo::Kind::Instance:
    if (Info.Shape != nullptr) {
      for (const auto &[Name, E] : Info.Shape->Exports) {
        Max = std::max(Max, depthOfExtern(E));
      }
    }
    break;
  default:
    break;
  }
  return Max;
}

Expect<void> ComponentContext::checkTypeDepth(uint64_t Depth) noexcept {
  // The reference engine bounds value-type nesting at 100.
  if (Depth > 100) {
    spdlog::error(ErrCode::Value::ComponentTypeNestingDepth);
    spdlog::error("    Value type nesting depth {} exceeds the limit."sv,
                  Depth);
    return Unexpect(ErrCode::Value::ComponentTypeNestingDepth);
  }
  return {};
}

Expect<void> ComponentContext::checkTypeSize(uint64_t Size) noexcept {
  if (Size >= MaxTypeSize) {
    spdlog::error(ErrCode::Value::ComponentTypeSizeLimit);
    spdlog::error("    Effective type size {} exceeds the limit of {}."sv, Size,
                  MaxTypeSize);
    return Unexpect(ErrCode::Value::ComponentTypeSizeLimit);
  }
  return {};
}

// NOLINTEND(misc-no-recursion)

} // namespace Validator
} // namespace WasmEdge
