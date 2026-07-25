// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "llvm/codegen.h"

#include "common/defines.h"
#include "common/hash.h"
#include "data.h"
#include "linker/native_linker.h"
#include "llvm.h"

#include <lld/Common/Driver.h>

#include <fstream>
#include <mutex>
#include <random>
#if WASMEDGE_OS_MACOS && LLVM_VERSION_MAJOR >= 15
#include <llvm/Target/TargetMachine.h>
#endif

#if LLVM_VERSION_MAJOR >= 14
#include <lld/Common/CommonLinkerContext.h>
#endif
#if LLVM_VERSION_MAJOR >= 17
#if WASMEDGE_OS_MACOS
LLD_HAS_DRIVER(macho)
#elif WASMEDGE_OS_LINUX
LLD_HAS_DRIVER(elf)
#elif WASMEDGE_OS_WINDOWS
LLD_HAS_DRIVER(coff)
#endif
#endif

#if WASMEDGE_OS_MACOS
#include <sys/utsname.h>
#include <unistd.h>
#endif
namespace LLVM = WasmEdge::LLVM;
using namespace std::literals;

namespace {

using namespace WasmEdge;

#if WASMEDGE_OS_MACOS
// Get current OS version
std::string getOSVersion() noexcept {
  struct utsname Info;
  if (::uname(&Info)) {
    // default os version
    return "13.0.0"s;
  }
  std::string_view Release = Info.release;
  auto GetNum = [](std::string_view &String) noexcept {
    uint64_t Result = 0;
    while (!String.empty() && std::isdigit(String[0])) {
      Result = Result * 10 + (String[0] - '0');
      String = String.substr(1);
    }
    return Result;
  };
  auto SkipDot = [](std::string_view &String) noexcept {
    if (!String.empty() && String[0] == '.')
      String = String.substr(1);
  };
  uint64_t Major = GetNum(Release);
  SkipDot(Release);
  uint64_t Minor = GetNum(Release);
  SkipDot(Release);
  uint64_t Micro = GetNum(Release);

  if (Major == 0) {
    Major = 8;
  }
  if (Major <= 19) {
    Micro = 0;
    Minor = Major - 4;
    Major = 10;
  } else {
    Micro = 0;
    Minor = 0;
    Major = 11 + Major - 20;
  }

  return fmt::format("{}.{}.{}"sv, Major, Minor, Micro);
}
// Get current SDK version
std::string getSDKVersion() noexcept {
  // TODO: parse SDKSettings.json to get real version
  return "12.1"s;
}
// Get current SDK version in pair
std::pair<uint32_t, uint32_t> getSDKVersionPair() noexcept {
  // TODO: parse SDKSettings.json to get real version
  return {UINT32_C(12), UINT32_C(1)};
}
#endif

std::filesystem::path uniquePath(const std::filesystem::path Model) noexcept {
  using size_type = std::filesystem::path::string_type::size_type;
  using value_type = std::filesystem::path::value_type;
  static const auto Hex = "0123456789abcdef"sv;
  std::uniform_int_distribution<size_type> Distribution(0, Hex.size() - 1);
  auto String = Model.native();
  for (size_type N = String.size(), I = 0; I < N; ++I) {
    if (String[I] == static_cast<value_type>('%')) {
      String[I] = static_cast<value_type>(Hex[Distribution(Hash::RandEngine)]);
    }
  }
  return String;
}

std::filesystem::path createTemp(const std::filesystem::path Model) noexcept {
  while (true) {
    auto Result = uniquePath(Model);
    std::error_code Error;
    if (!std::filesystem::exists(Result, Error)) {
      if (Error) {
        return {};
      }
      return Result;
    }
  }
}

// Write output object and link
Expect<void> outputNativeLibrary(const std::filesystem::path &OutputPath,
                                 const LLVM::MemoryBuffer &OSVec) noexcept {
  spdlog::info("output start"sv);
  std::filesystem::path ObjectName;
  {
    // tempfile
    std::filesystem::path OPath(OutputPath);
#if WASMEDGE_OS_WINDOWS
    OPath.replace_extension("%%%%%%%%%%.obj"sv);
#else
    OPath.replace_extension("%%%%%%%%%%.o"sv);
#endif
    ObjectName = createTemp(OPath);
    if (ObjectName.empty()) {
      // TODO:return error
      spdlog::error("so file creation failed:{}"sv, OPath.u8string());
      return Unexpect(ErrCode::Value::IllegalPath);
    }
    std::ofstream OS(ObjectName, std::ios_base::binary);
    OS.write(OSVec.data(), static_cast<std::streamsize>(OSVec.size()));
    OS.close();
  }

  // link
  // Serialize LLD invocations: CommonLinkerContext is a global singleton, so
  // concurrent link() calls from multiple threads would corrupt it.
  static std::mutex LldMutex;
  std::lock_guard<std::mutex> Lock(LldMutex);
  bool LinkResult = false;
#if WASMEDGE_OS_MACOS
  const auto OSVersion = getOSVersion();
  const auto SDKVersion = getSDKVersion();
#if LLVM_VERSION_MAJOR >= 14
  // LLVM 14 replaces the older mach_o lld implementation with the new one.
  // So we need to change the namespace after LLVM 14.x was released.
  // Reference: https://reviews.llvm.org/D114842
  LinkResult = lld::macho::link(
#else
  LinkResult = lld::mach_o::link(
#endif
      std::initializer_list<const char *>{
          "lld", "-arch",
#if defined(__x86_64__)
          "x86_64",
#elif defined(__aarch64__)
          "arm64",
#else
#error Unsupported architecture on the MacOS!
#endif
#if LLVM_VERSION_MAJOR >= 14
          // LLVM 14 replaces the older mach_o lld implementation with the new
          // one. And it require -arch and -platform_version to always be
          // specified. Reference: https://reviews.llvm.org/D97799
          "-platform_version", "macos", OSVersion.c_str(), SDKVersion.c_str(),
#else
          "-sdk_version", SDKVersion.c_str(),
#endif
          "-dylib", "-demangle", "-macosx_version_min", OSVersion.c_str(),
          "-syslibroot", "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
          ObjectName.u8string().c_str(), "-o", OutputPath.u8string().c_str()},
#elif WASMEDGE_OS_LINUX
  LinkResult = lld::elf::link(
      std::initializer_list<const char *>{"ld.lld", "--eh-frame-hdr",
                                          "--shared", "--gc-sections",
                                          "--discard-all", ObjectName.c_str(),
                                          "-o", OutputPath.u8string().c_str()},
#elif WASMEDGE_OS_WINDOWS
  LinkResult = lld::coff::link(
      std::initializer_list<const char *>{
          "lld-link", "-dll", "-base:0", "-nologo",
          ObjectName.u8string().c_str(),
          ("-out:" + OutputPath.u8string()).c_str()},
#endif

#if LLVM_VERSION_MAJOR >= 14
      llvm::outs(), llvm::errs(), false, false
#elif LLVM_VERSION_MAJOR >= 10
      false, llvm::outs(), llvm::errs()
#else
      false, llvm::errs()
#endif
  );

#if LLVM_VERSION_MAJOR >= 14
  lld::CommonLinkerContext::destroy();
#endif

  if (LinkResult) {
    std::error_code Error;
    std::filesystem::remove(ObjectName, Error);
#if WASMEDGE_OS_WINDOWS
    std::filesystem::path LibPath(OutputPath);
    LibPath.replace_extension(".lib"sv);
    std::filesystem::remove(LibPath, Error);
#endif

    spdlog::info("codegen done"sv);
  } else {
    spdlog::error("link error"sv);
  }

#if WASMEDGE_OS_MACOS
  // codesign
  if (LinkResult) {
    pid_t PID = ::fork();
    if (PID == -1) {
      spdlog::error("codesign error on fork:{}"sv, std::strerror(errno));
    } else if (PID == 0) {
      execlp("/usr/bin/codesign", "codesign", "-s", "-",
             OutputPath.u8string().c_str(), nullptr);
      std::exit(256);
    } else {
      int ChildStat;
      waitpid(PID, &ChildStat, 0);
      if (const int Status = WEXITSTATUS(ChildStat); Status != 0) {
        spdlog::error("codesign exited with status {}"sv, Status);
      }
    }
  }
#endif

  return {};
}

} // namespace

namespace WasmEdge::LLVM {

Expect<void> CodeGen::codegen(Span<const Byte> WasmData, Data D,
                              std::filesystem::path OutputPath) noexcept {
  // CompileFromBuffer skips the loader, so reject empty path here.
  if (OutputPath.empty()) {
    spdlog::error("output failed: empty output path"sv);
    return Unexpect(ErrCode::Value::IllegalPath);
  }

  auto LLContext = D.extract().getLLContext();
  auto &LLModule = D.extract().LLModule;
  auto &TM = D.extract().TM;
  std::filesystem::path LLPath(OutputPath);
  LLPath.replace_extension("ll"sv);

#if WASMEDGE_OS_MACOS
  {
    const auto [Major, Minor] = getSDKVersionPair();
    LLModule.addFlag(LLVMModuleFlagBehaviorError, "SDK Version"sv,
                     LLVM::Value::getConstVector32(LLContext, {Major, Minor}));
  }
#endif

  if (Conf.getCompilerConfigure().getOutputFormat() !=
      CompilerConfigure::OutputFormat::Wasm) {
    // create wasm.code and wasm.size
    auto Int32Ty = LLContext.getInt32Ty();
    auto Content = LLVM::Value::getConstString(
        LLContext,
        {reinterpret_cast<const char *>(WasmData.data()), WasmData.size()},
        true);
    LLModule.addGlobal(Content.getType(), true, LLVMExternalLinkage, Content,
                       "wasm.code");
    LLModule.addGlobal(Int32Ty, true, LLVMExternalLinkage,
                       LLVM::Value::getConstInt(Int32Ty, WasmData.size()),
                       "wasm.size");
    for (auto Fn = LLModule.getFirstFunction(); Fn; Fn = Fn.getNextFunction()) {
      if (Fn.getLinkage() == LLVMInternalLinkage) {
        Fn.setLinkage(LLVMExternalLinkage);
        Fn.setVisibility(LLVMProtectedVisibility);
        Fn.setDSOLocal(true);
        Fn.setDLLStorageClass(LLVMDLLExportStorageClass);
      }
    }
  } else {
    for (auto Fn = LLModule.getFirstFunction(); Fn; Fn = Fn.getNextFunction()) {
      if (Fn.getLinkage() == LLVMInternalLinkage) {
        Fn.setLinkage(LLVMPrivateLinkage);
        Fn.setDSOLocal(true);
        Fn.setDLLStorageClass(LLVMDefaultStorageClass);
      }
    }
  }

  // set dllexport
  for (auto GV = LLModule.getFirstGlobal(); GV; GV = GV.getNextGlobal()) {
    if (GV.getLinkage() == LLVMExternalLinkage) {
      GV.setVisibility(LLVMProtectedVisibility);
      GV.setDSOLocal(true);
      GV.setDLLStorageClass(LLVMDLLExportStorageClass);
    }
  }

  if (Conf.getCompilerConfigure().isDumpIR()) {
    if (auto ErrorMessage = LLModule.printModuleToFile("wasm.ll");
        unlikely(ErrorMessage)) {
      spdlog::error("wasm.ll open error:{}"sv, ErrorMessage.string_view());
      return WasmEdge::Unexpect(WasmEdge::ErrCode::Value::IllegalPath);
    }
  }

  spdlog::info("codegen start"sv);
  // codegen
  {
    if (Conf.getCompilerConfigure().isDumpIR()) {
      if (auto ErrorMessage = LLModule.printModuleToFile("wasm-opt.ll")) {
        // TODO:return error
        spdlog::error("printModuleToFile failed"sv);
        return Unexpect(ErrCode::Value::IllegalPath);
      }
    }

#if WASMEDGE_OS_MACOS
    constexpr std::string_view UnwindAnchor = R"(
.private_extern _wasmedge_unwind_anchor
_wasmedge_unwind_anchor:
  .cfi_startproc
  .cfi_def_cfa_offset 16
  .cfi_escape 0x2e, 0x10
  ret
  .cfi_endproc
)"sv;
    std::string OriginalAssembly;
#if LLVM_VERSION_MAJOR >= 15
    auto *TargetMachine = reinterpret_cast<llvm::TargetMachine *>(TM.unwrap());
    auto OriginalDwarfUnwind = TargetMachine->Options.MCOptions.EmitDwarfUnwind;
#endif
    OriginalAssembly = LLModule.getInlineAsm();
    std::string Assembly = OriginalAssembly;
    Assembly.append(UnwindAnchor);
    LLModule.setInlineAsm(Assembly);
#if LLVM_VERSION_MAJOR >= 15
    TargetMachine->Options.MCOptions.EmitDwarfUnwind =
        llvm::EmitDwarfUnwindType::Always;
#endif
#endif
    auto [OSVec, ErrorMessage] =
        TM.emitToMemoryBuffer(LLModule, LLVMObjectFile);
#if WASMEDGE_OS_MACOS
    LLModule.setInlineAsm(OriginalAssembly);
#if LLVM_VERSION_MAJOR >= 15
    TargetMachine->Options.MCOptions.EmitDwarfUnwind = OriginalDwarfUnwind;
#endif
#endif
    if (ErrorMessage) {
      // TODO:return error
      spdlog::error("addPassesToEmitFile failed"sv);
      return Unexpect(ErrCode::Value::IllegalPath);
    }

    if (Conf.getCompilerConfigure().isDumpIR()) {
      std::ofstream OS("wasm.o", std::ios_base::binary);
      if (!OS) {
        return Unexpect(ErrCode::Value::IllegalPath);
      }
      OS.write(OSVec.data(), static_cast<std::streamsize>(OSVec.size()));
      OS.close();
      if (!OS) {
        return Unexpect(ErrCode::Value::IllegalPath);
      }
    }

    if (Conf.getCompilerConfigure().getOutputFormat() ==
        CompilerConfigure::OutputFormat::Wasm) {
      const auto Object = Span<const Byte>(
          reinterpret_cast<const Byte *>(OSVec.data()), OSVec.size());
      EXPECTED_TRY(Linker::NativeLinker::link(
          Object, WasmData, OutputPath, Linker::OutputKind::UniversalWasm));
    } else {
      EXPECTED_TRY(outputNativeLibrary(OutputPath, OSVec));
    }
  }

  return {};
}

} // namespace WasmEdge::LLVM
