// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/native_linker.h"

#include "common/configure.h"
#include "common/defines.h"
#include "linker/eh_frame.h"
#include "linker/elf_writer.h"
#include "linker/layout.h"
#include "linker/macho_writer.h"
#include "linker/object_reader.h"
#include "linker/relocation.h"
#include "linker/universal_wasm_writer.h"
#include "loader/loader.h"
#if WASMEDGE_OS_WINDOWS
#include "system/winapi.h"
#endif

#include <llvm/ADT/SmallString.h>
#include <llvm/Support/FileSystem.h>

#include <array>
#include <optional>
#include <stdexcept>
#if !WASMEDGE_OS_WINDOWS
#include <cerrno>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
extern char **environ;
#endif

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

Expect<void> linkError() noexcept {
  return Unexpect(ErrCode::Value::IllegalPath);
}

std::optional<Target> hostTarget() noexcept {
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
  return std::nullopt;
#endif
}

ObjectFormat hostFormat() noexcept {
#if WASMEDGE_OS_LINUX
  return ObjectFormat::ELF;
#elif WASMEDGE_OS_MACOS
  return ObjectFormat::MachO;
#elif WASMEDGE_OS_WINDOWS
  return ObjectFormat::COFF;
#endif
}

struct TempFile {
  std::filesystem::path Path;
  int File = -1;
};

Expect<TempFile> createUniqueSibling(const std::filesystem::path &Output) {
  llvm::SmallString<128> Path;
  int File = -1;
  const auto Model = Output.u8string() + ".tmp-%%%%%%";
  if (llvm::sys::fs::createUniqueFile(Model, File, Path)) {
    if (File != -1) {
      llvm::sys::fs::closeFile(File);
    }
    std::error_code Error;
    std::filesystem::remove(std::filesystem::path(Path.str().str()), Error);
    return Unexpect(ErrCode::Value::IllegalPath);
  }
  return TempFile{std::filesystem::u8path(Path.str().str()), File};
}

class TempGuard {
public:
  TempGuard(std::filesystem::path Value, int File)
      : Path(std::move(Value)), File(File) {}
  ~TempGuard() {
    if (File != -1)
      llvm::sys::fs::closeFile(File);
    if (!Published) {
      std::error_code Error;
      std::filesystem::remove(Path, Error);
    }
  }

  void publish() noexcept { Published = true; }
  const std::filesystem::path &path() const noexcept { return Path; }
  int release() noexcept {
    const int Result = File;
    File = -1;
    return Result;
  }

private:
  std::filesystem::path Path;
  int File;
  bool Published = false;
};

} // namespace

Expect<void>
Internal::signMachO(const std::filesystem::path &Path,
                    const std::filesystem::path &SignExecutable,
                    const std::filesystem::path &VerifyExecutable) noexcept {
#if WASMEDGE_OS_WINDOWS
  static_cast<void>(Path);
  static_cast<void>(SignExecutable);
  static_cast<void>(VerifyExecutable);
  return linkError();
#else
  try {
    const auto SignProgram = SignExecutable.string();
    const auto VerifyProgram = VerifyExecutable.string();
    const auto File = Path.string();
    const std::array<std::array<const char *, 6>, 2> Arguments{{
        {SignProgram.c_str(), "--force", "--sign", "-", File.c_str(), nullptr},
        {VerifyProgram.c_str(), "--verify", "--strict", "--verbose=2",
         File.c_str(), nullptr},
    }};
    const std::array<const std::string *, 2> Programs{&SignProgram,
                                                      &VerifyProgram};
    for (size_t I = 0; I < Arguments.size(); ++I) {
      const auto &Values = Arguments[I];
      pid_t Child = -1;
      const int SpawnResult =
          ::posix_spawn(&Child, Programs[I]->c_str(), nullptr, nullptr,
                        const_cast<char *const *>(Values.data()), environ);
      if (SpawnResult != 0)
        return linkError();
      int Status = 0;
      while (::waitpid(Child, &Status, 0) == -1) {
        if (errno != EINTR)
          return linkError();
      }
      if (!WIFEXITED(Status) || WEXITSTATUS(Status) != 0)
        return linkError();
    }
    return {};
  } catch (...) {
    return linkError();
  }
#endif
}

Expect<void>
Internal::publishMachO(const std::filesystem::path &Temporary,
                       const std::filesystem::path &Output,
                       const std::filesystem::path &SignExecutable,
                       const std::filesystem::path &VerifyExecutable) noexcept {
  try {
    struct Guard {
      const std::filesystem::path &Path;
      bool Published = false;
      ~Guard() {
        if (!Published) {
          std::error_code Error;
          std::filesystem::remove(Path, Error);
        }
      }
    } Cleanup{Temporary};
    EXPECTED_TRY(signMachO(Temporary, SignExecutable, VerifyExecutable));
    std::error_code Error;
    std::filesystem::rename(Temporary, Output, Error);
    if (Error)
      return linkError();
    Cleanup.Published = true;
    return {};
  } catch (...) {
    return linkError();
  }
}

Expect<void> NativeLinker::link(Span<const Byte> Object, Span<const Byte> Wasm,
                                const std::filesystem::path &Output,
                                OutputKind Kind) noexcept {
  try {
    if (Output.empty()) {
      return linkError();
    }
#if WASMEDGE_OS_LINUX
    if (Kind != OutputKind::UniversalWasm && Kind != OutputKind::ELF)
      return linkError();
#elif WASMEDGE_OS_MACOS
    if (Kind != OutputKind::UniversalWasm && Kind != OutputKind::MachO)
      return linkError();
#else
    if (Kind != OutputKind::UniversalWasm)
      return linkError();
#endif
    const auto TargetValue = hostTarget();
    if (!TargetValue) {
      return Unexpect(ErrCode::Value::AOTNotImpl);
    }
    Configure Conf;
    Conf.addProposal(Proposal::Threads);
    Loader::Loader WasmLoader(Conf);
    if (!WasmLoader.parseModule(Wasm))
      return linkError();
    EXPECTED_TRY(auto Graph,
                 ObjectReader::read(Object, *TargetValue,
                                    Kind == OutputKind::UniversalWasm ||
                                            Kind == OutputKind::MachO
                                        ? ObjectReaderPolicy::Universal
                                        : ObjectReaderPolicy::Default));
    if (Graph.format() != hostFormat())
      return linkError();
#if WASMEDGE_OS_MACOS && defined(__aarch64__)
    constexpr uint64_t HostPageSize = 16384;
#else
    constexpr uint64_t HostPageSize = 4096;
#endif
    if (Kind == OutputKind::ELF && !ELFWriter::layout(Graph)) {
      return linkError();
    }
    if (Kind == OutputKind::MachO && !MachOWriter::layout(Graph)) {
      return linkError();
    }
    if (Kind != OutputKind::ELF && Kind != OutputKind::MachO &&
        !layout(Graph, 0, HostPageSize)) {
      return linkError();
    }
    if (Graph.format() == ObjectFormat::MachO) {
      EXPECTED_TRY(normalizeMachOEHFrame(Graph));
      EXPECTED_TRY(validateMachOEHFrameCoverage(Graph));
    }
    EXPECTED_TRY(applyRelocations(Graph));

    EXPECTED_TRY(auto Temp, createUniqueSibling(Output));
    TempGuard Guard(std::move(Temp.Path), Temp.File);
#if !WASMEDGE_OS_WINDOWS
    struct stat DestinationStat{};
    if (::stat(Output.c_str(), &DestinationStat) == 0 &&
        ::fchmod(Temp.File, DestinationStat.st_mode & 07777) != 0)
      return linkError();
#endif
    {
      Writer OutputWriter(Guard.release());
      if (Kind == OutputKind::ELF) {
        EXPECTED_TRY(ELFWriter::write(Graph, OutputWriter));
      } else if (Kind == OutputKind::MachO) {
        EXPECTED_TRY(MachOWriter::write(Graph, OutputWriter));
      } else {
        EXPECTED_TRY(UniversalWasmWriter::write(Graph, Wasm, OutputWriter));
      }
    }
#if WASMEDGE_OS_MACOS
    if (Kind == OutputKind::MachO) {
      EXPECTED_TRY(Internal::publishMachO(
          Guard.path(), Output, "/usr/bin/codesign", "/usr/bin/codesign"));
      Guard.publish();
      return {};
    }
#endif
#if WASMEDGE_OS_WINDOWS
    if (!winapi::MoveFileExW(Guard.path().c_str(), Output.c_str(),
                             winapi::MOVEFILE_REPLACE_EXISTING_)) {
      return linkError();
    }
#else
    std::error_code Error;
    std::filesystem::rename(Guard.path(), Output, Error);
    if (Error) {
      return linkError();
    }
#endif
    Guard.publish();
    return {};
  } catch (const std::bad_alloc &) {
    return linkError();
  } catch (const std::length_error &) {
    return linkError();
  } catch (const std::filesystem::filesystem_error &) {
    return linkError();
  }
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
