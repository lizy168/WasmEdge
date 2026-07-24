// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/native_linker.h"

#include "common/defines.h"
#include "linker/layout.h"
#include "linker/object_reader.h"
#include "linker/relocation.h"
#include "linker/universal_wasm_writer.h"
#if WASMEDGE_OS_WINDOWS
#include "system/winapi.h"
#endif

#include <llvm/ADT/SmallString.h>
#include <llvm/Support/FileSystem.h>

#include <optional>
#if !WASMEDGE_OS_WINDOWS
#include <sys/stat.h>
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

Expect<void> NativeLinker::link(Span<const Byte> Object, Span<const Byte> Wasm,
                                const std::filesystem::path &Output,
                                OutputKind Kind) noexcept {
  try {
    if (Kind != OutputKind::UniversalWasm || Output.empty()) {
      return linkError();
    }
    const auto TargetValue = hostTarget();
    if (!TargetValue) {
      return Unexpect(ErrCode::Value::AOTNotImpl);
    }
    EXPECTED_TRY(auto Graph, ObjectReader::read(Object, *TargetValue));
#if WASMEDGE_OS_MACOS && defined(__aarch64__)
    constexpr uint64_t HostPageSize = 16384;
#else
    constexpr uint64_t HostPageSize = 4096;
#endif
    if (auto Result = layout(Graph, 0, HostPageSize); !Result) {
      return linkError();
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
    Writer OutputWriter(Guard.release());
    EXPECTED_TRY(UniversalWasmWriter::write(Graph, Wasm, OutputWriter));
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
  } catch (...) {
    return linkError();
  }
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
