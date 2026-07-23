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

Expect<std::filesystem::path>
createUniqueSibling(const std::filesystem::path &Output) noexcept {
  llvm::SmallString<128> Path;
  int File = -1;
  const auto Model = Output.string() + ".tmp-%%%%%%";
  if (llvm::sys::fs::createUniqueFile(Model, File, Path) ||
      llvm::sys::fs::closeFile(File)) {
    if (File != -1) {
      llvm::sys::fs::closeFile(File);
    }
    std::error_code Error;
    std::filesystem::remove(std::filesystem::path(Path.str().str()), Error);
    return Unexpect(ErrCode::Value::IllegalPath);
  }
  return std::filesystem::path(Path.str().str());
}

class TempFile {
public:
  explicit TempFile(std::filesystem::path Value) : Path(std::move(Value)) {}
  ~TempFile() {
    if (!Published) {
      std::error_code Error;
      std::filesystem::remove(Path, Error);
    }
  }

  void publish() noexcept { Published = true; }
  const std::filesystem::path &path() const noexcept { return Path; }

private:
  std::filesystem::path Path;
  bool Published = false;
};

} // namespace

Expect<void> NativeLinker::link(Span<const Byte> Object, Span<const Byte> Wasm,
                                const std::filesystem::path &Output,
                                OutputKind Kind) noexcept {
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

  EXPECTED_TRY(auto TempPath, createUniqueSibling(Output));
  TempFile Temp(std::move(TempPath));
  EXPECTED_TRY(UniversalWasmWriter::write(Graph, Wasm, Temp.path()));
#if WASMEDGE_OS_WINDOWS
  if (!winapi::MoveFileExW(Temp.path().c_str(), Output.c_str(),
                           winapi::MOVEFILE_REPLACE_EXISTING_)) {
    return linkError();
  }
#else
  std::error_code Error;
  std::filesystem::rename(Temp.path(), Output, Error);
  if (Error) {
    return linkError();
  }
#endif
  Temp.publish();
  return {};
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
