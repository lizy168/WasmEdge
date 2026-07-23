// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The WasmEdge Authors

#include "linker/writer.h"

#include <limits>

namespace WasmEdge {
namespace LLVM {
namespace Linker {

namespace {

Expect<void> writeError() noexcept {
  return Unexpect(ErrCode::Value::IllegalPath);
}

} // namespace

Writer::Writer(const std::filesystem::path &Path) noexcept
    : Stream(Path, std::ios_base::binary | std::ios_base::trunc) {}

Expect<void> Writer::writeByte(uint8_t Data) noexcept {
  if (Buffer != nullptr) {
    Buffer->push_back(Data);
    return {};
  }
  Stream.put(static_cast<char>(Data));
  return Stream ? Expect<void>{} : writeError();
}

Expect<void> Writer::writeU32(uint32_t Data) noexcept {
  constexpr uint8_t PayloadMask = UINT8_C(0x7F);
  constexpr uint8_t ContinuationBit = UINT8_C(0x80);
  constexpr uint8_t PayloadBits = 7;
  do {
    uint8_t Byte = static_cast<uint8_t>(Data & PayloadMask);
    Data >>= PayloadBits;
    if (Data != 0) {
      Byte |= ContinuationBit;
    }
    EXPECTED_TRY(writeByte(Byte));
  } while (Data != 0);
  return {};
}

Expect<void> Writer::writeU64(uint64_t Data) noexcept {
  constexpr uint8_t PayloadMask = UINT8_C(0x7F);
  constexpr uint8_t ContinuationBit = UINT8_C(0x80);
  constexpr uint8_t PayloadBits = 7;
  do {
    uint8_t Byte = static_cast<uint8_t>(Data & PayloadMask);
    Data >>= PayloadBits;
    if (Data != 0) {
      Byte |= ContinuationBit;
    }
    EXPECTED_TRY(writeByte(Byte));
  } while (Data != 0);
  return {};
}

Expect<void> Writer::writeName(std::string_view Data) noexcept {
  if (Data.size() > std::numeric_limits<uint32_t>::max()) {
    return writeError();
  }
  EXPECTED_TRY(writeU32(static_cast<uint32_t>(Data.size())));
  if (Buffer != nullptr) {
    Buffer->insert(Buffer->end(), Data.begin(), Data.end());
    return {};
  }
  Stream.write(Data.data(), static_cast<std::streamsize>(Data.size()));
  return Stream ? Expect<void>{} : writeError();
}

Expect<void> Writer::write(Span<const Byte> Data) noexcept {
  if (Buffer != nullptr) {
    Buffer->insert(Buffer->end(), Data.begin(), Data.end());
    return {};
  }
  if (Data.size() >
      static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
    return writeError();
  }
  Stream.write(reinterpret_cast<const char *>(Data.data()),
               static_cast<std::streamsize>(Data.size()));
  return Stream ? Expect<void>{} : writeError();
}

Expect<void> Writer::close() noexcept {
  if (Buffer != nullptr) {
    return {};
  }
  Stream.flush();
  if (!Stream) {
    return writeError();
  }
  Stream.close();
  return Stream ? Expect<void>{} : writeError();
}

} // namespace Linker
} // namespace LLVM
} // namespace WasmEdge
