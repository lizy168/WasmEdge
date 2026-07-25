# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The WasmEdge Authors

find_package(LLVM REQUIRED HINTS "${LLVM_CMAKE_PATH}" "${LLVM_DIR}")
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(LLVMConfig)
include(AddLLVM)

set(LLVM_INCLUDE_DIR "${LLVM_INCLUDE_DIR}" PARENT_SCOPE)

set(WASMEDGE_LLVM_SOURCES
  compiler.cpp
  compiler/context.cpp
  compiler/function_compiler.cpp
  compiler/memoryInstr.cpp
  compiler/numericInstr.cpp
  compiler/refInstr.cpp
  compiler/threadInstr.cpp
  compiler/vectorInstr.cpp
  codegen.cpp
  data.cpp
  jit.cpp
  lazyjit.cpp
  linker/elf_writer.cpp
  linker/layout.cpp
  linker/eh_frame.cpp
  linker/link_graph.cpp
  linker/macho_writer.cpp
  linker/native_linker.cpp
  linker/pe_writer.cpp
  linker/object_reader.cpp
  linker/relocation.cpp
  linker/relocation_aarch64.cpp
  linker/relocation_arm.cpp
  linker/relocation_riscv.cpp
  linker/relocation_s390x.cpp
  linker/relocation_x86_64.cpp
  linker/universal_wasm_writer.cpp
  linker/writer.cpp
  llvm.cpp
)

set(WASMEDGE_LLVM_LINKER_SOURCES
  linker/elf_writer.cpp
  linker/eh_frame.cpp
  linker/layout.cpp
  linker/link_graph.cpp
  linker/macho_writer.cpp
  linker/native_linker.cpp
  linker/pe_writer.cpp
  linker/object_reader.cpp
  linker/relocation.cpp
  linker/relocation_aarch64.cpp
  linker/relocation_arm.cpp
  linker/relocation_riscv.cpp
  linker/relocation_s390x.cpp
  linker/relocation_x86_64.cpp
  linker/universal_wasm_writer.cpp
  linker/writer.cpp
)
if(MSVC)
  set_source_files_properties(${WASMEDGE_LLVM_LINKER_SOURCES}
    PROPERTIES COMPILE_OPTIONS /EHsc)
else()
  set_source_files_properties(${WASMEDGE_LLVM_LINKER_SOURCES}
    PROPERTIES COMPILE_OPTIONS -fexceptions)
endif()

if(WASMEDGE_LINK_LLVM_STATIC)
  wasmedge_add_library(wasmedgeLLVM
    ${WASMEDGE_LLVM_SOURCES}
  )

  target_link_libraries(wasmedgeLLVM
    PUBLIC
    wasmedgeCommon
    wasmedgeSystem
    wasmedgeLoader
    std::filesystem
    ${WASMEDGE_LLVM_LINK_STATIC_COMPONENTS}
    ${WASMEDGE_LLVM_LINK_SHARED_COMPONENTS}
  )
else()
  if(WIN32)
    set(EXTRA_COMPONENTS DebugInfoPDB LibDriver WindowsManifest)
  endif()

  # Command line warning D9025 : overriding '/EHs' with '/EHs-'
  # prevent LLVM from adding /EHs-c-.
  if(WIN32)
    set(LLVM_REQUIRES_EH ON)
  endif()

  llvm_add_library(wasmedgeLLVM
    ${WASMEDGE_LLVM_SOURCES}
    LINK_LIBS
    wasmedgeCommon
    wasmedgeSystem
    wasmedgeLoader
    std::filesystem
    ${CMAKE_THREAD_LIBS_INIT}
    LINK_COMPONENTS
    binaryformat
    core
    linker
    lto
    native
    nativecodegen
    object
    option
    passes
    support
    orcjit
    transformutils
    ${EXTRA_COMPONENTS}
  )
endif()

wasmedge_setup_target(wasmedgeLLVM)

target_include_directories(wasmedgeLLVM
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(wasmedgeLLVM
  SYSTEM
  PRIVATE
  ${LLVM_INCLUDE_DIR}
)

target_include_directories(wasmedgeLLVM
  PUBLIC
  ${PROJECT_BINARY_DIR}/include
)
