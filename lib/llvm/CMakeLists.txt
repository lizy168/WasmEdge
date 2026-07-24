# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright The WasmEdge Authors

find_package(LLVM REQUIRED HINTS "${LLVM_CMAKE_PATH}" "${LLVM_DIR}")
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(LLVMConfig)
include(AddLLVM)

find_package(LLD HINTS "${LLD_CMAKE_PATH}" "${LLD_DIR}" "${LLVM_LIBRARY_DIR}/cmake/lld")
if(LLD_FOUND)
  list(APPEND CMAKE_MODULE_PATH "${LLD_CMAKE_DIR}")
endif()

set(LLVM_INCLUDE_DIR "${LLVM_INCLUDE_DIR}" PARENT_SCOPE)
set(LLD_INCLUDE_DIRS "${LLD_INCLUDE_DIRS}" PARENT_SCOPE)

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
  linker/layout.cpp
  linker/eh_frame.cpp
  linker/link_graph.cpp
  linker/native_linker.cpp
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

if(MSVC)
  set_source_files_properties(linker/native_linker.cpp PROPERTIES COMPILE_OPTIONS /EHsc)
  set_source_files_properties(linker/universal_wasm_writer.cpp PROPERTIES COMPILE_OPTIONS /EHsc)
  set_source_files_properties(linker/writer.cpp PROPERTIES COMPILE_OPTIONS /EHsc)
else()
  set_source_files_properties(linker/native_linker.cpp PROPERTIES COMPILE_OPTIONS -fexceptions)
  set_source_files_properties(linker/universal_wasm_writer.cpp PROPERTIES COMPILE_OPTIONS -fexceptions)
  set_source_files_properties(linker/writer.cpp PROPERTIES COMPILE_OPTIONS -fexceptions)
endif()

if(WASMEDGE_LINK_LLVM_STATIC)
  wasmedge_add_library(wasmedgeLLVM
    ${WASMEDGE_LLVM_SOURCES}
  )

  target_link_libraries(wasmedgeLLVM
    PUBLIC
    wasmedgeCommon
    wasmedgeSystem
    std::filesystem
    ${WASMEDGE_LLVM_LINK_STATIC_COMPONENTS}
    ${WASMEDGE_LLVM_LINK_SHARED_COMPONENTS}
  )
else()
  if(APPLE)
    list(APPEND LLD_LIBS lldMachO)
  elseif(WIN32)
    list(APPEND LLD_LIBS lldCOFF)
    set(EXTRA_COMPONENTS DebugInfoPDB LibDriver WindowsManifest)
  else()
    list(APPEND LLD_LIBS lldELF)
  endif()

  list(APPEND LLD_LIBS lldCommon)
  if(LLVM_VERSION_MAJOR LESS_EQUAL 13)
    list(APPEND LLD_LIBS lldDriver)
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
    ${LLD_LIBS}
    std::filesystem
    ${CMAKE_THREAD_LIBS_INIT}
    LINK_COMPONENTS
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
  ${LLD_INCLUDE_DIRS}
)

target_include_directories(wasmedgeLLVM
  PUBLIC
  ${PROJECT_BINARY_DIR}/include
)

include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_LINK_OPTIONS "-Wl,-lc,--exclude-libs=libc.a")
check_cxx_source_compiles("int main(){}" SUPPORT_EXCLUDE_LIBS)

if(SUPPORT_EXCLUDE_LIBS)
  file(GLOB LLD_ALL_LIBS ${LLVM_LIBRARY_DIR}/liblld*.a)
  list(TRANSFORM LLD_ALL_LIBS REPLACE "^.*/" "")
  string(JOIN : LLD_ALL_LIBS_COLON ${LLD_ALL_LIBS})
  if(NOT LLD_ALL_LIBS_COLON STREQUAL "")
    target_link_options(wasmedgeLLVM
      PUBLIC
      "SHELL:-Wl,--exclude-libs=${LLD_ALL_LIBS_COLON}"
    )
  endif()
endif()
