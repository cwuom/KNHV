cmake_minimum_required(VERSION 3.18)

project(Nested_HV LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Nested_HV is a Windows kernel driver and requires the Windows WDK")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8 OR
   (CMAKE_CXX_COMPILER_ARCHITECTURE_ID AND
    NOT CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "x64"))
    message(FATAL_ERROR "Nested_HV requires an AMD64/x64 Windows kernel toolchain")
endif()

# MASM is supplied by the MSVC/WDK toolchain. Do not hard-code a Visual
# Studio installation path; CMake resolves ml64 from the selected developer
# environment (or a caller may pass CMAKE_ASM_MASM_COMPILER explicitly).
if(NOT CMAKE_ASM_MASM_COMPILER)
    set(CMAKE_ASM_MASM_COMPILER ml64)
endif()
enable_language(ASM_MASM)

# WDK path. FindWdk.cmake auto-detects the latest installed WDK. A caller can
# select a particular kit with -DWDK_CONTENT_ROOT=... without editing files.
set(WDK_CONTENT_ROOT "" CACHE PATH "Windows Kits root (for example C:/Program Files (x86)/Windows Kits/10)")
if(WDK_CONTENT_ROOT)
    set(ENV{WDKContentRoot} "${WDK_CONTENT_ROOT}")
endif()
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)

option(NESTED_HV_SIGN "Sign the driver as a post-build step" OFF)
option(NESTED_HV_BUILD_TESTS "Build the user-mode C++ contract/smoke test" ON)
set(NESTED_HV_SIGNTOOL "" CACHE FILEPATH "Path to signtool.exe (required when NESTED_HV_SIGN=ON)")
set(NESTED_HV_SIGN_CERT "" CACHE FILEPATH "PFX containing the signing private key (required when NESTED_HV_SIGN=ON)")
set(NESTED_HV_SIGN_PASSWORD "" CACHE STRING "PFX password (optional; avoid storing secrets in CMake cache)")
set(NESTED_HV_SIGN_TIMESTAMP_URL "" CACHE STRING "RFC3161 timestamp URL (optional for test certificates)")

# sources
set(SOURCES
        src/main.cpp
        src/vmm.cpp
        src/asm/arch.asm
        src/header/common.h
        src/header/vmx.h
)

wdk_add_driver(Nested_HV ${SOURCES})

# Kernel-only C/C++ options belong on the driver target.  Keeping them out of
# the user-mode contract test avoids contradictory MSVC switches such as
# /EHsc followed by /EHs-c- and /GS followed by /GS-, while the MASM source is
# still protected by the language-qualified expressions below.
target_compile_options(Nested_HV PRIVATE
        "$<$<COMPILE_LANGUAGE:C,CXX>:/utf-8>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/EHs-c->"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/GS->"
        # MSVC's option spelling is case-sensitive here: /Zc (lowercase c).
        # Using /ZC makes cl parse it as /Z plus stray switches, disables
        # extensions, and causes WDK 28000 headers to fail on anonymous structs.
        "$<$<COMPILE_LANGUAGE:C,CXX>:/Zc:wchar_t->"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/std:c++17>"
)

# link. WDK targets point at the selected kit, so no machine-specific library
# directory is needed here.
target_link_libraries(Nested_HV
        WDK::NTOSKRNL
        WDK::HAL
)
if(TARGET WDK::WDMSEC)
    target_link_libraries(Nested_HV WDK::WDMSEC)
endif()

# Keep the WDK-provided GsDriverEntry startup wrapper (it initializes the
# kernel-mode security cookie and calls DriverEntry). Always emit a linker PDB
# alongside the SYS, including Release builds, so WinDbg can resolve symbols.
set_property(TARGET Nested_HV APPEND_STRING PROPERTY LINK_FLAGS " /INTEGRITYCHECK /DEBUG")

# Signing is opt-in. An unsigned build remains useful for static analysis and
# avoids silently selecting an unrelated certificate from the local machine.
if(NESTED_HV_SIGN)
    if(NOT NESTED_HV_SIGNTOOL OR NOT EXISTS "${NESTED_HV_SIGNTOOL}")
        message(FATAL_ERROR "NESTED_HV_SIGN=ON requires a valid NESTED_HV_SIGNTOOL path")
    endif()
    if(NOT NESTED_HV_SIGN_CERT OR NOT EXISTS "${NESTED_HV_SIGN_CERT}")
        message(FATAL_ERROR "NESTED_HV_SIGN=ON requires a valid NESTED_HV_SIGN_CERT path")
    endif()

    set(_nested_hv_sign_args sign /v /fd SHA256)
    if(NESTED_HV_SIGN_PASSWORD)
        list(APPEND _nested_hv_sign_args /p "${NESTED_HV_SIGN_PASSWORD}")
    endif()
    if(NESTED_HV_SIGN_TIMESTAMP_URL)
        list(APPEND _nested_hv_sign_args /tr "${NESTED_HV_SIGN_TIMESTAMP_URL}" /td SHA256)
    endif()
    list(APPEND _nested_hv_sign_args /f "${NESTED_HV_SIGN_CERT}" "$<TARGET_FILE:Nested_HV>")

    add_custom_command(
            TARGET Nested_HV
            POST_BUILD
            COMMAND "${NESTED_HV_SIGNTOOL}" ${_nested_hv_sign_args}
            COMMENT "Signing ${PROJECT_NAME}.sys"
            VERBATIM
    )
endif()

# The contract test is a normal user-mode executable.  It intentionally does
# not include WDK headers or execute VMX instructions; it validates the
# kernel/assembly ABI and can optionally exercise the installed service on an
# isolated test machine.  Keeping it as a separate target prevents
# /kernel,/NODEFAULTLIB driver flags from leaking into the test binary.
if(NESTED_HV_BUILD_TESTS)
    enable_testing()
    add_executable(Nested_HV_ContractTests tests/vmx_contract_test.cpp)
    target_compile_definitions(Nested_HV_ContractTests PRIVATE
            NESTED_HV_SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(Nested_HV_ContractTests PRIVATE
            /W4 /EHsc /GR /GS /permissive- /std:c++17)
    target_link_libraries(Nested_HV_ContractTests PRIVATE advapi32 wintrust)
    add_test(NAME Nested_HV_ContractTests
            COMMAND Nested_HV_ContractTests --root "${CMAKE_CURRENT_SOURCE_DIR}")
endif()
