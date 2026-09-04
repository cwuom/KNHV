cmake_minimum_required(VERSION 3.18)

project(KNHV LANGUAGES C CXX)

# Keep the compilation database available to CMake Tools and other IDEs even
# when a caller does not provide a cache option explicitly.
if(NOT DEFINED CMAKE_EXPORT_COMPILE_COMMANDS OR
   CMAKE_EXPORT_COMPILE_COMMANDS STREQUAL "")
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL
        "Generate compile_commands.json for IDE tooling" FORCE)
endif()

# CMake adds user-mode Debug switches to every MSVC target.  Remove switches
# that are invalid or noisy for a WDK driver before the target is created
if(MSVC)
    function(knhv_strip_msvc_flag variable_name flag_regex)
        if(DEFINED ${variable_name})
            set(_knhv_flags "${${variable_name}}")
            separate_arguments(_knhv_flags WINDOWS_COMMAND
                               "${_knhv_flags}")
            list(FILTER _knhv_flags EXCLUDE REGEX "${flag_regex}")
            list(JOIN _knhv_flags " " _knhv_flags_text)
            set(${variable_name} "${_knhv_flags_text}" CACHE STRING
                "MSVC flags filtered for the WDK target" FORCE)
        endif()
    endfunction()

    knhv_strip_msvc_flag(CMAKE_C_FLAGS_DEBUG "^[/-]RTC1$")
    knhv_strip_msvc_flag(CMAKE_CXX_FLAGS "^[/-]GR$")
    knhv_strip_msvc_flag(CMAKE_CXX_FLAGS "^[/-]EHsc$")
    knhv_strip_msvc_flag(CMAKE_CXX_FLAGS_DEBUG "^[/-]RTC1$")
    knhv_strip_msvc_flag(CMAKE_EXE_LINKER_FLAGS_DEBUG
                               "^[/-]INCREMENTAL$")
endif()

if(NOT WIN32)
    message(FATAL_ERROR "KNHV is a Windows kernel driver and requires the Windows WDK")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8 OR
   (CMAKE_CXX_COMPILER_ARCHITECTURE_ID AND
    NOT CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "x64"))
    message(FATAL_ERROR "KNHV requires an AMD64/x64 Windows kernel toolchain")
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

# CMake launched outside a Visual Studio developer shell does not always
# populate MSVC's implicit standard-header search path. Derive the compiler
# include directory instead of relying on process-global INCLUDE variables.
set(_knhv_toolchain_includes "")
set(_knhv_user_toolchain_libdirs "")
if(MSVC AND CMAKE_CXX_COMPILER)
    get_filename_component(_knhv_msvc_bin
                           "${CMAKE_CXX_COMPILER}" DIRECTORY)
    get_filename_component(_knhv_msvc_host_bin
                           "${_knhv_msvc_bin}" DIRECTORY)
    get_filename_component(_knhv_msvc_bin_root
                           "${_knhv_msvc_host_bin}" DIRECTORY)
    get_filename_component(_knhv_msvc_root
                           "${_knhv_msvc_bin_root}" DIRECTORY)
    set(_knhv_msvc_include "${_knhv_msvc_root}/include")
    if(EXISTS "${_knhv_msvc_include}")
        list(APPEND _knhv_toolchain_includes
             "${_knhv_msvc_include}")
    endif()
    set(_knhv_msvc_lib "${_knhv_msvc_root}/lib/x64")
    if(EXISTS "${_knhv_msvc_lib}")
        list(APPEND _knhv_user_toolchain_libdirs
             "${_knhv_msvc_lib}")
    endif()
endif()
if(WDK_INC_VERSION AND
   EXISTS "${WDK_ROOT}/Include/${WDK_INC_VERSION}/ucrt")
    list(APPEND _knhv_toolchain_includes
         "${WDK_ROOT}/Include/${WDK_INC_VERSION}/ucrt")
endif()
if(WDK_INC_VERSION)
    foreach(_knhv_wdk_user_subdir IN ITEMS shared um)
        set(_knhv_wdk_user_include
            "${WDK_ROOT}/Include/${WDK_INC_VERSION}/${_knhv_wdk_user_subdir}")
        if(EXISTS "${_knhv_wdk_user_include}")
            list(APPEND _knhv_toolchain_includes
                 "${_knhv_wdk_user_include}")
        endif()
    endforeach()
endif()
if(WDK_LIB_VERSION)
    foreach(_knhv_wdk_user_lib_subdir IN ITEMS um ucrt)
        set(_knhv_wdk_user_lib
            "${WDK_ROOT}/Lib/${WDK_LIB_VERSION}/${_knhv_wdk_user_lib_subdir}/x64")
        if(EXISTS "${_knhv_wdk_user_lib}")
            list(APPEND _knhv_user_toolchain_libdirs
                 "${_knhv_wdk_user_lib}")
        endif()
    endforeach()
endif()

option(KNHV_SIGN "Sign the driver as a post-build step" OFF)
option(KNHV_BUILD_TESTS "Build the user-mode C++ contract/smoke test" ON)
option(KNHV_FAULT_INJECTION
       "Enable deterministic launch fault injection for isolated tests" OFF)
set(KNHV_TEST_FAIL_CPU "-1" CACHE STRING
    "Logical processor index used by fault injection (-1 disables it)")
set(KNHV_TEST_FAIL_STAGE "0" CACHE STRING
    "Fault injection stage number (0 disables it)")
set(KNHV_BUILD_ID "0" CACHE STRING
    "Numeric build identifier embedded in crash telemetry")
set(KNHV_SIGNTOOL "" CACHE FILEPATH "Path to signtool.exe (required when KNHV_SIGN=ON)")
set(KNHV_SIGN_CERT "" CACHE FILEPATH "PFX containing the signing private key (required when KNHV_SIGN=ON)")
set(KNHV_SIGN_PASSWORD "" CACHE STRING "PFX password (optional; avoid storing secrets in CMake cache)")
set(KNHV_SIGN_TIMESTAMP_URL "" CACHE STRING "RFC3161 timestamp URL (optional for test certificates)")

# sources
set(SOURCES
        src/core/main.cpp
        src/core/vmm.cpp
        src/core/vmm_state.cpp
        src/vmx/vmx_features.cpp
        src/vmx/vmx_diagnostics.cpp
        src/vmx/vmx_crash.cpp
        src/vmx/vmx_teardown_state.cpp
        src/vmx/vmx_exit.cpp
        src/vmx/vmx_vmcs.cpp
        src/vmx/vmx_launch.cpp
        src/vmx/vmx_stop.cpp
        src/asm/vmx_entry.asm
        src/asm/vmx_instructions.asm
        src/asm/vmx_launch.asm
        src/asm/vmx_asm.inc
        src/include/common.h
        src/include/knhv_logging.h
        src/include/vmm.h
        src/include/vmm_internal.h
        src/include/vmx.h
        src/include/vmx_contract.h
)

# MASM does not always emit include dependencies for Ninja. Keep the shared
# ABI include attached to every assembly object so offset changes rebuild all
# consumers.
set(_knhv_asm_contract "${CMAKE_CURRENT_SOURCE_DIR}/src/asm/vmx_asm.inc")
set_source_files_properties(
        src/asm/vmx_entry.asm
        src/asm/vmx_instructions.asm
        src/asm/vmx_launch.asm
        PROPERTIES OBJECT_DEPENDS "${_knhv_asm_contract}")

# The MSVC toolchain may populate these variables with user-mode CRT libraries.
# Capture them for the contract test, but keep them empty while the WDK driver
# target is created so NODEFAULTLIB remains effective at link time.
set(_knhv_saved_c_standard_libraries "${CMAKE_C_STANDARD_LIBRARIES}")
set(_knhv_saved_cxx_standard_libraries "${CMAKE_CXX_STANDARD_LIBRARIES}")
set(CMAKE_C_STANDARD_LIBRARIES "")
set(CMAKE_CXX_STANDARD_LIBRARIES "")
wdk_add_driver(KNHV ${SOURCES})
if(_knhv_toolchain_includes)
    target_include_directories(KNHV SYSTEM BEFORE PRIVATE
                               ${_knhv_toolchain_includes})
endif()
target_include_directories(KNHV PRIVATE
                           "${CMAKE_CURRENT_SOURCE_DIR}/src/include")

# A kernel image has no user-mode CRT.  An empty runtime property prevents
# CMake from adding /MDd or /MD to the WDK target
if(MSVC)
    set_property(TARGET KNHV PROPERTY MSVC_RUNTIME_LIBRARY "")
endif()

# Kernel-only C/C++ options belong on the driver target.  Keeping them out of
# the user-mode contract test avoids contradictory MSVC switches such as
# /EHsc followed by /EHs-c- and /GS followed by /GS-, while the MASM source is
# still protected by the language-qualified expressions below.
target_compile_options(KNHV PRIVATE
        "$<$<COMPILE_LANGUAGE:C,CXX>:/utf-8>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/WX>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/EHs-c->"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/GS->"
        # MSVC's option spelling is case-sensitive here: /Zc (lowercase c).
        # Using /ZC makes cl parse it as /Z plus stray switches, disables
        # extensions, and causes WDK 28000 headers to fail on anonymous structs.
        "$<$<COMPILE_LANGUAGE:C,CXX>:/Zc:wchar_t->"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/std:c++17>"
)
target_compile_definitions(KNHV PRIVATE
        KNHV_BUILD_ID=${KNHV_BUILD_ID})
if(KNHV_FAULT_INJECTION)
    target_compile_definitions(KNHV PRIVATE
            KNHV_TEST_FAIL_CPU=${KNHV_TEST_FAIL_CPU}
            KNHV_TEST_FAIL_STAGE=${KNHV_TEST_FAIL_STAGE})
endif()

# link. WDK targets point at the selected kit, so no machine-specific library
# directory is needed here.
target_link_libraries(KNHV
        WDK::NTOSKRNL
        WDK::HAL
)
if(TARGET WDK::WDMSEC)
    target_link_libraries(KNHV WDK::WDMSEC)
endif()

# Keep the WDK-provided GsDriverEntry startup wrapper (it initializes the
# kernel-mode security cookie and calls DriverEntry). Always emit a linker PDB
# alongside the SYS, including Release builds, so WinDbg can resolve symbols.
set_property(TARGET KNHV APPEND_STRING PROPERTY LINK_FLAGS " /INTEGRITYCHECK /DEBUG")

# Signing is opt-in. An unsigned build remains useful for static analysis and
# avoids silently selecting an unrelated certificate from the local machine.
if(KNHV_SIGN)
    if(NOT KNHV_SIGNTOOL OR NOT EXISTS "${KNHV_SIGNTOOL}")
        message(FATAL_ERROR "KNHV_SIGN=ON requires a valid KNHV_SIGNTOOL path")
    endif()
    if(NOT KNHV_SIGN_CERT OR NOT EXISTS "${KNHV_SIGN_CERT}")
        message(FATAL_ERROR "KNHV_SIGN=ON requires a valid KNHV_SIGN_CERT path")
    endif()

    set(_knhv_sign_args sign /v /fd SHA256)
    if(KNHV_SIGN_PASSWORD)
        list(APPEND _knhv_sign_args /p "${KNHV_SIGN_PASSWORD}")
    endif()
    if(KNHV_SIGN_TIMESTAMP_URL)
        list(APPEND _knhv_sign_args /tr "${KNHV_SIGN_TIMESTAMP_URL}" /td SHA256)
    endif()
    list(APPEND _knhv_sign_args /f "${KNHV_SIGN_CERT}" "$<TARGET_FILE:KNHV>")

    add_custom_command(
            TARGET KNHV
            POST_BUILD
            COMMAND "${KNHV_SIGNTOOL}" ${_knhv_sign_args}
            COMMENT "Signing ${PROJECT_NAME}.sys"
            VERBATIM
    )
endif()

# The contract test is a normal user-mode executable.  It intentionally does
# not include WDK headers or execute VMX instructions; it validates the
# kernel/assembly ABI and can optionally exercise the installed service on an
# isolated test machine.  Keeping it as a separate target prevents
# /kernel,/NODEFAULTLIB driver flags from leaking into the test binary.
if(KNHV_BUILD_TESTS)
    enable_testing()
    add_executable(KNHV_ContractTests
            tests/vmx_contract_test.cpp
            tests/test_support.cpp
            tests/source_contract_test.cpp
            tests/runtime_contract_test.cpp)
    if(_knhv_toolchain_includes)
        target_include_directories(KNHV_ContractTests SYSTEM BEFORE PRIVATE
                                   ${_knhv_toolchain_includes})
    endif()
    if(_knhv_user_toolchain_libdirs)
        target_link_directories(KNHV_ContractTests PRIVATE
                                ${_knhv_user_toolchain_libdirs})
    endif()
    target_compile_definitions(KNHV_ContractTests PRIVATE
            KNHV_SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(KNHV_ContractTests PRIVATE
            /W4 /WX /EHsc /GR /GS /permissive- /std:c++17)
    target_link_libraries(KNHV_ContractTests PRIVATE advapi32 wintrust)
    if(_knhv_saved_cxx_standard_libraries)
        set(_knhv_test_standard_libraries
            "${_knhv_saved_cxx_standard_libraries}")
        separate_arguments(_knhv_test_standard_libraries WINDOWS_COMMAND
                           "${_knhv_test_standard_libraries}")
        target_link_libraries(KNHV_ContractTests PRIVATE
                              ${_knhv_test_standard_libraries})
    endif()
    add_test(NAME KNHV_ContractTests
            COMMAND KNHV_ContractTests --root "${CMAKE_CURRENT_SOURCE_DIR}")
endif()
