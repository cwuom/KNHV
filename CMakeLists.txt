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
option(KNHV_BUILD_NESTED_DRIVERS
       "Build the provider control and nested contract-test drivers" ON)
option(KNHV_BUILD_BENCHMARKS
       "Build host-only benchmark executables with explicit hardware gates" ON)
option(KNHV_BUILD_PREFLIGHT
       "Build the read-only capability and ownership preflight executable" ON)
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

# Embed provenance in benchmark output. A dirty or unknown source state is
# reported by the executable and cannot be promoted to a release verdict.
execute_process(
        COMMAND git -C "${CMAKE_CURRENT_SOURCE_DIR}" rev-parse HEAD
        OUTPUT_VARIABLE KNHV_BENCH_GIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
if(NOT KNHV_BENCH_GIT)
    set(KNHV_BENCH_GIT "unknown")
endif()
execute_process(
        COMMAND git -C "${CMAKE_CURRENT_SOURCE_DIR}" status --porcelain
                           --untracked-files=all
        OUTPUT_VARIABLE _knhv_git_status
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
if(_knhv_git_status)
    set(KNHV_BENCH_SOURCE_DIRTY "true")
else()
    set(KNHV_BENCH_SOURCE_DIRTY "false")
endif()

# keep generated images separate from CMake's internal files so a build tree
# can be copied to a test target without collecting intermediate objects
set(KNHV_ARTIFACT_ROOT "" CACHE PATH
    "Root directory for classified build artifacts")
if(KNHV_ARTIFACT_ROOT)
    file(TO_CMAKE_PATH "${KNHV_ARTIFACT_ROOT}" _knhv_artifact_root)
    # the empty generator expression prevents multi-config CMake from adding
    # another configuration directory to an explicitly selected root
    set(_knhv_artifact_root "${_knhv_artifact_root}/$<0:>")
elseif(CMAKE_CONFIGURATION_TYPES)
    set(_knhv_artifact_root "${CMAKE_BINARY_DIR}/$<CONFIG>")
else()
    set(_knhv_artifact_root "${CMAKE_BINARY_DIR}")
endif()
set(_knhv_program_output_directory "${_knhv_artifact_root}/bin")
set(_knhv_driver_output_directory "${_knhv_artifact_root}/sys")
set(_knhv_symbol_output_directory "${_knhv_artifact_root}")

function(knhv_set_artifact_layout target artifact_kind)
    if(artifact_kind STREQUAL "driver")
        set(_knhv_runtime_output "${_knhv_driver_output_directory}")
    elseif(artifact_kind STREQUAL "program")
        set(_knhv_runtime_output "${_knhv_program_output_directory}")
    else()
        message(FATAL_ERROR "unknown KNHV artifact kind: ${artifact_kind}")
    endif()
    set_target_properties(${target} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${_knhv_runtime_output}"
            PDB_OUTPUT_DIRECTORY "${_knhv_symbol_output_directory}")
endfunction()

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
knhv_set_artifact_layout(KNHV driver)
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
        "$<$<COMPILE_LANGUAGE:C,CXX>:/W4>"
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

set(KNHV_NESTED_MODEL_SOURCES
        src/provider/provider_selection.cpp
        src/provider/provider_v2.cpp
        src/ept/ept_model.cpp
        src/time/time_contract.cpp
        src/nested/vmcs02_model.cpp
        src/iommu/iommu_model.cpp
        src/exit/exit_model.cpp
        src/vmx/cpu_policy_model.cpp
        src/interrupt/interrupt_model.cpp
        src/nested/nested_vmcs.cpp
        src/nested/nested_memory.cpp
        src/nested/nested_instructions.cpp
        src/boot/boot_contract.cpp
        src/include/knhv_boot_contract.h
        src/include/knhv_abi.h
        src/include/knhv_provider.h
        src/include/knhv_nested.h
        src/include/knhv_ept.h
        src/include/knhv_time.h
        src/include/knhv_vmcs02.h
        src/include/knhv_iommu.h
        src/include/knhv_exit.h
        src/include/knhv_cpu_policy.h
        src/include/knhv_interrupt.h
        src/include/knhv_control_ioctl.h
)

# The control and contract-test images are independent WDM services. They
# share only the versioned ABI and pure nested model; neither image owns the
# physical VMX root state used by the existing research baseline.
if(KNHV_BUILD_NESTED_DRIVERS)
    set(KNHV_CONTROL_SOURCES
            src/control/control_driver.cpp
            src/control/control_device.cpp
            ${KNHV_NESTED_MODEL_SOURCES}
            src/control/knhv_control_device.h
    )
    set(KNHV_NESTED_TEST_SOURCES
            src/test_driver/nested_test_driver.cpp
            src/control/control_device.cpp
            ${KNHV_NESTED_MODEL_SOURCES}
            src/control/knhv_control_device.h
    )

    wdk_add_driver(KNHV_Control ${KNHV_CONTROL_SOURCES})
    wdk_add_driver(KNHV_NestedTest ${KNHV_NESTED_TEST_SOURCES})
    set_target_properties(KNHV_Control PROPERTIES OUTPUT_NAME "KNHV-Control")
    set_target_properties(KNHV_NestedTest PROPERTIES OUTPUT_NAME "KNHV-NestedTest")
    foreach(_knhv_aux_target IN ITEMS KNHV_Control KNHV_NestedTest)
        knhv_set_artifact_layout(${_knhv_aux_target} driver)
        target_include_directories(${_knhv_aux_target} PRIVATE
                                   "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
                                   "${CMAKE_CURRENT_SOURCE_DIR}/src/control"
                                   "${CMAKE_CURRENT_SOURCE_DIR}/src/nested")
        target_compile_options(${_knhv_aux_target} PRIVATE
                "$<$<COMPILE_LANGUAGE:C,CXX>:/utf-8>"
                "$<$<COMPILE_LANGUAGE:C,CXX>:/W4>"
                "$<$<COMPILE_LANGUAGE:C,CXX>:/WX>"
                "$<$<COMPILE_LANGUAGE:C,CXX>:/EHs-c->"
                "$<$<COMPILE_LANGUAGE:C,CXX>:/GS->"
                "$<$<COMPILE_LANGUAGE:C,CXX>:/Zc:wchar_t->"
                "$<$<COMPILE_LANGUAGE:C,CXX>:/std:c++17>")
        target_compile_definitions(${_knhv_aux_target} PRIVATE
                KNHV_KERNEL_BUILD=1)
        if(MSVC)
            set_property(TARGET ${_knhv_aux_target}
                         PROPERTY MSVC_RUNTIME_LIBRARY "")
        endif()
        set_property(TARGET ${_knhv_aux_target} APPEND_STRING PROPERTY
                     LINK_FLAGS " /INTEGRITYCHECK /DEBUG")
        if(TARGET WDK::WDMSEC)
            target_link_libraries(${_knhv_aux_target} WDK::WDMSEC)
        endif()
    endforeach()
    if(KNHV_SIGN)
        set(_knhv_aux_sign_args sign /v /fd SHA256 /f "${KNHV_SIGN_CERT}")
        if(KNHV_SIGN_PASSWORD)
            list(APPEND _knhv_aux_sign_args /p "${KNHV_SIGN_PASSWORD}")
        endif()
        if(KNHV_SIGN_TIMESTAMP_URL)
            list(APPEND _knhv_aux_sign_args /tr "${KNHV_SIGN_TIMESTAMP_URL}"
                 /td SHA256)
        endif()
        foreach(_knhv_aux_target IN ITEMS KNHV_Control KNHV_NestedTest)
            add_custom_command(
                    TARGET ${_knhv_aux_target}
                    POST_BUILD
                    COMMAND "${KNHV_SIGNTOOL}" ${_knhv_aux_sign_args}
                            "$<TARGET_FILE:${_knhv_aux_target}>"
                    COMMENT "Signing $<TARGET_FILE_NAME:${_knhv_aux_target}>"
                    VERBATIM
            )
        endforeach()
    endif()
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
            tests/runtime_contract_test.cpp
            tests/nested_model_test.cpp
            tests/provider_v2_test.cpp
            tests/ept_time_model_test.cpp
            tests/vmcs02_model_test.cpp
            tests/iommu_model_test.cpp
            tests/exit_model_test.cpp
            tests/cpu_policy_model_test.cpp
            tests/interrupt_model_test.cpp
            src/provider/provider_selection.cpp
            src/provider/provider_v2.cpp
            src/ept/ept_model.cpp
            src/time/time_contract.cpp
            src/nested/vmcs02_model.cpp
            src/iommu/iommu_model.cpp
            src/exit/exit_model.cpp
            src/vmx/cpu_policy_model.cpp
            src/interrupt/interrupt_model.cpp
            src/nested/nested_vmcs.cpp
            src/nested/nested_memory.cpp
            src/nested/nested_instructions.cpp
            src/boot/boot_contract.cpp)
    knhv_set_artifact_layout(KNHV_ContractTests program)
    if(_knhv_toolchain_includes)
        target_include_directories(KNHV_ContractTests SYSTEM BEFORE PRIVATE
                                   ${_knhv_toolchain_includes})
    endif()
    target_include_directories(KNHV_ContractTests PRIVATE
                               "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
                               "${CMAKE_CURRENT_SOURCE_DIR}/src/nested"
                               "${CMAKE_CURRENT_SOURCE_DIR}/src/boot")
    if(_knhv_user_toolchain_libdirs)
        target_link_directories(KNHV_ContractTests PRIVATE
                                ${_knhv_user_toolchain_libdirs})
    endif()
    target_compile_definitions(KNHV_ContractTests PRIVATE
            KNHV_SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(KNHV_ContractTests PRIVATE
            /W4 /WX /EHsc /GR /GS /permissive- /std:c++17)
    if(MSVC)
        # keep the host test independent of machine-installed CRT DLLs
        set_property(TARGET KNHV_ContractTests PROPERTY
                     MSVC_RUNTIME_LIBRARY
                     "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        set_property(TARGET KNHV_ContractTests APPEND_STRING PROPERTY
                     LINK_FLAGS " /DEBUG /INCREMENTAL:NO")
    endif()
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

    add_executable(KNHV_NestedProbe
            HV_PROBE_TESTER/nested_probe.cpp)
    knhv_set_artifact_layout(KNHV_NestedProbe program)
    if(_knhv_toolchain_includes)
        target_include_directories(KNHV_NestedProbe SYSTEM BEFORE PRIVATE
                                   ${_knhv_toolchain_includes})
    endif()
    target_include_directories(KNHV_NestedProbe PRIVATE
                               "${CMAKE_CURRENT_SOURCE_DIR}/src/include")
    if(_knhv_user_toolchain_libdirs)
        target_link_directories(KNHV_NestedProbe PRIVATE
                                ${_knhv_user_toolchain_libdirs})
    endif()
    target_compile_options(KNHV_NestedProbe PRIVATE
            /W4 /WX /EHsc /GR /GS /permissive- /std:c++17)
    if(MSVC)
        # keep the probe independent of machine-installed CRT DLLs
        set_property(TARGET KNHV_NestedProbe PROPERTY
                     MSVC_RUNTIME_LIBRARY
                     "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        set_property(TARGET KNHV_NestedProbe APPEND_STRING PROPERTY
                     LINK_FLAGS " /DEBUG /INCREMENTAL:NO")
    endif()
    if(_knhv_saved_cxx_standard_libraries)
        set(_knhv_nested_probe_standard_libraries
            "${_knhv_saved_cxx_standard_libraries}")
        separate_arguments(_knhv_nested_probe_standard_libraries WINDOWS_COMMAND
                           "${_knhv_nested_probe_standard_libraries}")
        target_link_libraries(KNHV_NestedProbe PRIVATE
                              ${_knhv_nested_probe_standard_libraries})
    endif()

    add_executable(KNHV_NativeVmxProbe
            HV_PROBE_TESTER/native_vmx_probe.cpp)
    knhv_set_artifact_layout(KNHV_NativeVmxProbe program)
    if(_knhv_toolchain_includes)
        target_include_directories(KNHV_NativeVmxProbe SYSTEM BEFORE PRIVATE
                                   ${_knhv_toolchain_includes})
    endif()
    if(_knhv_user_toolchain_libdirs)
        target_link_directories(KNHV_NativeVmxProbe PRIVATE
                                ${_knhv_user_toolchain_libdirs})
    endif()
    target_compile_options(KNHV_NativeVmxProbe PRIVATE
            /W4 /WX /EHsc /GR /GS /permissive- /std:c++17)
    if(MSVC)
        # keep the native probe independent of machine-installed CRT DLLs
        set_property(TARGET KNHV_NativeVmxProbe PROPERTY
                     MSVC_RUNTIME_LIBRARY
                     "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        set_property(TARGET KNHV_NativeVmxProbe APPEND_STRING PROPERTY
                     LINK_FLAGS " /DEBUG /INCREMENTAL:NO")
    endif()
    if(_knhv_saved_cxx_standard_libraries)
        set(_knhv_native_probe_standard_libraries
            "${_knhv_saved_cxx_standard_libraries}")
        separate_arguments(_knhv_native_probe_standard_libraries WINDOWS_COMMAND
                           "${_knhv_native_probe_standard_libraries}")
        target_link_libraries(KNHV_NativeVmxProbe PRIVATE
                              ${_knhv_native_probe_standard_libraries})
    endif()
endif()

# Benchmarks are user-mode programs. They measure host or synthetic work and
# query the versioned control device before a candidate run; they never issue
# VMX instructions or touch a physical device directly.
if(KNHV_BUILD_BENCHMARKS)
    function(knhv_add_benchmark target source_file)
        add_executable(${target}
                benchmarks/${source_file}
                benchmarks/bench_common.cpp
                benchmarks/bench_common.h)
        knhv_set_artifact_layout(${target} program)
        if(_knhv_toolchain_includes)
            target_include_directories(${target} SYSTEM BEFORE PRIVATE
                                       ${_knhv_toolchain_includes})
        endif()
        target_include_directories(${target} PRIVATE
                                   "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
                                   "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks")
        if(_knhv_user_toolchain_libdirs)
            target_link_directories(${target} PRIVATE
                                    ${_knhv_user_toolchain_libdirs})
        endif()
        target_compile_definitions(${target} PRIVATE
                KNHV_BENCH_GIT="${KNHV_BENCH_GIT}"
                KNHV_BENCH_CONFIGURATION="$<CONFIG>"
                KNHV_BENCH_SOURCE_DIRTY="${KNHV_BENCH_SOURCE_DIRTY}")
        target_compile_options(${target} PRIVATE
                /W4 /WX /EHsc /GR /GS /permissive- /std:c++17)
        if(MSVC)
            set_property(TARGET ${target} PROPERTY
                         MSVC_RUNTIME_LIBRARY
                         "MultiThreaded$<$<CONFIG:Debug>:Debug>")
            set_property(TARGET ${target} APPEND_STRING PROPERTY
                         LINK_FLAGS " /DEBUG /INCREMENTAL:NO")
        endif()
        target_link_libraries(${target} PRIVATE bcrypt advapi32)
        if(_knhv_saved_cxx_standard_libraries)
            set(_knhv_bench_standard_libraries
                "${_knhv_saved_cxx_standard_libraries}")
            separate_arguments(_knhv_bench_standard_libraries WINDOWS_COMMAND
                               "${_knhv_bench_standard_libraries}")
            target_link_libraries(${target} PRIVATE
                                  ${_knhv_bench_standard_libraries})
        endif()
    endfunction()

    knhv_add_benchmark(KNHV_NativeLikeBench native_like_bench.cpp)
    knhv_add_benchmark(KNHV_VmxExitBench vmexit_bench.cpp)
    knhv_add_benchmark(KNHV_TscQpcBench tsc_qpc_bench.cpp)
    knhv_add_benchmark(KNHV_EptHookBench ept_hook_bench.cpp)
    knhv_add_benchmark(KNHV_DeviceIoBench device_io_bench.cpp)
endif()

# Preflight is a read-only user-mode executable. It reports unknown privileged
# state instead of attempting to provision VMX, change boot policy, or load a
# driver.
if(KNHV_BUILD_PREFLIGHT)
    add_executable(KNHV_Preflight
            preflight/preflight_main.cpp
            preflight/preflight_common.cpp
            preflight/preflight.h)
    knhv_set_artifact_layout(KNHV_Preflight program)
    if(_knhv_toolchain_includes)
        target_include_directories(KNHV_Preflight SYSTEM BEFORE PRIVATE
                                   ${_knhv_toolchain_includes})
    endif()
    target_include_directories(KNHV_Preflight PRIVATE
                               "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
                               "${CMAKE_CURRENT_SOURCE_DIR}/preflight")
    if(_knhv_user_toolchain_libdirs)
        target_link_directories(KNHV_Preflight PRIVATE
                                ${_knhv_user_toolchain_libdirs})
    endif()
    target_compile_options(KNHV_Preflight PRIVATE
            /W4 /WX /EHsc /GR /GS /permissive- /std:c++17)
    if(MSVC)
        set_property(TARGET KNHV_Preflight PROPERTY
                     MSVC_RUNTIME_LIBRARY
                     "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        set_property(TARGET KNHV_Preflight APPEND_STRING PROPERTY
                     LINK_FLAGS " /DEBUG /INCREMENTAL:NO")
    endif()
    target_link_libraries(KNHV_Preflight PRIVATE advapi32)
    if(_knhv_saved_cxx_standard_libraries)
        set(_knhv_preflight_standard_libraries
            "${_knhv_saved_cxx_standard_libraries}")
        separate_arguments(_knhv_preflight_standard_libraries WINDOWS_COMMAND
                           "${_knhv_preflight_standard_libraries}")
        target_link_libraries(KNHV_Preflight PRIVATE
                              ${_knhv_preflight_standard_libraries})
    endif()
endif()
