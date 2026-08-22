//
// Created by cwuom on 22 Aug 2026.
//

// User-mode contract and smoke tests for Nested_HV.
//
// This executable deliberately does not include ntddk.h or call VMXON.  The
// driver has no safe way to emulate VMX in a normal process, so the test keeps
// the high-value checks host-independent (source/ABI contracts, PE/PDB and
// signature validation) and makes service start an explicit opt-in operation.

#include <windows.h>
#include <intrin.h>
#include <softpub.h>
#include <wintrust.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")

namespace fs = std::filesystem;

namespace reference {
constexpr std::uint32_t kVmEntryLoadCet = 1u << 20;
constexpr std::uint32_t kVmExitLoadCet = 1u << 28;
constexpr std::uint32_t kCpuBasedActivateTertiary = 1u << 17;
constexpr std::uint32_t kSecondaryXsaves = 1u << 20;
constexpr std::uint32_t kXssExitingBitmap = 0x202c;
constexpr std::uint32_t kGuestSCet = 0x6828;
constexpr std::uint32_t kGuestSsp = 0x682a;
constexpr std::uint32_t kGuestIntrSspTable = 0x682c;
constexpr std::uint32_t kHostSCet = 0x6c18;
constexpr std::uint32_t kHostSsp = 0x6c1a;
constexpr std::uint32_t kHostIntrSspTable = 0x6c1c;
constexpr std::uint32_t kExitXsaves = 63;
constexpr std::uint32_t kExitXrstors = 64;
}  // namespace reference

static_assert(reference::kVmEntryLoadCet == 0x00100000);
static_assert(reference::kVmExitLoadCet == 0x10000000);
static_assert(reference::kCpuBasedActivateTertiary == 0x00020000);
static_assert(reference::kSecondaryXsaves == 0x00100000);
static_assert(reference::kXssExitingBitmap == 0x202c);
static_assert(reference::kGuestSCet == 0x6828);
static_assert(reference::kGuestSsp == 0x682a);
static_assert(reference::kGuestIntrSspTable == 0x682c);
static_assert(reference::kHostSCet == 0x6c18);
static_assert(reference::kHostSsp == 0x6c1a);
static_assert(reference::kHostIntrSspTable == 0x6c1c);
static_assert(reference::kExitXsaves == 63);
static_assert(reference::kExitXrstors == 64);

namespace {

// Keep a user-mode mirror of the MASM/C++ frame ABI.  The kernel header cannot
// be included here because it intentionally depends on WDK-only ntddk.h.
struct GuestContextLayout {
  std::array<std::uint8_t, 4096> FxArea{};
  std::uint64_t Rax{};
  std::uint64_t Rcx{};
  std::uint64_t Rdx{};
  std::uint64_t Rbx{};
  std::uint64_t Rbp{};
  std::uint64_t Rsi{};
  std::uint64_t Rdi{};
  std::uint64_t R8{};
  std::uint64_t R9{};
  std::uint64_t R10{};
  std::uint64_t R11{};
  std::uint64_t R12{};
  std::uint64_t R13{};
  std::uint64_t R14{};
  std::uint64_t R15{};
  std::uint64_t GuestRip{};
  std::uint64_t GuestRsp{};
  std::uint64_t Rflags{};
  std::uint64_t GuestCs{};
  std::uint64_t GuestSs{};
  std::uint64_t GuestCr3{};
  std::uint64_t GuestCr4{};
  std::uint64_t GuestFsBase{};
  std::uint64_t GuestGsBase{};
  std::uint64_t GuestEfer{};
  std::uint64_t GuestPat{};
  std::uint64_t GuestKernelGsBase{};
  std::uint64_t AbortVm{};
  std::uint64_t HaltVm{};
  std::uint64_t GuestCr0{};
  std::uint64_t GuestSysenterCs{};
  std::uint64_t GuestSysenterEsp{};
  std::uint64_t GuestSysenterEip{};
  std::uint64_t GuestXcr0{};
  std::uint64_t GuestXss{};
  std::uint64_t GuestSCet{};
  std::uint64_t GuestSsp{};
  std::uint64_t GuestInterruptSspTable{};
};

static_assert(offsetof(GuestContextLayout, Rax) == 0x1000);
static_assert(offsetof(GuestContextLayout, GuestXcr0) == 0x1108);
static_assert(offsetof(GuestContextLayout, GuestXss) == 0x1110);
static_assert(offsetof(GuestContextLayout, GuestSCet) == 0x1118);
static_assert(offsetof(GuestContextLayout, GuestSsp) == 0x1120);
static_assert(offsetof(GuestContextLayout, GuestInterruptSspTable) == 0x1128);
static_assert(sizeof(GuestContextLayout) <= 0x1178);

struct TestState {
  int passed = 0;
  int failed = 0;
};

void Check(TestState& state, std::string_view name, bool condition,
           std::string_view detail = {}) {
  if (condition) {
    ++state.passed;
    std::cout << "PASS  " << name << "\n";
  } else {
    ++state.failed;
    std::cerr << "FAIL  " << name;
    if (!detail.empty()) std::cerr << ": " << detail;
    std::cerr << "\n";
  }
}

std::string ReadText(const fs::path& path, TestState& state) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    Check(state, "read " + path.string(), false, "file not found");
    return {};
  }
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

void CheckPattern(TestState& state, std::string_view name,
                  const std::string& text, const char* pattern) {
  try {
    Check(state, name, std::regex_search(text, std::regex(pattern)), pattern);
  } catch (const std::regex_error& error) {
    Check(state, name, false, error.what());
  }
}

void TestSourceContract(const fs::path& root, TestState& state) {
  const std::string vmx = ReadText(root / "src/header/vmx.h", state);
  const std::string common = ReadText(root / "src/header/common.h", state);
  const std::string vmm = ReadText(root / "src/vmm.cpp", state);
  const std::string asm_source = ReadText(root / "src/asm/arch.asm", state);
  const std::string main = ReadText(root / "src/main.cpp", state);
  const std::string vscode_settings = ReadText(root / ".vscode/settings.json", state);
  if (vmx.empty() || common.empty() || vmm.empty() || asm_source.empty() ||
      main.empty() || vscode_settings.empty()) {
    return;
  }

  CheckPattern(state, "VM-entry CET control encoding", vmx,
               R"(VM_ENTRY_LOAD_CET_STATE\s+\(1UL\s*<<\s*20\))");
  CheckPattern(state, "VM-exit CET control encoding", vmx,
               R"(VM_EXIT_LOAD_CET_STATE\s+\(1UL\s*<<\s*28\))");
  CheckPattern(state, "secondary XSAVES control encoding", vmx,
               R"(SECONDARY_ENABLE_XSAVES\s+\(1UL\s*<<\s*20\))");
  CheckPattern(state, "CPUID XSAVES uses bit 3", vmx,
               R"(CPUID_D1_XSAVES\s+\(1U\s*<<\s*3\))");
  CheckPattern(state, "CPUID XFD uses bit 4", vmx,
               R"(CPUID_D1_XFD\s+\(1U\s*<<\s*4\))");
  CheckPattern(state, "tertiary control activation encoding", vmx,
               R"(CPU_BASED_ACTIVATE_TERTIARY_CONTROLS\s+\(1UL\s*<<\s*17\))");
  CheckPattern(state, "XSS exiting bitmap encoding", vmx,
               R"(CONTROL_XSS_EXITING_BITMAP\s*=\s*0x202c)");
  CheckPattern(state, "guest CET VMCS encodings", vmx,
               R"(GUEST_S_CET\s*=\s*0x6828[\s\S]*GUEST_SSP\s*=\s*0x682a[\s\S]*GUEST_INTR_SSP_TABLE\s*=\s*0x682c)");
  CheckPattern(state, "host CET VMCS encodings", vmx,
               R"(HOST_S_CET\s*=\s*0x6c18[\s\S]*HOST_SSP\s*=\s*0x6c1a[\s\S]*HOST_INTR_SSP_TABLE\s*=\s*0x6c1c)");
  CheckPattern(state, "XSAVES/XRSTORS exit reasons", vmx,
               R"(VM_EXIT_REASON_XSAVES\s+63[\s\S]*VM_EXIT_REASON_XRSTORS\s+64)");

  CheckPattern(state, "MASM GuestContext XCR0 offset", asm_source,
               R"(CTX_GUEST_XCR0\s+equ\s+01108h)");
  CheckPattern(state, "MASM GuestContext XSS offset", asm_source,
               R"(CTX_GUEST_XSS\s+equ\s+01110h)");
  CheckPattern(state, "MASM GuestContext CET offset", asm_source,
               R"(CTX_GUEST_S_CET\s+equ\s+01118h)");
  CheckPattern(state, "VM-exit uses XSAVES", asm_source,
               R"(\bxsaves\s+\[rsp\])");
  CheckPattern(state, "VM-exit uses XRSTORS", asm_source,
               R"(\bxrstors\s+\[rsp\])");
  CheckPattern(state, "XSAVES uses immutable XSS mask", asm_source,
               R"(mov r15, qword ptr \[g_XsavesMask\][\s\S]{0,500}xsaves\s+\[rsp\])");
  CheckPattern(state, "XRSTORS restores guest XSS after fixed mask", asm_source,
               R"(xrstors\s+\[rsp\][\s\S]{0,240}CTX_GUEST_XSS[\s\S]{0,160}wrmsr)");
  CheckPattern(state, "IA32_XSS access is XSAVES-gated", asm_source,
               R"(cmp byte ptr \[g_XsavesEnabled\], 0[\s\S]{0,80}je vmxSaveXsave)");
  CheckPattern(state, "CET teardown MSRs are gated", asm_source,
               R"(cmp byte ptr \[g_CetVmcsEnabled\], 0[\s\S]{0,100}je restoreGuestCetDone)");
  CheckPattern(state, "host XCR0 is installed before handler", asm_source,
               R"(HOST_XCR0_FRAME_SLOT[\s\S]{0,1200}call VmExitHandler)");
  CheckPattern(state, "fatal path parks after VMXOFF", asm_source,
               R"(vmxHalt:[\s\S]{0,1800}call MarkCurrentVcpuParked[\s\S]{0,300}vmxoff)");
  const std::size_t halt_begin = asm_source.find("vmxHalt:");
  const std::size_t halt_end = asm_source.find("vmxResumeFailure:");
  Check(state, "fatal path keeps interrupts disabled",
        halt_begin != std::string::npos && halt_end > halt_begin &&
            asm_source.substr(halt_begin, halt_end - halt_begin).find("sti") ==
                std::string::npos);
  CheckPattern(state, "VM-exit masks interrupts before private frame", asm_source,
               R"(HvVmExitEntryPoint proc[\s\S]{0,300}cli[\s\S]{0,400}sub rsp, 1180h)");

  CheckPattern(state, "SetupVmcs writes guest CET fields", vmm,
               R"(SetupVmcs\([\s\S]*?VmWriteChecked\(GUEST_S_CET[\s\S]*?VmWriteChecked\(GUEST_SSP[\s\S]*?VmWriteChecked\(GUEST_INTR_SSP_TABLE)");
  CheckPattern(state, "SetupVmcs writes host CET fields", vmm,
               R"(SetupVmcs\([\s\S]*?VmWriteChecked\(HOST_S_CET[\s\S]*?VmWriteChecked\(HOST_SSP[\s\S]*?VmWriteChecked\(HOST_INTR_SSP_TABLE)");
  CheckPattern(state, "SetupVmcs clears XSS exiting bitmap", vmm,
               R"(VmWriteChecked\(CONTROL_XSS_EXITING_BITMAP\s*,\s*0\))");
  CheckPattern(state, "SetupVmcs gates paired CET controls", vmm,
               R"(g_CetVmcsEnabled[\s\S]{0,900}VM_EXIT_LOAD_CET_STATE[\s\S]{0,900}VM_ENTRY_LOAD_CET_STATE)");
  CheckPattern(state, "XSAVES/XRSTORS exits recover natively", vmm,
               R"(case VM_EXIT_REASON_XSAVES[\s\S]{0,300}case VM_EXIT_REASON_XRSTORS[\s\S]{0,900}RequestSafeExit\s*\(Ctx\))");
  CheckPattern(state, "VM-entry injection is cleared per exit", vmm,
               R"(VmExitHandler\(GuestContext\* Ctx\)[\s\S]{0,1300}CONTROL_VM_ENTRY_INTR_INFO_FIELD, 0[\s\S]{0,300}CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE, 0)");
  const std::size_t setup_begin = vmm.find("bool SetupVmcs(");
  const std::size_t setup_end = vmm.find(
      "// ==============================================================================\n// Launch Logic", setup_begin);
  Check(state, "IPI launch enables guest interrupts",
         setup_begin != std::string::npos && setup_end > setup_begin &&
             vmm.substr(setup_begin, setup_end - setup_begin).find(
                 "u64 guestRflags = GetRflags()") != std::string::npos &&
             vmm.substr(setup_begin, setup_end - setup_begin).find(
                 "guestRflags |= (1ULL << 9)") != std::string::npos &&
             vmm.substr(setup_begin, setup_end - setup_begin).find(
                 "guestRflags &= ~((1ULL << 17)") != std::string::npos &&
             vmm.substr(setup_begin, setup_end - setup_begin).find(
                 "guestRflags &= ~((1ULL << 9)") == std::string::npos);
  CheckPattern(state, "unload VMCALL logs the IRET contract", vmm,
               R"(unload VMCALL: cpu=.*GuestRip|unload VMCALL decision: cpu=)");
  CheckPattern(state, "non-empty LDTR fails closed", vmm,
               R"(ldtrSelector\s*!=\s*0[\s\S]{0,600}non-empty LDTR[\s\S]{0,240}return false)");
  CheckPattern(state, "feature contract has a sticky validity result", vmm,
               R"(g_VmxFeatureContractInitialized\s*=\s*true)");
  CheckPattern(state, "feature contract resets only while idle", vmm,
               R"(if\s*\(g_VcpuData\s*==\s*nullptr\)[\s\S]{0,500}g_VmxFeatureContractInitialized\s*=\s*false)");
  CheckPattern(state, "CPUID XSS mask is restricted to the guest contract", vmm,
               R"(g_SupportedXssMask\s*=\s*enumeratedXss\s*&\s*IA32_XSS_VIRTUALIZABLE_MASK)");
  CheckPattern(state, "XSAVES fixed mask follows host XSS", vmm,
               R"(g_XsavesMask\s*=\s*g_XsavesEnabled\s*\?\s*g_HostXssMask\s*:\s*0)");
  CheckPattern(state, "guest XSS stays inside fixed frame mask", vmm,
               R"(g_SupportedXssMask\s*&=\s*g_XsavesMask)");
  CheckPattern(state, "guest XSS contract preserves IPT and CET_U", vmx,
               R"(IA32_XSS_GUEST_KNOWN_MASK\s+\(IA32_XSS_IPT\s*\|\s*IA32_XSS_CET_U\))");
  CheckPattern(state, "active PT is rejected before VMX", vmm,
               R"(IA32_XSS_IPT[\s\S]{0,500}MSR_IA32_RTIT_CTL[\s\S]{0,300}ptControl\s*!=\s*0)");
  CheckPattern(state, "guest XSS is separated from host XSS", vmm,
               R"(vcpu->HostXss\s*=\s*hostXss[\s\S]{0,260}vcpu->GuestXss\s*=\s*hostXss\s*&\s*g_SupportedXssMask)");
  CheckPattern(state, "guest XSS writes keep a fixed frame mask", vmm,
               R"(g_XsavesEnabled\s*&&\s*msrIndex\s*==\s*MSR_IA32_XSS[\s\S]{0,520}g_SupportedXssMask[\s\S]{0,220}Ctx->GuestXss\s*=\s*value\.QuadPart)");
  CheckPattern(state, "guest XSS is installed before launch", vmm,
               R"(WriteMsrSafe\(MSR_IA32_XSS\s*,\s*vcpu->GuestXss\)[\s\S]{0,1000}VMCS ready; entering VMLAUNCH)");
  CheckPattern(state, "each CPU validates local XCR0 contract", vmm,
             R"(localSupportedXcr0[\s\S]{0,1200}localXcr0\s*=\s*_xgetbv\(0\)[\s\S]{0,700}localXcr0\s*&\s*~localSupportedXcr0)");
  CheckPattern(state, "each CPU validates XRSTORS", vmm,
               R"(g_XsavesEnabled\s*\)[\s\S]{0,400}localXsaveFeatures\s*&\s*CPUID_D1_XSAVES)");
  CheckPattern(state, "each CPU validates complete XSS mask", vmm,
               R"(g_XsavesMask\s*&\s*~localXssMask)");
  CheckPattern(state, "each CPU validates local CR4 CET contract", vmm,
               R"(const u64 localCr4\s*=\s*__readcr4\(\)[\s\S]{0,350}localCet\s*=\s*\(localCr4\s*&\s*CR4_CET\)[\s\S]{0,350}localCet\s*!=\s*\(g_CetVmcsEnabled\s*!=\s*0\))");
  CheckPattern(state, "PT MSR window is intercepted", vmm,
               R"(MSR_IA32_RTIT_OUTPUT_BASE[\s\S]{0,220}0x58FU[\s\S]{0,220}setBit\(msr, false\))");
  CheckPattern(state, "diagnostic VM-exit log is rate limited", vmm,
               R"(InterlockedIncrement\(&vcpu->VmExitCount\)[\s\S]{0,600}exitCount\s*<=\s*16)");
  CheckPattern(state, "diagnostic launch log includes VMCS state", vmm,
               R"(VMCS ready; entering VMLAUNCH[\s\S]{0,240}revision=0x%X)");
  CheckPattern(state, "launch state is published by the success marker", vmm,
               R"(MarkCurrentVcpuLaunched[\s\S]{0,600}State[\s\S]{0,120}VcpuLaunched)");
  CheckPattern(state, "launch starts in the intermediate state", vmm,
               R"(InterlockedCompareExchange\(&vcpu->State,[\s\S]{0,120}VcpuStarting)");
  const std::size_t prepare_begin = vmm.find(
      "extern \"C\" ULONG PrepareHvCallback(");
  const std::size_t prepare_end = vmm.find(
      "extern \"C\" void AbortHvLaunch", prepare_begin);
  Check(state, "IPI preparation has no direct debugger print",
        prepare_begin != std::string::npos && prepare_end > prepare_begin &&
            vmm.substr(prepare_begin, prepare_end - prepare_begin)
                    .find("DbgPrint(") == std::string::npos);
  const std::size_t thunk_begin = asm_source.find("GuestStartThunk proc");
  const std::size_t thunk_end = asm_source.find("GuestStartThunk endp", thunk_begin);
  Check(state, "guest launch returns without leaving VMX",
         thunk_begin != std::string::npos && thunk_end > thunk_begin &&
             asm_source.substr(thunk_begin, thunk_end - thunk_begin).find(
                 "VMX_LAUNCH_SUCCESS_MAGIC") != std::string::npos &&
             asm_source.substr(thunk_begin, thunk_end - thunk_begin).find("ret") !=
                 std::string::npos &&
             asm_source.substr(thunk_begin, thunk_end - thunk_begin).find("vmcall") ==
                 std::string::npos);
  const std::size_t wrapper_begin = asm_source.find("EnableHvCallback proc frame");
  const std::size_t wrapper_end = asm_source.find("EnableHvCallback endp", wrapper_begin);
  Check(state, "IPI wrapper preserves nonvolatile XMM registers",
        wrapper_begin != std::string::npos && wrapper_end > wrapper_begin &&
            asm_source.substr(wrapper_begin, wrapper_end - wrapper_begin).find(
                "movdqu xmmword ptr [rsp + 080h], xmm6") != std::string::npos &&
            asm_source.substr(wrapper_begin, wrapper_end - wrapper_begin).find(
                "movdqu xmm6, xmmword ptr [rsp + 080h]") != std::string::npos);
  CheckPattern(state, "launch reserves teardown stack space", asm_source,
               R"(HvLaunchGuest proc[\s\S]{0,420}sub rsp, 200h[\s\S]{0,300}VMCS_GUEST_RSP[\s\S]{0,700}vmlaunch[\s\S]{0,300}add rsp, 200h)");
  const std::size_t launch_begin = asm_source.find("HvLaunchGuest proc frame");
  const std::size_t launch_end = asm_source.find("HvLaunchGuest endp", launch_begin);
  Check(state, "launch has VMXE guard",
        launch_begin != std::string::npos && launch_end > launch_begin &&
            asm_source.substr(launch_begin, launch_end - launch_begin).find(
                "test rax, CR4_VMXE") != std::string::npos &&
            asm_source.substr(launch_begin, launch_end - launch_begin).find(
                "jz launchNotVmx") != std::string::npos);
  Check(state, "launch has unwind stack metadata",
        launch_begin != std::string::npos && launch_end > launch_begin &&
            asm_source.substr(launch_begin, launch_end - launch_begin).find(
                ".allocstack 200h") != std::string::npos &&
            asm_source.substr(launch_begin, launch_end - launch_begin).find(
                ".endprolog") != std::string::npos);
  Check(state, "IPI bool ABI is tested at byte width",
        wrapper_begin != std::string::npos && wrapper_end > wrapper_begin &&
            asm_source.substr(wrapper_begin, wrapper_end - wrapper_begin).find(
                "call PrepareHvCallback") != std::string::npos &&
            asm_source.substr(wrapper_begin, wrapper_end - wrapper_begin).find(
                "test al, al") != std::string::npos);
  const std::size_t abort_begin = vmm.find("extern \"C\" void AbortHvLaunch");
  const std::size_t abort_end = vmm.find("// ==============================================================================\n// Stop Logic", abort_begin);
  Check(state, "non-VMX launch token is handled",
        abort_begin != std::string::npos && abort_end > abort_begin &&
            vmm.substr(abort_begin, abort_end - abort_begin).find(
                "VMX_LAUNCH_NOT_VMX_MAGIC") != std::string::npos &&
            vmm.substr(abort_begin, abort_end - abort_begin).find(
                "vmxInstructionFailure") != std::string::npos &&
            vmm.substr(abort_begin, abort_end - abort_begin).find(
                "HvVmxOff") != std::string::npos);
  const std::size_t teardown_begin = asm_source.find("restoreGuestStateDone:");
  const std::size_t teardown_end = asm_source.find("vmxoff", teardown_begin);
  Check(state, "teardown preserves guest XSS before VMXOFF",
        teardown_begin != std::string::npos && teardown_end > teardown_begin &&
            asm_source.substr(teardown_begin, teardown_end - teardown_begin)
                .find("HOST_XSS_FRAME_SLOT") == std::string::npos);
  CheckPattern(state, "guest CPUID hides VMX", vmm,
               R"(leaf\s*==\s*1[\s\S]{0,300}regs\[2\]\s*&=\s*~\(1\s*<<\s*5\))");
  CheckPattern(state, "guest CPUID hides incomplete CET", vmm,
               R"(kGuestCetStateVirtualized\s*=\s*false|kGuestCetStateVirtualized\s*&&)");
  CheckPattern(state, "CR3 PCID no-flush is accepted", vmm,
               R"(noFlushMask\s*=\s*pcide\s*\?\s*\(1ULL\s*<<\s*63\))");
  CheckPattern(state, "guest CR4.CET is contract gated", vmm,
               R"(crNum\s*==\s*4[\s\S]{0,260}value\s*&\s*CR4_CET[\s\S]{0,260}g_CetVmcsEnabled)");
  CheckPattern(state, "guest CPUID gates CET on XSS support", vmm,
               R"(cetGuestSupported[\s\S]{0,300}IA32_XSS_CET_U)");
  CheckPattern(state, "25H2 inactive CET state is supported", main,
               R"(Windows 11 25H2[\s\S]{0,800}active supervisor CET state is outside the safe VMX contract)");
  CheckPattern(state, "CET_U requires XSAVES", main,
               R"(CET_U is enabled without an XSAVES CET_U component)");
  CheckPattern(state, "CET_U MSRs can pass through with XSAVES", vmm,
               R"(cetUserStateSupported[\s\S]{0,500}MSR_IA32_U_CET[\s\S]{0,200}MSR_IA32_PL3_SSP)");
  CheckPattern(state, "VS Code config selects an active preset", vscode_settings,
               R"("cmake\.useCMakePresets"\s*:\s*"always")");
  CheckPattern(state, "VS Code config selects the debug configure preset",
               vscode_settings,
               R"("cmake\.configurePreset"\s*:\s*"vscode-debug")");
  CheckPattern(state, "VS Code config selects the debug build preset",
               vscode_settings,
               R"("cmake\.buildPreset"\s*:\s*"vscode-debug")");
  CheckPattern(state, "C++ GuestContext offset assertions", common,
               R"(offsetof\(GuestContext,\s*GuestXcr0\)\s*==\s*0x1108[\s\S]*offsetof\(GuestContext,\s*GuestSCet\)\s*==\s*0x1118)");
}

void TestArtifact(const fs::path& driver, TestState& state) {
  std::ifstream file(driver, std::ios::binary);
  std::error_code size_error;
  const std::uintmax_t file_size = fs::file_size(driver, size_error);
  if (!file || size_error || file_size < sizeof(IMAGE_DOS_HEADER)) {
    Check(state, "driver artifact is readable", false, driver.string());
    return;
  }

  IMAGE_DOS_HEADER dos{};
  file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
  const bool dos_ok = file.good() && dos.e_magic == IMAGE_DOS_SIGNATURE;
  Check(state, "SYS has an MZ header", dos_ok, driver.string());
  if (!dos_ok || dos.e_lfanew < 0) return;

  const std::uint64_t pe_offset = static_cast<std::uint32_t>(dos.e_lfanew);
  const std::uint64_t minimum_nt_size = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
  if (pe_offset > file_size || file_size - pe_offset < minimum_nt_size) {
    Check(state, "SYS PE header is inside the file", false, driver.string());
    return;
  }

  file.seekg(static_cast<std::streamoff>(pe_offset), std::ios::beg);
  DWORD signature = 0;
  IMAGE_FILE_HEADER header{};
  file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
  file.read(reinterpret_cast<char*>(&header), sizeof(header));
  const bool pe = file.good() && signature == IMAGE_NT_SIGNATURE;
  Check(state, "SYS has a PE image", pe, driver.string());
  if (!pe) return;

  Check(state, "SYS is an AMD64 image",
        header.Machine == IMAGE_FILE_MACHINE_AMD64, driver.string());
  Check(state, "SYS contains sections", header.NumberOfSections != 0,
        driver.string());
  if (header.SizeOfOptionalHeader < sizeof(WORD) ||
      file_size - pe_offset < minimum_nt_size + header.SizeOfOptionalHeader) {
    Check(state, "SYS optional header is inside the file", false,
          driver.string());
    return;
  }

  std::vector<std::uint8_t> optional(header.SizeOfOptionalHeader);
  const bool optional_read =
      static_cast<bool>(file.read(reinterpret_cast<char*>(optional.data()),
                                  static_cast<std::streamsize>(optional.size())));
  Check(state, "SYS optional header is readable", optional_read,
        driver.string());
  if (!optional_read) return;

  WORD optional_magic = 0;
  std::memcpy(&optional_magic, optional.data(), sizeof(optional_magic));
  Check(state, "SYS uses the PE32+ optional header",
        optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, driver.string());
  const bool has_subsystem =
      optional.size() >= offsetof(IMAGE_OPTIONAL_HEADER64, Subsystem) +
                              sizeof(WORD);
  Check(state, "SYS optional header contains a subsystem field", has_subsystem,
        driver.string());
  if (!has_subsystem) return;

  WORD subsystem = 0;
  std::memcpy(&subsystem,
              optional.data() + offsetof(IMAGE_OPTIONAL_HEADER64, Subsystem),
              sizeof(subsystem));
  Check(state, "SYS uses the Native subsystem",
        optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
            subsystem == IMAGE_SUBSYSTEM_NATIVE,
        driver.string());

  const fs::path pdb = driver.parent_path() / (driver.stem().wstring() + L".pdb");
  std::error_code pdb_error;
  const std::uintmax_t pdb_size = fs::file_size(pdb, pdb_error);
  Check(state, "matching PDB exists",
        fs::is_regular_file(pdb) && !pdb_error && pdb_size != 0, pdb.string());
}

bool IsUntrustedPrivateRoot(LONG status) {
  return status == TRUST_E_SUBJECT_NOT_TRUSTED ||
         status == CERT_E_UNTRUSTEDROOT || status == CERT_E_CHAINING ||
         status == CERT_E_UNTRUSTEDTESTROOT;
}

void TestSignature(const fs::path& driver, bool allowTestRoot, TestState& state) {
  const std::wstring path = driver.wstring();
  WINTRUST_FILE_INFO file{sizeof(file), path.c_str(), nullptr, nullptr};
  WINTRUST_DATA data{};
  data.cbStruct = sizeof(data);
  data.dwUIChoice = WTD_UI_NONE;
  data.fdwRevocationChecks = WTD_REVOKE_NONE;
  data.dwUnionChoice = WTD_CHOICE_FILE;
  data.pFile = &file;
  data.dwStateAction = WTD_STATEACTION_VERIFY;
  GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const LONG status = WinVerifyTrust(nullptr, &policy, &data);
  data.dwStateAction = WTD_STATEACTION_CLOSE;
  (void)WinVerifyTrust(nullptr, &policy, &data);

  const bool trusted = status == ERROR_SUCCESS;
  const bool accepted = trusted || (allowTestRoot && IsUntrustedPrivateRoot(status));
  Check(state, "SYS has a verifiable Authenticode signature", accepted,
        trusted ? "trusted" : "private test root is not in this store");
  if (!trusted && !accepted) {
    std::cerr << "WinVerifyTrust status: 0x" << std::hex << status << std::dec
              << "\n";
  }
}

void TestHardware(TestState& state) {
  int max_leaf[4]{};
  __cpuidex(max_leaf, 0, 0);
  const int max_basic = max_leaf[0];
  Check(state, "CPUID leaf 1 is available", max_basic >= 1);
  if (max_basic < 1) return;

  int leaf1[4]{};
  __cpuidex(leaf1, 1, 0);
  Check(state, "Intel VMX is enumerated", (leaf1[2] & (1 << 5)) != 0);
  Check(state, "no active hypervisor is enumerated", (leaf1[2] & (1u << 31)) == 0);
  Check(state, "XSAVE and OSXSAVE are enabled", (leaf1[2] & (1 << 26)) &&
                                                     (leaf1[2] & (1 << 27)));
  if (!(leaf1[2] & (1 << 26)) || !(leaf1[2] & (1 << 27)) || max_basic < 0xd) return;

  unsigned __int64 xcr0 = _xgetbv(0);
  Check(state, "XCR0 has x87 and SSE enabled", (xcr0 & 3) == 3);

  int d1[4]{};
  __cpuidex(d1, 0xd, 1);
  Check(state, "XSAVES is enumerated", (d1[0] & (1 << 3)) != 0);
  Check(state, "XSAVE(S) area fits the 4 KiB exit frame", static_cast<unsigned>(d1[1]) <= 0x1000);
  std::cout << "Hardware: XCR0=0x" << std::hex << xcr0
            << " CPUID.0D.1:EBX=0x" << static_cast<unsigned>(d1[1])
            << " ECX:EDX=0x" << static_cast<unsigned>(d1[2]) << ":"
            << static_cast<unsigned>(d1[3]) << std::dec << "\n";
}

// The driver handles this reserved leaf only in VMX non-root mode.  It is a
// small end-to-end smoke test: user mode executes CPUID, the VM-exit handler
// observes it, and the modified register tuple returns to the caller.
void TestMagicCpuid(TestState& state) {
  int regs[4]{};
  __cpuidex(regs, 0x13371337, 0);
  Check(state, "magic CPUID reaches the VM-exit handler",
        static_cast<std::uint32_t>(regs[0]) == 0x13371337U &&
            static_cast<std::uint32_t>(regs[1]) == 0xDEADC0DEU &&
            static_cast<std::uint32_t>(regs[2]) == 0x00C0FFEEU &&
            static_cast<std::uint32_t>(regs[3]) == 0x48564856U,
        "unexpected CPUID register tuple");
}

bool WaitForService(SC_HANDLE service, DWORD expected, DWORD timeout_ms) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  SERVICE_STATUS_PROCESS status{};
  DWORD bytes = 0;
  do {
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<LPBYTE>(&status), sizeof(status),
                              &bytes)) {
      return false;
    }
    if (status.dwCurrentState == expected) return true;
    Sleep(100);
  } while (GetTickCount64() < deadline);
  return false;
}

void TestService(const std::wstring& name, bool start, bool stop,
                 TestState& state) {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) {
    Check(state, "SCM is accessible", false, std::to_string(GetLastError()));
    return;
  }
  SC_HANDLE service = OpenServiceW(manager, name.c_str(),
                                   SERVICE_QUERY_STATUS | SERVICE_START |
                                       SERVICE_STOP);
  Check(state, "driver service is installed", service != nullptr);
  if (!service) {
    CloseServiceHandle(manager);
    return;
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytes = 0;
  const bool queried = QueryServiceStatusEx(
      service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status),
      sizeof(status), &bytes) != FALSE;
  Check(state, "driver service status is queryable", queried);
  bool service_running = queried && status.dwCurrentState == SERVICE_RUNNING;
  bool started_by_test = false;
  if (start) {
    const BOOL result = StartServiceW(service, 0, nullptr);
    const DWORD error = result ? ERROR_SUCCESS : GetLastError();
    const bool accepted = result || error == ERROR_SERVICE_ALREADY_RUNNING;
    Check(state, "driver start request succeeds", accepted,
          std::to_string(error));
    started_by_test = result != FALSE;
    if (accepted) {
      service_running = WaitForService(service, SERVICE_RUNNING, 10000);
      Check(state, "driver reaches RUNNING state", service_running);
    } else {
      service_running = false;
    }
  }
  if (service_running && start) TestMagicCpuid(state);
  if (stop && started_by_test) {
    SERVICE_STATUS ignored{};
    const BOOL result = ControlService(service, SERVICE_CONTROL_STOP, &ignored);
    Check(state, "driver stop request succeeds", result != FALSE,
          std::to_string(GetLastError()));
    if (result) {
      Check(state, "driver reaches STOPPED state",
            WaitForService(service, SERVICE_STOPPED, 10000));
    }
  }
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
}

struct Options {
  fs::path root;
  fs::path driver;
  bool driver_explicit = false;
  std::wstring service = L"Nested_HV";
  bool hardware = false;
  bool runtime = false;
  bool start = false;
  bool stop = false;
  bool signature = false;
  bool allow_test_root = false;
  bool help = false;
};

void PrintUsage() {
  std::wcout << L"Nested_HV_ContractTests [--root path] [--driver path] "
                L"[--hardware] [--signature] [--runtime] [--start] [--stop] "
                L"[--allow-test-root]\n";
}

bool ParseOptions(int argc, wchar_t** argv, Options& options) {
#ifdef NESTED_HV_SOURCE_ROOT
  options.root = fs::path(NESTED_HV_SOURCE_ROOT);
#else
  options.root = fs::current_path();
#endif
  for (int i = 1; i < argc; ++i) {
    const std::wstring arg = argv[i];
    auto next = [&](fs::path& out) {
      if (i + 1 >= argc) return false;
      out = argv[++i];
      return true;
    };
    if (arg == L"--root") {
      if (!next(options.root)) return false;
    } else if (arg == L"--driver") {
      if (!next(options.driver)) return false;
      options.driver_explicit = true;
    } else if (arg == L"--service") {
      if (i + 1 >= argc) return false;
      options.service = argv[++i];
    } else if (arg == L"--hardware") {
      options.hardware = true;
    } else if (arg == L"--runtime") {
      options.runtime = true;
    } else if (arg == L"--start") {
      options.runtime = true;
      options.start = true;
    } else if (arg == L"--stop") {
      options.runtime = true;
      options.stop = true;
    } else if (arg == L"--signature") {
      options.signature = true;
    } else if (arg == L"--allow-test-root") {
      options.allow_test_root = true;
    } else if (arg == L"--help" || arg == L"-h") {
      options.help = true;
      return true;
    } else {
      std::wcerr << L"Unknown option: " << arg << L"\n";
      return false;
    }
  }
  if (options.driver.empty()) {
    options.driver = options.root / L"build/vscode/Debug/Nested_HV.sys";
  }
  return true;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  Options options;
  if (!ParseOptions(argc, argv, options)) return argc > 1 ? 2 : 0;
  if (options.help) {
    PrintUsage();
    return 0;
  }
  TestState state;

  TestSourceContract(options.root, state);
  if (options.hardware) TestHardware(state);
  if (options.signature || options.runtime || options.driver_explicit) {
    TestArtifact(options.driver, state);
  }
  if (options.signature) TestSignature(options.driver, options.allow_test_root, state);
  if (options.runtime) {
    TestService(options.service, options.start, options.stop, state);
  }

  std::cout << "\nDriver tests: " << state.passed << " passed, " << state.failed
            << " failed\n";
  return state.failed == 0 ? 0 : 1;
}
