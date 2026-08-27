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
constexpr std::uint32_t kVmExitSaveDebug = 1u << 2;
constexpr std::uint32_t kVmEntryLoadDebug = 1u << 2;
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
static_assert(reference::kVmExitSaveDebug == 0x4);
static_assert(reference::kVmEntryLoadDebug == 0x4);

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
  std::uint64_t GuestDr7{};
  std::uint64_t GuestDebugctl{};
};

static_assert(offsetof(GuestContextLayout, Rax) == 0x1000);
static_assert(offsetof(GuestContextLayout, GuestXcr0) == 0x1108);
static_assert(offsetof(GuestContextLayout, GuestXss) == 0x1110);
static_assert(offsetof(GuestContextLayout, GuestSCet) == 0x1118);
static_assert(offsetof(GuestContextLayout, GuestSsp) == 0x1120);
  static_assert(offsetof(GuestContextLayout, GuestInterruptSspTable) == 0x1128);
static_assert(offsetof(GuestContextLayout, GuestDr7) == 0x1130);
static_assert(offsetof(GuestContextLayout, GuestDebugctl) == 0x1138);
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
  CheckPattern(state, "CPUID XGETBV1 uses bit 2", vmx,
               R"(CPUID_D1_XGETBV1\s+\(1U\s*<<\s*2\))");
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
  CheckPattern(state, "VMX debug control encoding", vmx,
               R"(VM_EXIT_SAVE_DEBUG_CONTROLS\s+\(1UL\s*<<\s*2\)[\s\S]*VM_ENTRY_LOAD_DEBUG_CONTROLS\s+\(1UL\s*<<\s*2\))");
  CheckPattern(state, "IA32_DEBUGCTL is defined", vmx,
               R"(MSR_IA32_DEBUGCTL\s+0x000001D9)");
  CheckPattern(state, "XFD state is fail-closed", vmx,
               R"(MSR_IA32_XFD\s+0x000001C4[\s\S]*MSR_IA32_XFD_ERR\s+0x000001C5)");
  CheckPattern(state, "FRED capability bit is identified", vmx,
               R"(CPUID_7_1_EAX_FRED\s+\(1U\s*<<\s*17\))");
  CheckPattern(state, "FXSAVE capability bit is identified", vmx,
               R"(CPUID_1_EDX_FXSR\s+\(1U\s*<<\s*24\))");
  CheckPattern(state, "FXSAVE masks CR4 OSXSAVE", vmx,
               R"(CR4_OSXSAVE\s+\(1ULL\s*<<\s*18\))");
  Check(state, "PKU and MPX state bits are identified",
        vmx.find("CR4_PKE") != std::string::npos &&
            vmx.find("CPUID_7_EBX_MPX") != std::string::npos &&
            vmx.find("CPUID_7_ECX_PKU") != std::string::npos &&
            vmx.find("CPUID_7_ECX_OSPKE") != std::string::npos &&
            vmx.find("XCR0_PKRU") != std::string::npos);

  Check(state, "flight recorder has fixed-size records", common.find(
        "struct HvTraceRecord") != std::string::npos &&
        common.find("HV_TRACE_RECORDS_PER_CPU = 512") != std::string::npos &&
        common.find("HV_TRACE_TAIL_RECORDS = 32") != std::string::npos);
  const std::size_t trace_begin =
      vmm.find("static __forceinline void WriteHvTrace");
  const std::size_t trace_end =
      vmm.find("extern \"C\" void HvTraceCurrentVcpuEvent", trace_begin);
  const std::string trace_source =
      trace_begin != std::string::npos && trace_end > trace_begin
          ? vmm.substr(trace_begin, trace_end - trace_begin)
          : std::string{};
  Check(state, "flight recorder writes atomically without formatting",
        trace_source.find("InterlockedIncrement64") != std::string::npos &&
            trace_source.find("MemoryBarrier();") != std::string::npos &&
            trace_source.find("DbgPrint") == std::string::npos);
  CheckPattern(state, "fatal snapshot is captured before VMXOFF", asm_source,
               R"(call HvCaptureFatalSnapshotPreVmxoff[\s\S]{0,500}vmxoff)");
  Check(state, "crash blob carries a trace tail",
        vmm.find("TraceRecordsPerCpu = HV_TRACE_TAIL_RECORDS") != std::string::npos &&
        vmm.find("snapshotCount * HV_TRACE_TAIL_RECORDS") != std::string::npos &&
            vmm.find("traceTail") != std::string::npos);

  CheckPattern(state, "MASM GuestContext XCR0 offset", asm_source,
               R"(CTX_GUEST_XCR0\s+equ\s+01108h)");
  CheckPattern(state, "MASM GuestContext XSS offset", asm_source,
               R"(CTX_GUEST_XSS\s+equ\s+01110h)");
  CheckPattern(state, "MASM GuestContext CET offset", asm_source,
               R"(CTX_GUEST_S_CET\s+equ\s+01118h)");
  CheckPattern(state, "MASM GuestContext debug offsets", asm_source,
               R"(CTX_GUEST_DR7\s+equ\s+01130h[\s\S]*CTX_GUEST_DEBUGCTL\s+equ\s+01138h)");
  CheckPattern(state, "VMREAD flags are checked", asm_source,
               R"(HvVmReadChecked proc[\s\S]{0,180}vmread r8, rcx[\s\S]{0,180}mov \[rdx\], r8)");
  Check(state, "legacy FXSAVE backend is guarded",
        asm_source.find("g_XstateMode") != std::string::npos &&
            asm_source.find("vmxSaveFxsave:") != std::string::npos &&
            asm_source.find("fxsave64 [rsp]") != std::string::npos &&
            asm_source.find("fxrstor64 [rsp]") != std::string::npos);
  CheckPattern(state, "VMWRITE uses field then value operands", asm_source,
               R"(HvVmWrite proc[\s\S]{0,260}vmwrite rcx, rdx)");
  CheckPattern(state, "VMLAUNCH guest RSP uses field then value operands",
               asm_source,
               R"(mov ecx, VMCS_GUEST_RSP[\s\S]{0,120}vmwrite rcx, rdx)");
  CheckPattern(state, "VMLAUNCH guest RIP uses field then value operands",
               asm_source,
               R"(mov ecx, VMCS_GUEST_RIP[\s\S]{0,120}vmwrite rcx, rdx)");
  Check(state, "C++ has no unchecked VMREAD path",
        vmm.find("HvVmRead(") == std::string::npos);
  CheckPattern(state, "FXSAVE mode hides XSAVE from the guest", vmm,
               R"(leaf\s*==\s*1[\s\S]{0,280}g_XstateMode\s*==\s*XstateSaveFxsave[\s\S]{0,180}CPUID_1_ECX_XSAVE)");
  CheckPattern(state, "FXSAVE mode hides AVX state", vmm,
               R"(CPUID_1_ECX_AVX[\s\S]{0,260}CPUID_1_ECX_FMA[\s\S]{0,140}CPUID_1_ECX_F16C)");
  CheckPattern(state, "FXSAVE mode hides CPUID leaf D", vmm,
               R"(leaf\s*==\s*0xD[\s\S]{0,120}g_XstateMode\s*==\s*XstateSaveFxsave[\s\S]{0,120}RtlZeroMemory\(regs,\s* sizeof\(regs\)\))");
  Check(state, "guest OSXSAVE follows the selected backend",
        vmm.find("requiredOsxsave = g_XstateMode != XstateSaveFxsave") !=
                std::string::npos &&
            vmm.find("value & CR4_OSXSAVE") != std::string::npos &&
            vmm.find("InjectGuestException(c, 13") != std::string::npos);
  CheckPattern(state, "VMCS always masks guest OSXSAVE", vmm,
               R"(cr4GuestHostMask[\s\S]{0,180}CR4_OSXSAVE[\s\S]{0,220}cr4ReadShadow[\s\S]{0,180}CR4_OSXSAVE)");
  CheckPattern(state, "guest debug VMREAD failures halt",
               asm_source,
               R"(VMCS_GUEST_DR7[\s\S]{0,240}test dl, 041h[\s\S]{0,360}VMCS_GUEST_DEBUGCTL[\s\S]{0,240}test dl, 041h[\s\S]{0,260}CTX_HALT_VM)");
  CheckPattern(state, "VM-exit uses XSAVES", asm_source,
               R"(\bxsaves\s+\[rsp\])");
  CheckPattern(state, "VM-exit uses XRSTORS", asm_source,
               R"(\bxrstors\s+\[rsp\])");
  CheckPattern(state, "XSAVES uses immutable XSS mask", asm_source,
               R"(mov r15, qword ptr \[g_XsavesMask\][\s\S]{0,500}xsaves\s+\[rsp\])");
  CheckPattern(state, "XSAVES uses the host XCR0 mask", asm_source,
               R"(HOST_XCR0_FRAME_SLOT[\s\S]{0,260}xsaves\s+\[rsp\])");
  CheckPattern(state, "XRSTORS restores guest XSS after fixed mask", asm_source,
               R"(xrstors\s+\[rsp\][\s\S]{0,240}CTX_GUEST_XSS[\s\S]{0,160}wrmsr)");
  CheckPattern(state, "XRSTORS restores host state before guest XCR0", asm_source,
               R"(HOST_XCR0_FRAME_SLOT[\s\S]{0,500}xrstors\s+\[rsp\][\s\S]{0,260}CTX_GUEST_XCR0[\s\S]{0,120}xsetbv)");
  CheckPattern(state, "IA32_XSS access is XSAVES-gated", asm_source,
               R"(cmp byte ptr \[g_XsavesEnabled\], 0[\s\S]{0,80}je vmxSaveXsave)");
  CheckPattern(state, "CET teardown MSRs are gated", asm_source,
               R"(cmp byte ptr \[g_CetVmcsEnabled\], 0[\s\S]{0,100}je restoreGuestCetDone)");
  CheckPattern(state, "host XCR0 is installed before handler", asm_source,
               R"(HOST_XCR0_FRAME_SLOT[\s\S]{0,1200}call VmExitHandler)");
  const std::size_t halt_begin = asm_source.find("vmxHalt:");
  const std::size_t halt_end = asm_source.find("vmxResumeFailure:");
  CheckPattern(state, "fatal path parks after VMXOFF", asm_source,
               R"(vmxHalt:[\s\S]{0,1800}call MarkCurrentVcpuParked[\s\S]{0,300}vmxoff)");
  CheckPattern(state, "VMRESUME failure is validated in C++", asm_source,
               R"(vmxResumeFailure:[\s\S]{0,1500}call HandleVmResumeFailure)");
  CheckPattern(state, "fatal path triggers the dedicated bugcheck", asm_source,
               R"(vmxHalt:[\s\S]{0,3000}call HvFatalBugCheck)");
  const std::size_t saved_fatal_begin =
      vmm.find("HvFatalBugCheck(GuestContext* c)");
  const std::size_t saved_fatal_reason =
      saved_fatal_begin == std::string::npos
          ? std::string::npos
          : vmm.find("LastExitReasonRaw", saved_fatal_begin);
  const std::size_t saved_fatal_bugcheck =
      saved_fatal_begin == std::string::npos
          ? std::string::npos
          : vmm.find("KeBugCheckEx", saved_fatal_begin);
  Check(state, "fatal bugcheck uses the saved exit snapshot",
        saved_fatal_begin != std::string::npos &&
            saved_fatal_reason > saved_fatal_begin &&
            saved_fatal_bugcheck > saved_fatal_reason);
  CheckPattern(state, "native teardown reaches the stopped marker after VMXOFF", asm_source,
               R"(HvRestoreStateAndReturn proc[\s\S]{0,7000}vmxoff[\s\S]{0,1200}call MarkCurrentVcpuStopped)");
  const std::size_t teardown_begin =
      asm_source.find("HvRestoreStateAndReturn proc");
  const std::size_t teardown_end =
      asm_source.find("HvRestoreStateAndReturn endp", teardown_begin);
  const std::string teardown_source =
      teardown_begin != std::string::npos && teardown_end > teardown_begin
          ? asm_source.substr(teardown_begin, teardown_end - teardown_begin)
          : std::string{};
  const std::size_t host_kgs_restore =
      teardown_source.find("HOST_KGS_CONTEXT_SLOT");
  const std::size_t host_kgs_wrmsr =
      host_kgs_restore != std::string::npos
          ? teardown_source.find("wrmsr", host_kgs_restore)
          : std::string::npos;
  const std::size_t teardown_marker =
      teardown_source.find("MarkCurrentVcpuTearingDown");
  Check(state, "native teardown restores host KERNEL_GS_BASE before marker",
         host_kgs_restore != std::string::npos &&
             host_kgs_wrmsr != std::string::npos &&
             teardown_marker != std::string::npos &&
             host_kgs_wrmsr < teardown_marker);
  const std::size_t host_xcr0_restore =
      teardown_source.find("HOST_XCR0_FRAME_SLOT");
  const std::size_t host_xcr0_xsetbv =
      host_xcr0_restore != std::string::npos
          ? teardown_source.find("xsetbv", host_xcr0_restore)
          : std::string::npos;
  Check(state, "native teardown restores host XCR0 before marker",
        host_xcr0_restore != std::string::npos &&
            host_xcr0_xsetbv != std::string::npos &&
            teardown_marker != std::string::npos &&
            host_xcr0_xsetbv < teardown_marker);
  CheckPattern(state, "native teardown has an intermediate lifecycle state", vmm,
               R"(MarkCurrentVcpuTearingDown[\s\S]{0,500}VcpuTearingDown)");
  CheckPattern(state, "stop callback leaves a tearing down CPU alone", vmm,
               R"(state == VcpuTearingDown[\s\S]{0,220}return 0)");
  Check(state, "stopped state requires teardown quiescence",
        vmm.find("if (vcpu->TeardownQuiesced == 0) return;") !=
                std::string::npos &&
            vmm.find("InterlockedExchange(&vcpu->TeardownQuiesced, 1)") !=
                std::string::npos &&
            vmm.find("HvCall(HYPERVISOR_MAGIC, VMCALL_UNLOAD") !=
                std::string::npos);
  CheckPattern(state, "live scan retains a tearing down CPU", vmm,
               R"(state == VcpuLaunched \|\| state == VcpuVmxOn[\s\S]{0,180}VcpuTearingDown)");
  Check(state, "fatal assembly does not VMREAD after VMXOFF",
        halt_begin != std::string::npos && halt_end > halt_begin &&
            asm_source.substr(halt_begin, halt_end - halt_begin).find("HvVmRead") ==
                std::string::npos);
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
               R"(VmExitHandler\(GuestContext\* Ctx\)[\s\S]{0,3200}CONTROL_VM_ENTRY_INTR_INFO_FIELD, 0[\s\S]{0,300}CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE, 0)");
  const std::size_t exit_begin = vmm.find("extern \"C\" void VmExitHandler");
  const std::size_t exit_end = vmm.find(
      "// =============================================================================="
      "\n// VMCS Setup", exit_begin);
  const std::string exit_source =
      exit_begin != std::string::npos && exit_end > exit_begin
          ? vmm.substr(exit_begin, exit_end - exit_begin)
          : std::string{};
  Check(state, "VM-entry failure preserves raw reason",
        exit_source.find("rawExitReason") != std::string::npos &&
            exit_source.find("LastExitReasonRaw") != std::string::npos &&
            exit_source.find("if (entryFailure)") != std::string::npos);
  CheckPattern(state, "VM-entry failure does not use native teardown", vmm,
               R"(if\s*\(entryFailure\)[\s\S]{0,650}LastVmInstructionError[\s\S]{0,350}return;)");
  CheckPattern(state, "VMRESUME flags are passed to C++", asm_source,
               R"(vmxResumeFailure:[\s\S]{0,700}pushfq[\s\S]{0,900}mov rdx, rbx[\s\S]{0,180}call HandleVmResumeFailure)");
  CheckPattern(state, "VMRESUME failure reads instruction error only for ZF",
               vmm,
               R"(vmFailValid\s*=\s*\(resumeFlags\s*&\s*\(1ULL\s*<<\s*6\)\)[\s\S]{0,500}VM_INSTRUCTION_ERROR)");
  CheckPattern(state, "native teardown validates descriptor state", vmm,
               R"(UpdateNativeTeardownContract\(vcpu\)[\s\S]{0,500}NativeTeardownSafe)");
  CheckPattern(state, "safe exit requires descriptor contract", vmm,
               R"(descriptorContractSafe[\s\S]{0,220}NativeTeardownSafe[\s\S]{0,260}c->AbortVm)");
  Check(state, "DEBUGCTL is virtualized",
         vmm.find("if (msrIndex == MSR_IA32_DEBUGCTL)") != std::string::npos &&
             vmm.find("VmWriteChecked(GUEST_DEBUGCTL") != std::string::npos &&
             vmm.find("MSR_IA32_DEBUGCTL") != std::string::npos);
  CheckPattern(state, "DEBUGCTL reserved bits fail with #GP", vmm,
               R"(if\s*\(!IsValidDebugctl\(value\.QuadPart\)\)[\s\S]{0,180}InjectGuestException\(Ctx,\s*13)");
  CheckPattern(state, "guest CR3 state rejects no-flush bit", vmm,
               R"(static __forceinline bool IsValidArchitecturalCr3\([\s\S]{0,260}value\s*&\s*\(1ULL\s*<<\s*63\))");
  Check(state, "CR0 and CR4 guest writes honor VMX fixed bits",
        vmm.find("IsFixedCrValueValid(value, MSR_IA32_VMX_CR0_FIXED0") !=
                std::string::npos &&
            vmm.find("IsFixedCrValueValid(requestedCr4") !=
                std::string::npos);
  CheckPattern(state, "EFER illegal mode changes inject #GP", vmm,
               R"(kWritableEferBits\s*=\s*EFER_SCE\s*\|\s*EFER_NXE[\s\S]{0,300}InjectGuestException\(Ctx,\s*13)");
  const std::size_t msr_read_begin = vmm.find("bool HandleMsrRead(");
  const std::size_t msr_write_begin = vmm.find("bool HandleMsrWrite(");
  Check(state, "privileged MSR exits reject CPL3",
        msr_read_begin != std::string::npos && msr_write_begin > msr_read_begin &&
            vmm.substr(msr_read_begin, msr_write_begin - msr_read_begin).find(
                "Ctx->GuestCs & 3U") != std::string::npos &&
            vmm.substr(msr_write_begin, 900).find("Ctx->GuestCs & 3U") !=
                std::string::npos &&
            vmm.substr(msr_read_begin, msr_write_begin - msr_read_begin).find(
                "InjectGuestException(Ctx, 13, true, 0)") != std::string::npos &&
            vmm.substr(msr_write_begin, 900).find(
                "InjectGuestException(Ctx, 13, true, 0)") != std::string::npos);
  CheckPattern(state, "CR access rejects CPL3", vmm,
               R"(static bool HandleCrAccess\(GuestContext\* c\)[\s\S]{0,220}c->GuestCs\s*&\s*3U\)[\s\S]{0,120}InjectGuestException\(c,\s*13,\s*true,\s*0)");
  CheckPattern(state, "XSETBV rejects CPL3", vmm,
               R"(static bool HandleXsetbv\(GuestContext\* c,[\s\S]{0,220}c->GuestCs\s*&\s*3U\)[\s\S]{0,120}InjectGuestException\(c,\s*13,\s*true,\s*0)");
  const std::size_t xsetbv_host_mask =
      vmm.find("if (requested != vcpu->HostXcr0)");
  const std::size_t xsetbv_host_mask_end =
      vmm.find("c->GuestXcr0 = requested", xsetbv_host_mask);
  const std::string xsetbv_host_mask_source =
      xsetbv_host_mask != std::string::npos &&
              xsetbv_host_mask_end > xsetbv_host_mask
          ? vmm.substr(xsetbv_host_mask,
                       xsetbv_host_mask_end - xsetbv_host_mask)
          : std::string{};
  Check(state, "XSETBV keeps the fixed host XCR0 contract",
        xsetbv_host_mask != std::string::npos &&
            xsetbv_host_mask_end > xsetbv_host_mask &&
            xsetbv_host_mask_source.find("InjectGuestException(c, 13") !=
                std::string::npos);
  CheckPattern(state, "CPL3 VMCALL injects GP", vmm,
               R"(The unload token is a ring-0 service call[\s\S]{0,180}InjectGuestException\(Ctx,\s*13,\s*true,\s*0)");
  Check(state, "CR0 writes synchronize the teardown snapshot",
        vmm.find("c->GuestCr0 = newCr0") != std::string::npos);
  Check(state, "CR4 writes synchronize the teardown snapshot",
        vmm.find("c->GuestCr4 = actualCr4") != std::string::npos);
  Check(state, "FS/GS MSR writes synchronize the teardown snapshot",
        vmm.find("Ctx->GuestFsBase = value.QuadPart") != std::string::npos &&
            vmm.find("Ctx->GuestGsBase = value.QuadPart") != std::string::npos);
  Check(state, "EFER/PAT MSR writes synchronize the teardown snapshot",
        vmm.find("Ctx->GuestEfer = newValue") != std::string::npos &&
            vmm.find("Ctx->GuestPat = value.QuadPart") != std::string::npos);
  Check(state, "GS/KGS state uses authoritative snapshots",
        vmm.find("expectedKgs") == std::string::npos &&
            vmm.find("observedKgs") == std::string::npos &&
            vmm.find("Untracked KERNEL_GS_BASE") == std::string::npos);
  CheckPattern(state, "debug controls are paired in VMCS", vmm,
               R"(requestedExit\s*=\s*VM_EXIT_HOST_ADDRESS_SPACE_SIZE[\s\S]{0,180}VM_EXIT_SAVE_DEBUG_CONTROLS[\s\S]{0,900}requestedEntry\s*=\s*VM_ENTRY_IA32E_MODE_GUEST[\s\S]{0,180}VM_ENTRY_LOAD_DEBUG_CONTROLS)");
  Check(state, "CET does not depend on VMX BASIC bit 56",
        vmm.find("VMX_BASIC_NO_HW_ERROR_CODE") == std::string::npos);
  const std::size_t setup_begin = vmm.find("bool SetupVmcs(");
  const std::size_t setup_end = vmm.find(
      "// ==============================================================================\n// Launch Logic", setup_begin);
  Check(state, "IPI launch preserves callback interrupt state",
        setup_begin != std::string::npos && setup_end > setup_begin &&
            vmm.substr(setup_begin, setup_end - setup_begin).find(
                "u64 guestRflags = GetRflags()") != std::string::npos &&
            vmm.substr(setup_begin, setup_end - setup_begin).find(
                "guestRflags &= ~((1ULL << 17)") != std::string::npos &&
            vmm.substr(setup_begin, setup_end - setup_begin).find(
                "guestRflags &= ~((1ULL << 9)") == std::string::npos &&
            vmm.substr(setup_begin, setup_end - setup_begin).find(
                "Preserve the callback's interrupt flag") != std::string::npos);
  CheckPattern(state, "unload VMCALL logs the IRET contract", vmm,
               R"(unload VMCALL: cpu=.*GuestRip|unload VMCALL decision: cpu=)");
  CheckPattern(state, "non-empty LDTR fails closed", vmm,
               R"(ldtrSelector\s*!=\s*0[\s\S]{0,600}non-empty LDTR[\s\S]{0,240}return false)");
  CheckPattern(state, "GDT validation checks descriptor type", vmm,
               R"(const u8 type = access & 0x0FU;[\s\S]{0,900}if \(requireSystem\)[\s\S]{0,260}type == 9U)");
  const std::size_t selector_validator =
      vmm.find("static bool IsGdtSelectorUsable(");
  const std::size_t selector_validator_end =
      vmm.find("bool InitializeVmxFeatureContract()", selector_validator);
  const std::string selector_validator_source =
      selector_validator != std::string::npos &&
              selector_validator_end > selector_validator
          ? vmm.substr(selector_validator,
                       selector_validator_end - selector_validator)
          : std::string{};
  Check(state, "GDT validation accepts user RPL data selectors",
        selector_validator_source.find("selector & 0x4U") != std::string::npos &&
            selector_validator_source.find("requireKernelPrivilege") !=
                std::string::npos &&
            selector_validator_source.find("selector & 0x3U") !=
                std::string::npos);
  CheckPattern(state, "VMCS accepts current user data selectors", vmm,
               R"(dsSelector,\s*true,\s*false,\s*false,\s*false,\s*false[\s\S]{0,180}esSelector,\s*true,\s*false,\s*false,\s*false,\s*false)");
  CheckPattern(state, "VMCS keeps CS SS and TR at kernel privilege", vmm,
               R"(csSelector,\s*false,\s*false,\s*true,\s*true,\s*false[\s\S]{0,260}ssSelector,\s*false,\s*false,\s*false,\s*true,\s*true[\s\S]{0,800}trSelector,\s*false,\s*true,\s*false,\s*true,\s*false)");
  CheckPattern(state, "TSS base is canonical before VMCS write", vmm,
               R"(base\s*\|=\s*\(high\s*<<\s*32\)[\s\S]{0,120}return\s+IsCanonical\(base\)\s*\?\s*base\s*:\s*0)");
  CheckPattern(state, "feature contract has a sticky validity result", vmm,
               R"(g_VmxFeatureContractInitialized\s*=\s*true)");
  CheckPattern(state, "production mode launches every active CPU", vmm,
               R"(kDebugSingleCpu\s*=\s*false)");
  CheckPattern(state, "IPI broadcast is single and all-processor", vmm,
               R"(BroadcastToAllProcessorGroups\([\s\S]{0,500}return callback \? KeIpiGenericCall\(callback, 0\) : 0)");
  CheckPattern(state, "CPU generation profile has explicit branches", vmm,
               R"(VmxProfileLegacyControls[\s\S]{0,900}VmxProfileTrueControls[\s\S]{0,900}VmxProfileXsaves[\s\S]{0,900}VmxProfileRdtscp[\s\S]{0,900}VmxProfileInvpcid)");
  CheckPattern(state, "CPU generation profile checks optional controls", vmm,
               R"(BuildVmxCapabilityProfile\([\s\S]{0,3200}VmxProfileTertiaryControls)");
  CheckPattern(state, "CPU generation selects explicit VMX control branches", vmm,
               R"(SelectVmxControlGeneration[\s\S]{0,700}VmxGenerationLegacy[\s\S]{0,700}VmxGenerationTrueTertiary)");
  CheckPattern(state, "CPU generation controls use the local profile", vmm,
               R"(const u32 profile\s*=\s*Vcpu->VmxProfile[\s\S]{0,500}VmxProfileInvpcid[\s\S]{0,500}VmxProfileRdtscp)");
  Check(state, "legacy CPUs hide unsupported optional instructions",
        vmm.find("VmxProfileInvpcid") != std::string::npos &&
            vmm.find("regs[1] &= ~(1 << 10)") != std::string::npos &&
            vmm.find("VmxProfileRdtscp") != std::string::npos &&
            vmm.find("regs[3] &= ~(1 << 27)") != std::string::npos);
  CheckPattern(state, "each CPU enforces only global VMX state contracts", vmm,
               R"(globalProfileMask\s*=\s*VmxProfileXsaves\s*\|\s*VmxProfileCetVmcs[\s\S]{0,500}VcpuFailed)");
  const std::size_t start_hypervisor =
      vmm.find("extern \"C\" NTSTATUS StartHypervisor()");
  const std::string start_source =
      start_hypervisor != std::string::npos
          ? vmm.substr(start_hypervisor)
          : std::string{};
  const std::size_t optional_reduce =
      vmm.find("InterlockedAnd(&g_VmxGuestOptionalProfileCandidate");
  Check(state, "guest optional profile uses all-CPU intersection",
        optional_reduce != std::string::npos &&
            vmm.find("kGuestOptionalProfileMask") != std::string::npos);
  const std::size_t optional_seed = start_source.find(
      "InterlockedExchange(&g_VmxGuestOptionalProfileCandidate");
  const std::size_t optional_zero =
      start_source.find("InterlockedExchange(&g_VmxGuestOptionalProfile,");
  const bool optional_zero_value =
      optional_zero != std::string::npos &&
      start_source.substr(optional_zero, 96).find("0") != std::string::npos;
  const std::size_t optional_broadcast =
      start_source.find("BroadcastToAllProcessorGroups(EnableHvCallback)");
  const std::size_t optional_publish = start_source.find(
      "InterlockedExchange(&g_VmxGuestOptionalProfile,", optional_broadcast);
  const std::size_t optional_publish_value =
      optional_publish != std::string::npos
          ? start_source.find("candidateOptionalProfile", optional_publish)
          : std::string::npos;
  const std::size_t launch_result = start_source.find("if (ok != expected)");
  Check(state, "guest optional profile publishes after synchronized launch",
        optional_zero_value &&
            optional_seed != std::string::npos &&
            optional_broadcast != std::string::npos &&
            optional_publish != std::string::npos &&
            optional_publish_value != std::string::npos &&
            launch_result != std::string::npos &&
            optional_seed < optional_broadcast &&
            optional_broadcast < launch_result &&
            launch_result < optional_publish &&
            optional_publish < optional_publish_value);
  CheckPattern(state, "feature control is never provisioned by the driver", vmm,
               R"(EnsureFeatureControlForVmx\([\s\S]{0,500}return \(featureControl & required\) == required)");
  CheckPattern(state, "feature contract resets only while idle", vmm,
               R"(if\s*\(g_VcpuData\s*==\s*nullptr\)[\s\S]{0,500}g_VmxFeatureContractInitialized\s*=\s*false)");
  CheckPattern(state, "VMX region allocation follows VMX BASIC", vmm,
               R"(g_VmxRequires32BitPhysicalAddress\s*=\s*\([\s\S]{0,180}VMX_BASIC_PHYSICAL_ADDRESS_32)");
  CheckPattern(state, "CPUID XSS mask is restricted to the guest contract", vmm,
               R"(g_SupportedXssMask\s*=\s*enumeratedXss\s*&\s*IA32_XSS_GUEST_KNOWN_MASK)");
  CheckPattern(state, "XSAVES fixed mask preserves host XSS", vmm,
               R"(g_XsavesMask\s*=\s*g_XsavesEnabled[\s\S]{0,120}\?\s*g_HostXssMask\s*:\s*0)");
  CheckPattern(state, "guest XSS stays inside fixed frame mask", vmm,
               R"(g_SupportedXssMask\s*&=\s*g_XsavesMask)");
  CheckPattern(state, "guest XSS excludes hidden IPT", vmm,
               R"(g_GuestXssWriteMask\s*=\s*g_SupportedXssMask\s*;)");
  CheckPattern(state, "preservation contract includes PT and CET_U", vmx,
               R"(IA32_XSS_PRESERVABLE_MASK\s+\(IA32_XSS_IPT\s*\|\s*IA32_XSS_CET_U\))");
  Check(state, "XSAVES computed frame matches the live CPUID selection",
        vmm.find("g_XsaveStateSize != xsavesSize") != std::string::npos &&
            vmm.find("localXsavesSize != localXsaveStateSize") !=
                std::string::npos);
  CheckPattern(state, "active PT is rejected before VMX", vmm,
               R"(IA32_XSS_IPT[\s\S]{0,500}MSR_IA32_RTIT_CTL[\s\S]{0,300}ptControl\s*&\s*IA32_RTIT_CTL_TRACEEN)");
  CheckPattern(state, "guest XSS starts with the interrupted host state", vmm,
               R"(vcpu->HostXss\s*=\s*hostXss[\s\S]{0,260}vcpu->GuestXss\s*=\s*hostXss\s*;)");
  const std::size_t xss_msr_write_begin = vmm.find("bool HandleMsrWrite");
  const std::size_t xss_msr_write_end =
      vmm.find("bool Handle", xss_msr_write_begin + 1);
  const std::string msr_write_source =
      xss_msr_write_begin != std::string::npos &&
              xss_msr_write_end > xss_msr_write_begin
          ? vmm.substr(xss_msr_write_begin,
                       xss_msr_write_end - xss_msr_write_begin)
          : std::string{};
  const std::size_t xss_branch =
      msr_write_source.find("if (msrIndex == MSR_IA32_XSS)");
  const std::size_t xss_legacy_gate =
      msr_write_source.find("if (!g_XsavesEnabled)", xss_branch);
  const std::size_t xss_legacy_change =
      msr_write_source.find("value.QuadPart != 0", xss_legacy_gate);
  const std::size_t xss_legacy_exit =
      msr_write_source.find("RequestSafeExit(Ctx)", xss_legacy_change);
  const std::size_t xss_change =
      msr_write_source.find("value.QuadPart != Ctx->GuestXss", xss_legacy_exit);
  const std::size_t xss_native_exit =
      msr_write_source.find("RequestSafeExit(Ctx)", xss_change);
  Check(state, "guest XSS changes leave VMX for native execution",
        xss_branch != std::string::npos &&
            xss_legacy_gate > xss_branch &&
            xss_legacy_change > xss_legacy_gate &&
            xss_legacy_exit > xss_legacy_change &&
            xss_change > xss_legacy_exit &&
            xss_native_exit > xss_change);
  CheckPattern(state, "PT and unsupported CET accesses leave VMX natively", vmm,
               R"(if\s*\(IsIntelPtMsr\(msrIndex\)\s*\|\|\s*IsCetStateMsr\(msrIndex\)\)\s*\{[\s\S]{0,180}RequestSafeExit\(Ctx\)[\s\S]{0,100}return true;)");
  CheckPattern(state, "FS_BASE writes update the FS snapshot", vmm,
               R"(VmWriteChecked\(GUEST_FS_BASE[\s\S]{0,180}Ctx->GuestFsBase\s*=\s*value\.QuadPart)");
  CheckPattern(state, "PAT writes update the PAT snapshot", vmm,
               R"(VmWriteChecked\(GUEST_PAT[\s\S]{0,180}Ctx->GuestPat\s*=\s*value\.QuadPart)");
  const std::size_t guest_xss_install =
      vmm.find("!WriteMsrSafe(MSR_IA32_XSS, vcpu->GuestXss)");
  const std::size_t launch_ready_log =
      guest_xss_install == std::string::npos
          ? std::string::npos
          : vmm.find("VMCS ready; entering VMLAUNCH", guest_xss_install);
  Check(state, "guest XSS is installed before launch",
        guest_xss_install != std::string::npos &&
            launch_ready_log > guest_xss_install);
  Check(state, "each CPU validates local XCR0 contract",
        vmm.find("localSupportedXcr0") != std::string::npos &&
            vmm.find("localXcr0 = _xgetbv(0)") != std::string::npos &&
            vmm.find("localXcr0 & ~localSupportedXcr0") != std::string::npos);
  CheckPattern(state, "each CPU validates local CR4 OSXSAVE contract", vmm,
               R"(const u64 localCr4\s*=\s*__readcr4\(\)[\s\S]{0,700}localUsesXsave[\s\S]{0,260}CR4_OSXSAVE)");
  Check(state, "each CPU retains local XSAVE area size",
        vmm.find("localXsaveAreaSize = static_cast<u32>(localCpuid[1]);") !=
                std::string::npos &&
            vmm.find("localXsaveAreaSize != g_XsaveStateSize") !=
                std::string::npos);
  Check(state, "local CPUID-only XSTATE components do not reject XCR0",
        vmm.find("(localSupportedXcr0 & ~localXcr0)") == std::string::npos);
  CheckPattern(state, "each CPU validates XRSTORS", vmm,
               R"(g_XsavesEnabled\s*\)[\s\S]{0,400}localXsaveFeatures\s*&\s*CPUID_D1_XSAVES)");
  CheckPattern(state, "each CPU validates complete XSS mask", vmm,
               R"(g_XsavesMask\s*&\s*~localXssMask)");
  Check(state, "each CPU validates local CR4 CET contract",
        vmm.find("const u64 localCr4 = __readcr4()") != std::string::npos &&
            vmm.find("const bool localCet = (localCr4 & CR4_CET)") !=
                std::string::npos &&
            vmm.find("localCet != (g_CetVmcsEnabled != 0)") !=
                std::string::npos);
  CheckPattern(state, "each CPU rejects active FRED", vmm,
               R"(localCr4\s*&\s*CR4_FRED[\s\S]{0,260}VcpuFailed)");
  CheckPattern(state, "each CPU rejects active user CET state", vmm,
               R"(localCetEnumerated[\s\S]{0,900}ReadMsrSafe\(MSR_IA32_U_CET[\s\S]{0,260}IA32_CET_ENABLE_MASK[\s\S]{0,260}VcpuFailed)");
  CheckPattern(state, "each CPU rejects active PL3 shadow stack", vmm,
               R"(localCetShadowStackEnumerated[\s\S]{0,700}ReadMsrSafe\(MSR_IA32_PL3_SSP[\s\S]{0,260}localPl3Ssp\s*!=\s*0[\s\S]{0,260}VcpuFailed)");
  CheckPattern(state, "PT MSR window is intercepted", vmm,
               R"(MSR_IA32_RTIT_OUTPUT_BASE[\s\S]{0,220}0x58FU[\s\S]{0,220}setBit\(msr, false\))");
  CheckPattern(state, "XFD MSRs are intercepted", vmm,
               R"(MSR_IA32_XFD, MSR_IA32_XFD_ERR[\s\S]{0,180}setBit\(msr, false\))");
  CheckPattern(state, "guest CPUID hides unvirtualized XCR1", vmm,
               R"(leaf\s*==\s*0xD\s*&&\s*subleaf\s*==\s*1[\s\S]{0,320}CPUID_D1_XGETBV1[\s\S]{0,180}CPUID_D1_XFD)");
  CheckPattern(state, "FRED uses CPUID subleaf one", vmm,
               R"(localCpuid7MaxSubleaf\s*=\s*static_cast<u32>\(localCpuid\[0\]\)[\s\S]{0,500}__cpuidex\(localCpuid, 7, 1\)[\s\S]{0,180}CPUID_7_1_EAX_FRED)");
  CheckPattern(state, "diagnostic VM-exit log is rate limited", vmm,
               R"(InterlockedIncrement\(&vcpu->VmExitCount\)[\s\S]{0,600}exitCount\s*<=\s*16)");
  CheckPattern(state, "diagnostic launch log includes VMCS state", vmm,
               R"(VMCS ready; entering VMLAUNCH[\s\S]{0,240}revision=0x%X)");
  CheckPattern(state, "diagnostic trace captures guest transition state", vmm,
               R"(LastGuestCr0\s*=\s*Ctx->GuestCr0[\s\S]{0,1100}LastGuestTr\s*=\s*guestTr[\s\S]{0,1000}LastVmExitIntrInfo)");
  CheckPattern(state, "launch state is published by the success marker", vmm,
               R"(MarkCurrentVcpuLaunched[\s\S]{0,900}State[\s\S]{0,140}VcpuLaunched)");
  const std::size_t launch_marker_begin = vmm.find(
      "extern \"C\" void MarkCurrentVcpuLaunched()");
  const std::size_t launch_marker_end = vmm.find(
      "extern \"C\" void MarkCurrentVcpuParked()", launch_marker_begin);
  Check(state, "launch marker uses VMX stage and atomic VmxOn publication",
        launch_marker_begin != std::string::npos &&
            launch_marker_end > launch_marker_begin &&
            vmm.substr(launch_marker_begin,
                       launch_marker_end - launch_marker_begin)
                    .find("InterlockedCompareExchange(&vcpu->LaunchStage, 5, 4)") !=
                std::string::npos &&
            vmm.substr(launch_marker_begin,
                       launch_marker_end - launch_marker_begin)
                     .find("VcpuLaunched") != std::string::npos &&
             vmm.substr(launch_marker_begin,
                        launch_marker_end - launch_marker_begin)
                     .find("VcpuVmxOn") != std::string::npos);
  Check(state, "launch marker does not inspect guest CR4.VMXE",
        launch_marker_begin != std::string::npos &&
            launch_marker_end > launch_marker_begin &&
            vmm.substr(launch_marker_begin,
                       launch_marker_end - launch_marker_begin)
                    .find("__readcr4()") == std::string::npos);
  CheckPattern(state, "unresolved launch states are detected", vmm,
               R"(HasUnresolvedVcpu[\s\S]{0,550}state == VcpuFailed[\s\S]{0,550}return true)");
  CheckPattern(state, "unresolved launch states quarantine teardown", vmm,
               R"(HasParkedVcpu\(\)\s*\|\|\s*HasLiveVcpu\(\)\s*\|\|\s*HasUnresolvedVcpu\(\)[\s\S]{0,350}kHvLifecycleQuarantined)");
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
               R"(HvLaunchGuest proc[\s\S]{0,1100}sub rsp, 200h[\s\S]{0,800}VMCS_GUEST_RSP[\s\S]{0,700}vmlaunch[\s\S]{0,300}add rsp, 200h)");
  CheckPattern(state, "guest launch RSP points at the wrapper return slot",
               asm_source,
                R"(HvLaunchGuest proc[\s\S]{0,1100}add rax, 200h[\s\S]{0,260}VMCS_GUEST_RSP)");
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
  Check(state, "launch snapshot and VMLAUNCH share one IPI callback",
        wrapper_begin != std::string::npos && wrapper_end > wrapper_begin &&
            asm_source.substr(wrapper_begin, wrapper_end - wrapper_begin).find(
                "call PrepareHvCallback") != std::string::npos &&
            asm_source.substr(wrapper_begin, wrapper_end - wrapper_begin).find(
                "call HvLaunchGuest") != std::string::npos &&
            asm_source.find("g_HvLaunchCommit") == std::string::npos);
  const std::size_t start_begin =
      vmm.find("extern \"C\" NTSTATUS StartHypervisor()");
  const std::size_t start_end =
      vmm.find("static bool HasParkedVcpu()", start_begin);
  const std::string launch_start_source =
      start_begin != std::string::npos && start_end > start_begin
          ? vmm.substr(start_begin, start_end - start_begin)
          : std::string{};
  const std::size_t launch_broadcast =
      launch_start_source.find("BroadcastToAllProcessorGroups(EnableHvCallback)");
  Check(state, "startup uses one stateful launch rendezvous",
        launch_broadcast != std::string::npos &&
            launch_start_source.find(
                "BroadcastToAllProcessorGroups(EnableHvCallback)",
                launch_broadcast + 1) == std::string::npos);
  Check(state, "incomplete live XSS fails before VMXON",
        launch_start_source.find("g_HostXssMask & ~g_XsavesMask") !=
                std::string::npos &&
            launch_start_source.find("g_XsaveStateSize == 0") !=
                std::string::npos);
  Check(state, "fault injection stages are compile-time gated",
        vmm.find("enum HvFaultStage") != std::string::npos &&
            vmm.find("HV_TEST_FAIL_CPU") != std::string::npos &&
            vmm.find("HV_TEST_FAIL_STAGE") != std::string::npos);
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
  CheckPattern(state, "teardown restores guest XSS after stopped marker", asm_source,
               R"(vmxoff[\s\S]{0,1200}call MarkCurrentVcpuStopped[\s\S]{0,2100}CTX_GUEST_XSS)");
  CheckPattern(state, "native teardown restores host state before guest mask", asm_source,
               R"(HOST_XCR0_FRAME_SLOT[\s\S]{0,500}xrstors\s+\[r10\][\s\S]{0,260}CTX_GUEST_XCR0[\s\S]{0,120}xsetbv)");
  Check(state, "native teardown keeps guest XSS after guest state",
        asm_source.find("xrstors [r10]") != std::string::npos &&
            asm_source.find("mov rax, [r10 + CTX_GUEST_XSS]") !=
                std::string::npos &&
            asm_source.find("restoreGuestStateDone:") != std::string::npos);
  CheckPattern(state, "VmxOn stop restores host XSS", vmm,
               R"(state\s*==\s*VcpuVmxOn[\s\S]{0,500}WriteMsrSafe\(MSR_IA32_XSS\s*,\s*vcpu->HostXss\))");
  CheckPattern(state, "stop claims ownership with a lifecycle CAS", vmm,
               R"(StopHypervisorInternal\([\s\S]{0,500}InterlockedCompareExchange\(&g_HvLifecycle[\s\S]{0,220}kHvLifecycleStopping)");
  CheckPattern(state, "quarantine is not overwritten by idle cleanup", vmm,
               R"(HasParkedVcpu\(\)[\s\S]{0,300}kHvLifecycleQuarantined[\s\S]{0,120}return)");
  CheckPattern(state, "guest CPUID hides VMX", vmm,
               R"(leaf\s*==\s*1[\s\S]{0,300}regs\[2\]\s*&=\s*~\(1\s*<<\s*5\))");
  CheckPattern(state, "PT gate reads VMX post-VMXON capability", main,
               R"(ptEnumerated[\s\S]{0,500}ReadMsrSafe\(MSR_IA32_VMX_MISC[\s\S]{0,500}VMX_MISC_INTEL_PT)");
  CheckPattern(state, "active PT fails before VMXON", main,
               R"(ptControl[\s\S]{0,180}IA32_RTIT_CTL_TRACEEN[\s\S]{0,160}Intel PT tracing is active)");
  Check(state, "PT enumeration alone does not reject VMX",
        main.find("Intel PT state is not virtualized") == std::string::npos);
  Check(state, "inactive supervisor CET enumeration does not reject VMX",
        main.find("supervisor CET CPUID state is not virtualized") ==
            std::string::npos);
  Check(state, "CPUID-only XSTATE components do not reject XCR0",
        main.find("dynamic XSTATE components are not virtualized") ==
            std::string::npos &&
            main.find("hostXcr0 & ~supportedXcr0") == std::string::npos);
  Check(state, "VMX gate failure is not reported as a BIOS-only failure",
        main.find("VMX capability gate rejected; see the preceding reason") !=
            std::string::npos &&
        main.find("VMX not supported or disabled in BIOS") == std::string::npos);
  CheckPattern(state, "XCR0 must be a CPUID-supported subset", vmm,
               R"(hostXcr0\s*&\s*~supportedXcr0)");
  CheckPattern(state, "active unsupported XSS fails before VMXON", vmm,
               R"(hostXss\s*&\s*~IA32_XSS_HOST_ALLOWED_MASK)");
  CheckPattern(state, "only active FRED is rejected before VMXON", main,
               R"(fredEnumerated\s*&&\s*\(currentCr4\s*&\s*CR4_FRED\)\s*!=\s*0)");
  CheckPattern(state, "FXSAVE gate uses CPUID leaf one FXSR bit", main,
               R"(fxsrEnumerated\s*=\s*\(static_cast<u32>\(cpuInfo\[3\]\)\s*&\s*CPUID_1_EDX_FXSR\)\s*!=\s*0)");
  CheckPattern(state, "FXSAVE gate rejects OSXSAVE state", main,
               R"(fxsrEnumerated[\s\S]{0,220}CR4_OSFXSR[\s\S]{0,160}CR4_OSXSAVE)");
  Check(state, "XSAVE gate requires CPUID and CR4 OSXSAVE",
        main.find("const bool xsaveEnumerated") != std::string::npos &&
            main.find("const bool osxsaveEnabled") != std::string::npos &&
            main.find("const bool cr4OsxsaveEnabled") != std::string::npos &&
            main.find("if (xsaveEnumerated && osxsaveEnabled && "
                      "cr4OsxsaveEnabled)") != std::string::npos);
  CheckPattern(state, "XSAVE feature leaf is gated by CPUID XSAVE", main,
               R"(if\s*\(maxBasicLeaf\s*>=\s*0xD\s*&&\s*xsaveEnumerated\))");
  CheckPattern(state, "each CPU validates the FXSAVE CR4 contract", vmm,
               R"(g_XstateMode\s*==\s*XstateSaveFxsave[\s\S]{0,260}localFxsrEnumerated[\s\S]{0,220}CR4_OSFXSR[\s\S]{0,160}CR4_OSXSAVE)");
  Check(state, "XFD is rejected before VMXON",
        main.find("xfdEnumerated") != std::string::npos &&
            main.find("active XFD state is not virtualized") !=
                std::string::npos);
  CheckPattern(state, "boot FRED check uses CPUID subleaf one", main,
               R"(cpuid7MaxSubleaf\s*=\s*static_cast<u32>\(cpuInfo\[0\]\)[\s\S]{0,500}__cpuidex\(cpuInfo, 7, 1\)[\s\S]{0,180}CPUID_7_1_EAX_FRED)");
  Check(state, "driver contract tag identifies the capability revision",
        main.find("PT-HIDDEN-XSTATE-V5-FRED-SUBLEAF1-CET-HIDDEN") !=
            std::string::npos);
  CheckPattern(state, "CR3 PCID no-flush is accepted", vmm,
               R"(noFlushMask\s*=\s*pcide\s*\?\s*\(1ULL\s*<<\s*63\))");
  CheckPattern(state, "NormalizeCr3 clears the no-flush hint", vmm,
               R"(static __forceinline u64 NormalizeCr3[\s\S]{0,260}value\s*&\s*~\(1ULL\s*<<\s*63\))");
  CheckPattern(state, "CR3 no-flush is normalized before VMCS write", vmm,
               R"(const u64 normalizedCr3\s*=\s*NormalizeCr3\(value,\s*guestCr4\)[\s\S]{0,180}VmWriteChecked\(GUEST_CR3,\s*normalizedCr3\))");
  Check(state, "initial VMCS CR3 is normalized",
        vmm.find("const u64 guestCr3 = NormalizeCr3(__readcr3(), hostCr4);") !=
                std::string::npos &&
            vmm.find("VmWriteChecked(GUEST_CR3, guestCr3)") !=
                std::string::npos);
  Check(state, "guest CR4.CET is contract gated",
        vmm.find("value & CR4_CET") != std::string::npos &&
            vmm.find("!g_CetVmcsEnabled") != std::string::npos);
  CheckPattern(state, "guest CR4.FRED is contract gated", vmm,
               R"(if\s*\(\(value\s*&\s*CR4_FRED\)[\s\S]{0,260}InjectGuestException\(c,\s*13)");
  Check(state, "VMCS CR4 mask traps unsupported CET",
        vmm.find("cr4GuestHostMask") != std::string::npos &&
            vmm.find("g_CetVmcsEnabled") != std::string::npos &&
            vmm.find("CONTROL_CR4_GUEST_HOST_MASK") != std::string::npos);
  const std::size_t cr4_mask_begin = vmm.find("const u64 cr4GuestHostMask");
  const std::size_t cr4_mask_end =
      vmm.find("VmWriteChecked(CONTROL_CR4_GUEST_HOST_MASK", cr4_mask_begin);
  const std::string cr4_mask_source =
      cr4_mask_begin != std::string::npos && cr4_mask_end > cr4_mask_begin
          ? vmm.substr(cr4_mask_begin, cr4_mask_end - cr4_mask_begin)
          : std::string{};
  Check(state, "VMCS CR4 mask traps unsupported FRED",
        cr4_mask_source.find("CR4_OSXSAVE") != std::string::npos &&
            cr4_mask_source.find("CR4_FRED") != std::string::npos);
  Check(state, "VMCS CR4 mask traps unsaved PKRU",
        vmm.find("g_XstateMode == XstateSaveFxsave") != std::string::npos &&
            vmm.find("g_HostXcr0Mask & XCR0_PKRU") != std::string::npos &&
            vmm.find("? CR4_PKE") != std::string::npos);
  CheckPattern(state, "guest CPUID keeps optional capability intersection", vmm,
               R"(leaf\s*==\s*7\s*&&\s*subleaf\s*==\s*0[\s\S]{0,700}g_VmxGuestOptionalProfile[\s\S]{0,180}VmxProfileInvpcid)");
  Check(state, "guest CPUID hides PT capability",
        vmm.find("regs[1] &= ~static_cast<int>(CPUID_7_EBX_INTEL_PT)") !=
            std::string::npos);
  CheckPattern(state, "guest CPUID hides FRED capability", vmm,
               R"(leaf\s*==\s*7\s*&&\s*subleaf\s*==\s*1[\s\S]{0,320}regs\[0\]\s*&=[\s\S]{0,120}CPUID_7_1_EAX_FRED)");
  CheckPattern(state, "guest CPUID hides LKGS with FRED",
               vmm,
               R"(CPUID_7_1_EAX_LKGS)" );
  Check(state, "guest CPUID bounds leaf 7 subleafs",
        vmm.find("bool subleafSupported = true") != std::string::npos &&
            vmm.find("const u32 maxSubleaf") != std::string::npos &&
            vmm.find("subleaf > maxSubleaf") != std::string::npos &&
            vmm.find("RtlZeroMemory(regs, sizeof(regs))") !=
                std::string::npos);
  CheckPattern(state, "guest CPUID hides incomplete CET capability", vmm,
               R"(if\s*\(!kGuestCetStateVirtualized\)\s*\{[\s\S]{0,240}CPUID_7_ECX_CET_SHSTK[\s\S]{0,180}CPUID_7_EDX_CET_IBT)");
  Check(state, "guest XSS contract hides incomplete CET state",
        vmm.find("g_SupportedXssMask = 0") != std::string::npos &&
            vmm.find("const u64 guestXssMask = kGuestCetStateVirtualized") !=
                std::string::npos);
  CheckPattern(state, "guest CPUID hides Intel PT leaf", vmm,
               R"(leaf\s*==\s*0x14[\s\S]{0,160}RtlZeroMemory\(regs, sizeof\(regs\)\))");
  Check(state, "guest CPUID recomputes XSS area size",
        vmm.find("ComputeXsaveAreaSize(") != std::string::npos &&
        vmm.find("guestXsaveSize") != std::string::npos &&
        vmm.find("regs[1] = static_cast<int>(guestXsaveSize)") !=
            std::string::npos);
  Check(state, "guest CPUID constrains D.0 XSAVE sizes",
         vmm.find("ComputeStandardXsaveAreaSize") != std::string::npos &&
         vmm.find("guestCurrentXsaveSize") != std::string::npos &&
             vmm.find("guestMaximumXsaveSize") != std::string::npos &&
             vmm.find("regs[1] = static_cast<int>(guestCurrentXsaveSize)") !=
                 std::string::npos &&
             vmm.find("regs[2] = static_cast<int>(guestMaximumXsaveSize)") !=
                 std::string::npos);
  Check(state, "guest CPUID D.0 separates current and maximum masks",
        vmm.find("guestCurrentXcr0") != std::string::npos &&
            vmm.find("guestSupportedXcr0") != std::string::npos &&
            vmm.find("guestCurrentXsaveSize") != std::string::npos &&
            vmm.find("guestMaximumXsaveSize") != std::string::npos);
  const std::size_t d1_begin = vmm.find("leaf == 0xD && subleaf == 1");
  const std::string d1_source =
      d1_begin != std::string::npos
          ? vmm.substr(d1_begin, 1800)
          : std::string{};
  Check(state, "D.1 reports compacted area only when supported",
        d1_source.find("const bool hostXsavec") != std::string::npos &&
            d1_source.find("const bool compactedSupported") !=
                std::string::npos &&
            d1_source.find("g_XsavesEnabled != 0 || hostXsavec") !=
                std::string::npos &&
            d1_source.find("if (compactedSupported &&") !=
                std::string::npos &&
            d1_source.find("regs[1] = 0") != std::string::npos);
  CheckPattern(state, "guest CPUID hides unsaved MPX and PKU", vmm,
               R"(CPUID_7_EBX_MPX[\s\S]{0,380}XCR0_PKRU[\s\S]{0,380}CPUID_7_ECX_PKU[\s\S]{0,180}CPUID_7_ECX_OSPKE)");
  CheckPattern(state, "guest CR4 PKE requires saved PKRU", vmm,
               R"(CR4_PKE[\s\S]{0,300}XCR0_PKRU[\s\S]{0,300}InjectGuestException\(c, 13)");
  Check(state, "compacted XSAVE validates component ownership",
        vmm.find("const u32 componentFlags") != std::string::npos &&
            vmm.find("const bool xssComponent") != std::string::npos &&
            vmm.find("const bool xcr0Component") != std::string::npos &&
            vmm.find("offset += componentSize") != std::string::npos);
  Check(state, "compacted XSAVE honors ECX bit 1 alignment",
        vmm.find("offset = (offset + 63ULL) & ~63ULL") != std::string::npos);
  Check(state, "active CET state is rejected before VMXON",
        main.find("active user CET state is outside the safe VMX contract") !=
                std::string::npos &&
            main.find("active supervisor CET state is outside the safe VMX contract") !=
                std::string::npos);
  CheckPattern(state, "CET_U requires XSAVES", main,
               R"(CET_U is enabled without an XSAVES CET_U component)");
  CheckPattern(state, "CET_U MSRs are trapped when guest CET is hidden", vmm,
               R"(const bool cetUserStateSupported\s*=\s*kGuestCetStateVirtualized[\s\S]{0,260}if\s*\(!cetUserStateSupported\)[\s\S]{0,220}MSR_IA32_U_CET[\s\S]{0,120}MSR_IA32_PL3_SSP)");
  Check(state, "VMX control capability checks allowed-one bits",
        vmm.find("static __forceinline bool ControlBitCanBeOne") !=
                std::string::npos &&
            vmm.find("(mandatoryOne | allowedOne) & mask") !=
                std::string::npos &&
            vmm.find("VmxControlAllows") != std::string::npos);
  Check(state, "VMX mandatory-one bits use the capability low half",
        vmm.find("static __forceinline u32 ControlMandatoryOn") !=
                std::string::npos &&
            vmm.find("return static_cast<u32>(__readmsr(msr))") !=
                std::string::npos);
  Check(state, "unknown VMX mandatory controls fail closed",
        vmm.find("primaryMandatoryOn & ~VMX_PROCBASED_MANDATORY_ON") !=
                std::string::npos &&
            vmm.find("pinMandatoryOn & ~VMX_PINBASED_MANDATORY_ON") !=
                std::string::npos &&
            vmm.find("exitMandatoryOn & ~VMX_EXIT_MANDATORY_ON") !=
                std::string::npos &&
            vmm.find("entryMandatoryOn & ~VMX_ENTRY_MANDATORY_ON") !=
                std::string::npos);
  const std::size_t supported_primary =
      vmm.find("constexpr u32 supportedPrimary");
  const std::size_t cr3_load =
      vmm.find("CPU_BASED_CR3_LOAD_EXITING", supported_primary);
  const std::size_t cr3_store =
      vmm.find("CPU_BASED_CR3_STORE_EXITING", cr3_load);
  const std::size_t unsupported_primary =
      vmm.find("constexpr u32 unsupportedPrimary", supported_primary);
  const std::size_t unsupported_path =
      vmm.find("unsupported exit path", unsupported_primary);
  const std::string unsupported_primary_source =
      unsupported_primary != std::string::npos &&
              unsupported_path > unsupported_primary
          ? vmm.substr(unsupported_primary,
                       unsupported_path - unsupported_primary)
          : std::string{};
  Check(state, "CR3 load/store exits use the CR-access handler",
        supported_primary != std::string::npos &&
            cr3_load > supported_primary && cr3_store > cr3_load &&
            unsupported_primary > cr3_store &&
            unsupported_path > unsupported_primary &&
            unsupported_primary_source.find("CR3_LOAD") == std::string::npos &&
            unsupported_primary_source.find("CR3_STORE") == std::string::npos);
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
  const bool fxsr = (leaf1[3] & (1 << 24)) != 0;
  const bool xsave = (leaf1[2] & (1 << 26)) != 0;
  const bool osxsave = (leaf1[2] & (1 << 27)) != 0;
  Check(state, "legacy FXSR is enumerated", fxsr);
  if (!fxsr) return;

  if (!xsave || !osxsave || max_basic < 0xd) {
    std::cout << "Hardware: backend=FXSAVE\n";
    return;
  }

  unsigned __int64 xcr0 = _xgetbv(0);
  Check(state, "XCR0 has x87 and SSE enabled", (xcr0 & 3) == 3);

  int d0[4]{};
  __cpuidex(d0, 0xd, 0);
  Check(state, "XSAVE area fits the 4 KiB exit frame",
        static_cast<unsigned>(d0[1]) <= 0x1000);

  int d1[4]{};
  __cpuidex(d1, 0xd, 1);
  const bool xsaves = (d1[0] & (1 << 3)) != 0;
  if (xsaves) {
    Check(state, "XSAVES area fits the 4 KiB exit frame",
          static_cast<unsigned>(d1[1]) <= 0x1000);
  }
  std::cout << "Hardware: XCR0=0x" << std::hex << xcr0
            << " backend=" << (xsaves ? "XSAVES" : "XSAVE")
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
