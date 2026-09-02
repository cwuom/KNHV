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

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <limits>
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

// Keep the MSR bitmap calculation independent from the driver so a policy
// change cannot silently move a bit to the wrong VMX region
struct MsrBitmapModel {
  static constexpr std::size_t kBitmapBytes = 0x1000;
  std::array<std::uint8_t, kBitmapBytes> bytes{};

  static bool Resolve(std::uint32_t msr, bool write,
                      std::size_t& byte_offset, std::uint8_t& bit_mask) {
    std::uint32_t normalized = msr;
    std::uint32_t region = 0;
    if (msr <= 0x1FFFU) {
      region = write ? 0x800U : 0x000U;
    } else if (msr >= 0xC0000000U && msr <= 0xC0001FFFU) {
      region = write ? 0xC00U : 0x400U;
      normalized -= 0xC0000000U;
    } else {
      return false;
    }
    byte_offset = static_cast<std::size_t>(
        region + ((normalized & 0x1FFFU) >> 3));
    bit_mask = static_cast<std::uint8_t>(1U << (normalized & 7U));
    return byte_offset < kBitmapBytes;
  }

  bool Set(std::uint32_t msr, bool write) {
    std::size_t byte_offset = 0;
    std::uint8_t bit_mask = 0;
    if (!Resolve(msr, write, byte_offset, bit_mask)) return false;
    bytes[byte_offset] |= bit_mask;
    return true;
  }

  bool IsSet(std::uint32_t msr, bool write) const {
    std::size_t byte_offset = 0;
    std::uint8_t bit_mask = 0;
    return Resolve(msr, write, byte_offset, bit_mask) &&
           (bytes[byte_offset] & bit_mask) != 0;
  }
};

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
  std::string text{std::istreambuf_iterator<char>(file),
                   std::istreambuf_iterator<char>()};
  // source files may be checked out with CRLF while the contract anchors use
  // LF; normalize only the in-memory copy so order checks stay portable
  for (std::size_t cursor = 0; cursor + 1 < text.size();) {
    if (text[cursor] == '\r' && text[cursor + 1] == '\n') {
      text.erase(cursor, 1);
    } else {
      ++cursor;
    }
  }
  return text;
}

void CheckPattern(TestState& state, std::string_view name,
                  const std::string& text, const char* pattern) {
  try {
    Check(state, name, std::regex_search(text, std::regex(pattern)), pattern);
  } catch (const std::regex_error& error) {
    Check(state, name, false, error.what());
  }
}

std::string SliceSource(const std::string& text, std::string_view begin,
                        std::string_view end) {
  const std::size_t begin_pos = text.find(begin);
  if (begin_pos == std::string::npos) return {};
  const std::size_t content_begin = begin_pos + begin.size();
  const std::size_t end_pos = text.find(end, content_begin);
  if (end_pos == std::string::npos || end_pos <= begin_pos) return {};
  return text.substr(begin_pos, end_pos - begin_pos);
}

bool TokensInOrder(const std::string& text,
                   std::initializer_list<std::string_view> tokens) {
  std::size_t cursor = 0;
  for (const std::string_view token : tokens) {
    const std::size_t position = text.find(token, cursor);
    if (position == std::string::npos) return false;
    cursor = position + token.size();
  }
  return true;
}

bool ContainsAny(const std::string& text,
                 std::initializer_list<std::string_view> tokens) {
  for (const std::string_view token : tokens) {
    if (text.find(token) != std::string::npos) return true;
  }
  return false;
}

std::size_t FirstTokenPosition(const std::string& text,
                               std::initializer_list<std::string_view> tokens) {
  std::size_t first = std::string::npos;
  for (const std::string_view token : tokens) {
    const std::size_t position = text.find(token);
    if (position < first) first = position;
  }
  return first;
}

bool ContainsUtf16Le(const std::string& bytes, std::string_view needle) {
  if (needle.empty() || bytes.size() < needle.size() * 2) return false;
  for (std::size_t offset = 0;
       offset + needle.size() * 2 <= bytes.size(); ++offset) {
    bool match = true;
    for (std::size_t i = 0; i < needle.size(); ++i) {
      if (static_cast<unsigned char>(bytes[offset + i * 2]) !=
              static_cast<unsigned char>(needle[i]) ||
          bytes[offset + i * 2 + 1] != '\0') {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

bool ContainsBytes(const std::string& bytes,
                   std::initializer_list<std::uint8_t> needle) {
  if (needle.empty() || bytes.size() < needle.size()) return false;
  for (std::size_t offset = 0;
       offset + needle.size() <= bytes.size(); ++offset) {
    std::size_t index = 0;
    bool match = true;
    for (const std::uint8_t expected : needle) {
      const auto actual = static_cast<std::uint8_t>(
          static_cast<unsigned char>(bytes[offset + index]));
      if (actual != expected) {
        match = false;
        break;
      }
      ++index;
    }
    if (match) return true;
  }
  return false;
}

std::string ExtractDriverContractTag(const std::string& source) {
  try {
    std::smatch match;
    if (!std::regex_search(
            source, match,
            std::regex(R"REGEX(kDriverContractTag\s*=\s*"([^"]+)")REGEX")) ||
        match.size() < 2) {
      return {};
    }
    return match[1].str();
  } catch (const std::regex_error&) {
    return {};
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
  CheckPattern(state, "unconditional non-root exit reasons", vmx,
               R"(VM_EXIT_REASON_GETSEC\s+11[\s\S]*VM_EXIT_REASON_INVD\s+13[\s\S]*VM_EXIT_REASON_INVEPT\s+50[\s\S]*VM_EXIT_REASON_INVVPID\s+53)");
  CheckPattern(state, "instruction exit reason numbering", vmx,
               R"(VM_EXIT_REASON_RDPMC\s+15[\s\S]*VM_EXIT_REASON_RDTSC\s+16[\s\S]*VM_EXIT_REASON_CR_ACCESS\s+28)");
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
  const std::string fatal_snapshot_layout =
      SliceSource(vmm, "struct HvFatalSnapshot", "struct HvCrashBlob");
  const bool fatal_exit_event_fields =
      TokensInOrder(fatal_snapshot_layout,
                    {"ExitIntrInfo", "ExitIntrError", "IdtVectoringInfo",
                     "IdtVectoringError"});
  const bool fatal_entry_event_fields =
      TokensInOrder(fatal_snapshot_layout,
                    {"EntryIntrInfo", "EntryIntrError",
                     "EntryInstructionLength"}) ||
      TokensInOrder(fatal_snapshot_layout,
                    {"VmEntryIntrInfo", "VmEntryIntrError",
                     "VmEntryInstructionLength"}) ||
      TokensInOrder(fatal_snapshot_layout,
                    {"LastVmEntryIntrInfo", "LastVmEntryIntrError",
                     "LastVmEntryInstructionLength"});
  Check(state, "fatal snapshot retains complete VM-exit event state",
        !fatal_snapshot_layout.empty() && fatal_exit_event_fields &&
            fatal_entry_event_fields);
  const std::string fatal_snapshot_capture = SliceSource(
      vmm, "extern \"C\" void HvCaptureFatalSnapshotPreVmxoff(GuestContext* c)",
      "extern \"C\" __declspec(noreturn) void HvFatalBugCheck");
  Check(state, "pre-VMXOFF snapshot reads all event fields before commit",
        !fatal_snapshot_capture.empty() &&
            TokensInOrder(fatal_snapshot_capture,
                          {"VM_EXIT_INTR_INFO", "VM_EXIT_INTR_ERROR_CODE",
                           "VM_EXIT_IDT_VECTORING_INFO",
                           "VM_EXIT_IDT_VECTORING_ERROR_CODE",
                           "FatalSnapshotCommitState"}) &&
            ContainsAny(fatal_snapshot_capture,
                        {"LastVmEntryIntrInfo", "EntryIntrInfo",
                         "VmEntryIntrInfo"}) &&
            ContainsAny(fatal_snapshot_capture,
                        {"LastVmEntryIntrError", "EntryIntrError",
                         "VmEntryIntrError"}) &&
            ContainsAny(fatal_snapshot_capture,
                        {"LastVmEntryInstructionLength", "EntryInstructionLength",
                         "VmEntryInstructionLength"}));
  Check(state, "crash blob carries a trace tail",
        vmm.find("TraceRecordsPerCpu = HV_TRACE_TAIL_RECORDS") != std::string::npos &&
        vmm.find("snapshotCount * HV_TRACE_TAIL_RECORDS") != std::string::npos &&
            vmm.find("traceTail") != std::string::npos);
  CheckPattern(state, "secondary dump snapshots arbitrary bugchecks", vmm,
               R"(HvSecondaryDumpDataCallback[\s\S]{0,1000}InterlockedCompareExchange\(\s*&g_HvCrashBlobCaptured[\s\S]{0,500}CaptureHvCrashBlob\(dumpData->BugCheckCode)");
  const std::size_t fatal_bugcheck_begin =
      vmm.find("HvFatalBugCheck(GuestContext* c)");
  const std::size_t fatal_bugcheck_end =
      fatal_bugcheck_begin == std::string::npos
          ? std::string::npos
          : vmm.find("static __forceinline u32 CurrentProcessorIndex",
                     fatal_bugcheck_begin);
  const std::string fatal_bugcheck_source =
      fatal_bugcheck_begin != std::string::npos &&
              fatal_bugcheck_end > fatal_bugcheck_begin
          ? vmm.substr(fatal_bugcheck_begin,
                       fatal_bugcheck_end - fatal_bugcheck_begin)
          : std::string{};
  Check(state, "fatal bugcheck defers crash blob capture to callback",
        !fatal_bugcheck_source.empty() &&
            fatal_bugcheck_source.find("CaptureHvCrashBlob") ==
                std::string::npos &&
            fatal_bugcheck_source.find("KeBugCheckEx") != std::string::npos);
  Check(state, "crash blob carries launch hardware boundaries",
        vmm.find("LaunchVmlaunchIssued") != std::string::npos &&
            vmm.find("LaunchGuestStarted") != std::string::npos &&
            vmm.find("LaunchVmExitAsmReached") != std::string::npos &&
            vmm.find("LaunchFirstVmExitEntered") != std::string::npos);
  const std::string crash_blob_copy = SliceSource(
      vmm, "static void CaptureHvCrashBlob(",
      "extern \"C\" VOID HvSecondaryDumpDataCallback");
  Check(state, "crash blob exports complete VM-exit event state",
        !crash_blob_copy.empty() &&
            crash_blob_copy.find("LastVmExitIntrInfo") != std::string::npos &&
            crash_blob_copy.find("LastVmExitIntrError") != std::string::npos &&
            crash_blob_copy.find("LastIdtVectoringInfo") != std::string::npos &&
            crash_blob_copy.find("LastIdtVectoringError") != std::string::npos);
  Check(state, "crash blob exports VM-entry interruption state",
        !crash_blob_copy.empty() &&
            ContainsAny(crash_blob_copy,
                        {"LastVmEntryIntrInfo", "EntryIntrInfo",
                         "VmEntryIntrInfo"}) &&
            ContainsAny(crash_blob_copy,
                        {"LastVmEntryIntrError", "EntryIntrError",
                         "VmEntryIntrError"}) &&
            ContainsAny(crash_blob_copy,
                        {"LastVmEntryInstructionLength", "EntryInstructionLength",
                         "VmEntryInstructionLength"}));
  Check(state, "crash blob carries VMXOFF failure flags",
        vmm.find("kHvCrashBlobVersion = 11") != std::string::npos &&
            vmm.find("VmxOffFailureFlags") != std::string::npos &&
            vmm.find("g_HvVmxOffFailureFlagsAsm") != std::string::npos &&
            vmm.find("InterlockedCompareExchange64") != std::string::npos);
  Check(state, "crash blob preserves the VMCS first-failure tuple",
        !fatal_snapshot_layout.empty() &&
            fatal_snapshot_layout.find("VmcsFailureCommitState") !=
                std::string::npos &&
            fatal_snapshot_layout.find("VmcsFailureReason") !=
                std::string::npos &&
            fatal_snapshot_layout.find("VmcsFailureArg0") !=
                std::string::npos &&
            fatal_snapshot_layout.find("VmcsFailureArg1") !=
                std::string::npos &&
            !crash_blob_copy.empty() &&
            crash_blob_copy.find("ReadVmcsFailureRecord") !=
                std::string::npos &&
            crash_blob_copy.find("out.VmcsFailureCommitState") !=
                std::string::npos &&
            crash_blob_copy.find("out.VmcsFailureReason") !=
                std::string::npos &&
            crash_blob_copy.find("out.VmcsFailureArg0") !=
                std::string::npos &&
            crash_blob_copy.find("out.VmcsFailureArg1") !=
                std::string::npos);
  Check(state, "VMCS failure tuple rejects an in-flight publication",
        vmm.find("ReadVmcsFailureRecord(const VcpuContext*") !=
                std::string::npos &&
            vmm.find("const long finalCommit") != std::string::npos &&
            vmm.find("firstCommit == finalCommit") != std::string::npos &&
            vmm.find("*reason = static_cast<u32>(HvVmcsFailureNone)") !=
                std::string::npos);
  Check(state, "crash blob exports VMCS clear diagnostics",
        !fatal_snapshot_layout.empty() &&
            fatal_snapshot_layout.find("VmcsCurrentState") !=
                std::string::npos &&
            fatal_snapshot_layout.find("VmcsClearFlags") !=
                std::string::npos &&
            !crash_blob_copy.empty() &&
            crash_blob_copy.find("out.VmcsCurrentState") !=
                std::string::npos &&
            crash_blob_copy.find("out.VmcsClearFlags") !=
                std::string::npos);
  Check(state, "crash blob records fatal snapshot commit state",
        !fatal_snapshot_layout.empty() &&
            fatal_snapshot_layout.find("FatalSnapshotCommitState") !=
                std::string::npos &&
            !crash_blob_copy.empty() &&
            crash_blob_copy.find("finalFatalSnapshotCommitState") !=
                std::string::npos &&
            crash_blob_copy.find(
                "fatalSnapshotCommitState != HvFatalSnapshotCommitted") !=
                std::string::npos &&
            crash_blob_copy.find(
                "finalFatalSnapshotCommitState != HvFatalSnapshotCommitted") !=
                std::string::npos &&
            crash_blob_copy.find("out.DiagnosticValidity = 0") !=
                std::string::npos);
  const std::string crash_blob_callback = SliceSource(
      vmm, "extern \"C\" VOID HvSecondaryDumpDataCallback",
      "bool RegisterSecondaryDumpCallback");
  Check(state, "crash blob publishes only after an atomic commit",
        !crash_blob_callback.empty() &&
            crash_blob_callback.find("HvCrashBlobCaptureWriting") !=
                std::string::npos &&
            crash_blob_callback.find("HvCrashBlobCaptureCommitted") !=
                std::string::npos &&
            crash_blob_callback.find("MemoryBarrier()") != std::string::npos);
  Check(state, "fatal snapshot avoids optional PT MSR reads",
        !fatal_snapshot_capture.empty() &&
            fatal_snapshot_capture.find("ReadMsrSafe(MSR_IA32_RTIT_CTL") ==
                std::string::npos &&
            vmm.find("vcpu->LastPtCtl = localPtControl") !=
                std::string::npos);
  const std::string vmcs_clear_source = SliceSource(
      vmm, "extern \"C\" bool HvClearCurrentVmcsAndRecord()",
      "static __forceinline u64 PackSegmentSelectors");
  Check(state, "VMCS clear validates ownership before VMXOFF",
        !vmcs_clear_source.empty() &&
            TokensInOrder(vmcs_clear_source,
                          {"VmcsCurrentStateActive", "HvVmPtrSt",
                           "currentPhys", "HvVmClear",
                           "VmcsCurrentStateNone"}) &&
            vmcs_clear_source.find("VmcsCurrentStateFailed") !=
                std::string::npos);
  Check(state, "VMCS clear failure is a non-returning fail-stop",
        vmm.find("extern \"C\" __declspec(noreturn) void HvFailVmcsClear") !=
                std::string::npos &&
            vmm.find("HvCaptureFatalSnapshotPreVmxoff(nullptr)") !=
                std::string::npos &&
            vmm.find("HvFatalBugCheck(nullptr)") != std::string::npos);
  Check(state, "crash blob rejects an unknown capture state",
        !crash_blob_callback.empty() &&
            crash_blob_callback.find(
                "captureState != HvCrashBlobCaptureCommitted") !=
                std::string::npos &&
            crash_blob_callback.find("dumpData->Context = nullptr") !=
                std::string::npos &&
            crash_blob_callback.find(
                "dumpData->Flags = KB_SECONDARY_DATA_FLAG_NO_DEVICE_ACCESS") !=
                std::string::npos);
  Check(state, "crash blob terminates a zero-sized dump chunk",
        !crash_blob_callback.empty() &&
            crash_blob_callback.find("maxAllowed == 0 && remaining != 0") !=
                std::string::npos &&
            crash_blob_callback.find("Returning ADDITIONAL_DATA with an unchanged context") !=
                std::string::npos);
  Check(state, "crash blob terminates an empty storage callback",
        !crash_blob_callback.empty() &&
            crash_blob_callback.find(
                "!g_HvCrashBlob || g_HvCrashBlobSize == 0") !=
                std::string::npos &&
            crash_blob_callback.find("dumpData->Context = nullptr") !=
                std::string::npos);
  Check(state, "crash blob persists first VM-exit proof",
        !fatal_snapshot_layout.empty() &&
            TokensInOrder(fatal_snapshot_layout,
                          {"FirstExitProbeState",
                           "FirstExitProbeBaselineVmExits",
                           "FirstExitProbeObservedVmExits",
                           "FirstExitProbeResumeFlags"}) &&
            !crash_blob_copy.empty() &&
            crash_blob_copy.find("FirstExitProbeState") !=
                std::string::npos &&
            crash_blob_copy.find("FirstExitProbeResumeFlags") !=
                std::string::npos);

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
  const std::string vmwrite_asm =
      SliceSource(asm_source, "HvVmWrite proc", "HvVmWrite endp");
  CheckPattern(state, "VMWRITE encodes value then field", vmwrite_asm,
               R"(vmwrite rdx, rcx)");
  Check(state, "VMWRITE wrapper does not use the swapped operand order",
        !vmwrite_asm.empty() && vmwrite_asm.find("vmwrite rcx, rdx") ==
                                  std::string::npos);
  const std::string vmwrite_checked_source = SliceSource(
      vmm, "static __forceinline bool VmWriteChecked(",
      "static __forceinline bool VmReadChecked(");
  const std::size_t vmwrite_call =
      vmwrite_checked_source.find("HvVmWrite(field, value)");
  const std::size_t vmwrite_status =
      vmwrite_checked_source.find("const bool success = VmxOk(flags)",
                                  vmwrite_call);
  const std::size_t vmwrite_latch = vmwrite_checked_source.find(
      "InterlockedCompareExchange(&vcpu->VmcsWriteFailed, 1, 0)",
      vmwrite_status);
  const std::size_t vmwrite_error_read = vmwrite_checked_source.find(
      "HvVmReadChecked(VM_INSTRUCTION_ERROR");
  const std::size_t vmwrite_first_field =
      vmwrite_checked_source.find("FirstVmcsWriteField = field");
  const std::size_t vmwrite_first_flags =
      vmwrite_checked_source.find("FirstVmcsWriteFlags = flags");
  const std::size_t vmwrite_first_error =
      vmwrite_checked_source.find("FirstVmcsWriteError = instructionError");
  Check(state, "VMWRITE failures retain first field and VM-instruction error",
        !vmwrite_checked_source.empty() && vmwrite_call != std::string::npos &&
            vmwrite_status > vmwrite_call && vmwrite_latch > vmwrite_status &&
            vmwrite_first_field != std::string::npos &&
            vmwrite_first_flags != std::string::npos &&
            vmwrite_first_error != std::string::npos &&
            vmwrite_error_read != std::string::npos);
  Check(state, "VMWRITE reads instruction error only on VMfailValid",
        vmwrite_error_read != std::string::npos &&
            vmwrite_checked_source.find("flags & (1ULL << 6)",
                                       vmwrite_status) < vmwrite_error_read &&
            (vmwrite_checked_source.find("if (vcpu->VmcsWriteFailed != 0)") !=
                 std::string::npos ||
             vmwrite_checked_source.find(
                 "InterlockedCompareExchange(&vcpu->VmcsWriteFailed, 0, 0)") !=
                 std::string::npos));
  const bool write_diagnostic_before_latch =
      vmwrite_first_field != std::string::npos &&
      vmwrite_first_flags != std::string::npos &&
      vmwrite_first_error != std::string::npos &&
      vmwrite_latch != std::string::npos &&
      vmwrite_first_field < vmwrite_latch &&
      vmwrite_first_flags < vmwrite_latch &&
      vmwrite_first_error < vmwrite_latch;
  const bool write_failure_state_machine =
      vmwrite_checked_source.find("VmcsWriteState") != std::string::npos &&
      vmwrite_checked_source.find("MemoryBarrier") != std::string::npos;
  Check(state, "VMWRITE failure diagnostics publish atomically",
        write_diagnostic_before_latch || write_failure_state_machine);
  const std::string vmread_checked_source = SliceSource(
      vmm, "static __forceinline bool VmReadChecked(",
      "static __forceinline bool VmcsValueMatches(");
  Check(state, "VMREAD failures retain the VM-instruction error",
        !vmread_checked_source.empty() &&
            vmread_checked_source.find("VmcsReadState") != std::string::npos &&
            vmread_checked_source.find("VM_INSTRUCTION_ERROR") !=
                std::string::npos &&
            vmread_checked_source.find("FirstVmcsReadError = instructionError") !=
                std::string::npos &&
            vmread_checked_source.find("MemoryBarrier()") != std::string::npos);
  Check(state, "VMCS readback mismatches are recorded separately",
        vmm.find("static __forceinline bool VmcsValueMatches(") !=
                std::string::npos &&
            vmm.find("FirstVmcsMismatchField") != std::string::npos &&
            vmm.find("FirstVmcsMismatchExpected") != std::string::npos &&
            vmm.find("FirstVmcsMismatchActual") != std::string::npos &&
            vmm.find("FirstVmcsMismatchMask") != std::string::npos &&
            vmm.find("VmcsValueMismatch") != std::string::npos);
  const std::size_t setup_readback_compare =
      vmm.find("if (success) {\n        // a successful VMREAD", vmm.find("bool SetupVmcs("));
  Check(state, "VMCS readback compares launch-critical fields",
        setup_readback_compare != std::string::npos &&
            vmm.find("HOST_RIP", setup_readback_compare) != std::string::npos &&
            vmm.find("GUEST_RIP", setup_readback_compare) != std::string::npos &&
            vmm.find("CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS",
                     setup_readback_compare) != std::string::npos &&
            vmm.find("CONTROL_MSR_BITMAP_ADDRESS", setup_readback_compare) !=
                std::string::npos &&
            vmm.find("CONTROL_CR4_READ_SHADOW", setup_readback_compare) !=
                std::string::npos);
  Check(state, "VMCS readback uses field-width masks",
        vmm.find("0xFFFFULL", setup_readback_compare) != std::string::npos &&
            vmm.find("0xFFFFFFFFULL", setup_readback_compare) !=
                std::string::npos &&
            vmm.find("~0ULL", setup_readback_compare) != std::string::npos);
  const std::string vmcs_setup_source = SliceSource(
      vmm, "bool SetupVmcs(",
      "// ==============================================================================\n// Launch Logic");
  const std::size_t vmcs_readback_begin = vmcs_setup_source.find(
      "if (success) {\n        // a successful VMREAD");
  const std::string vmcs_readback_source =
      vmcs_readback_begin == std::string::npos
          ? std::string{}
          : vmcs_setup_source.substr(vmcs_readback_begin);
  Check(state, "VMCS readback reads host SYSENTER fields",
        !vmcs_setup_source.empty() &&
            TokensInOrder(vmcs_setup_source,
                          {"VmReadChecked(HOST_IA32_SYSENTER_CS, &vmcsHostSysenterCs)",
                           "VmReadChecked(HOST_IA32_SYSENTER_ESP, &vmcsHostSysenterEsp)",
                           "VmReadChecked(HOST_IA32_SYSENTER_EIP, &vmcsHostSysenterEip)"}));
  Check(state, "VMCS readback reads guest SYSENTER and DEBUGCTL",
        !vmcs_setup_source.empty() &&
            TokensInOrder(vmcs_setup_source,
                          {"VmReadChecked(GUEST_SYSENTER_CS, &vmcsGuestSysenterCs)",
                           "VmReadChecked(GUEST_SYSENTER_ESP, &vmcsGuestSysenterEsp)",
                           "VmReadChecked(GUEST_SYSENTER_EIP, &vmcsGuestSysenterEip)",
                           "VmReadChecked(GUEST_DEBUGCTL, &vmcsGuestDebugctl)"}));
  CheckPattern(
      state, "VMCS readback compares host SYSENTER values with widths",
      vmcs_readback_source,
      R"(VmcsValueMatches\([\s\S]{0,180}HOST_IA32_SYSENTER_CS[\s\S]{0,120}vmcsHostSysenterCs[\s\S]{0,120}sysenterCs[\s\S]{0,80}0xFFFFFFFFULL[\s\S]{0,260}VmcsValueMatches\([\s\S]{0,180}HOST_IA32_SYSENTER_ESP[\s\S]{0,120}vmcsHostSysenterEsp[\s\S]{0,120}sysenterEsp[\s\S]{0,80}~0ULL[\s\S]{0,260}VmcsValueMatches\([\s\S]{0,180}HOST_IA32_SYSENTER_EIP[\s\S]{0,120}vmcsHostSysenterEip[\s\S]{0,120}sysenterEip[\s\S]{0,80}~0ULL)");
  CheckPattern(
      state, "VMCS readback compares guest SYSENTER and DEBUGCTL",
      vmcs_readback_source,
      R"(VmcsValueMatches\([\s\S]{0,180}GUEST_SYSENTER_CS[\s\S]{0,120}vmcsGuestSysenterCs[\s\S]{0,120}sysenterCs[\s\S]{0,80}0xFFFFFFFFULL[\s\S]{0,260}VmcsValueMatches\([\s\S]{0,180}GUEST_SYSENTER_ESP[\s\S]{0,120}vmcsGuestSysenterEsp[\s\S]{0,120}sysenterEsp[\s\S]{0,80}~0ULL[\s\S]{0,260}VmcsValueMatches\([\s\S]{0,180}GUEST_SYSENTER_EIP[\s\S]{0,120}vmcsGuestSysenterEip[\s\S]{0,120}sysenterEip[\s\S]{0,80}~0ULL[\s\S]{0,260}VmcsValueMatches\([\s\S]{0,180}GUEST_DEBUGCTL[\s\S]{0,120}vmcsGuestDebugctl[\s\S]{0,120}Vcpu->GuestDebugctl[\s\S]{0,80}~0ULL)");
  Check(state, "VMCS setup writes the guest RSP",
        vmm.find("VmWriteChecked(GUEST_RSP, reinterpret_cast<u64>(GuestSp))") !=
            std::string::npos);
  Check(state, "VMCS setup writes the guest RIP",
        vmm.find("VmWriteChecked(GUEST_RIP, reinterpret_cast<u64>(GuestIp))") !=
            std::string::npos);
  Check(state, "guest entry stack follows the VMX canonical rule",
        vmm.find("VMX requires canonical guest pointers") !=
                std::string::npos &&
            vmm.find("IsCanonical(reinterpret_cast<u64>(GuestSp))") !=
                std::string::npos &&
            vmm.find("(reinterpret_cast<u64>(GuestSp) & 0xFULL)") ==
                std::string::npos);
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
  Check(state, "VMCS always masks guest OSXSAVE",
        vmm.find("GetCr4GuestHostMask") != std::string::npos &&
            vmm.find("CR4_OSXSAVE") != std::string::npos &&
            vmm.find("cr4ReadShadow = guestCr4 & cr4GuestHostMask") !=
                std::string::npos);
  CheckPattern(state, "guest debug VMREAD failures halt",
               asm_source,
               R"(VMCS_GUEST_DR7[\s\S]{0,240}test dl, 041h[\s\S]{0,360}VMCS_GUEST_DEBUGCTL[\s\S]{0,240}test dl, 041h[\s\S]{0,260}CTX_HALT_VM)");
  CheckPattern(state, "VM-exit uses XSAVES", asm_source,
               R"(\bxsaves64\s+\[rsp\])");
  CheckPattern(state, "VM-exit uses XRSTORS", asm_source,
               R"(\bxrstors64\s+\[rsp\])");
  Check(state, "MASM uses explicit 64-bit XSAVE forms",
        asm_source.find("    xsaves [") == std::string::npos &&
            asm_source.find("    xsave [") == std::string::npos &&
            asm_source.find("    xrstors [") == std::string::npos &&
            asm_source.find("    xrstor [") == std::string::npos);
  CheckPattern(state, "XSAVES uses immutable XSS mask", asm_source,
               R"(mov r15, qword ptr \[g_XsavesMask\][\s\S]{0,500}xsaves64\s+\[rsp\])");
  CheckPattern(state, "XSAVES uses the host XCR0 mask", asm_source,
               R"(HOST_XCR0_FRAME_SLOT[\s\S]{0,700}xsaves64\s+\[rsp\])");
  CheckPattern(state, "XRSTORS restores guest XSS after fixed mask", asm_source,
               R"(xrstors64\s+\[rsp\][\s\S]{0,240}CTX_GUEST_XSS[\s\S]{0,160}wrmsr)");
  CheckPattern(state, "XRSTORS restores host state before guest XCR0", asm_source,
               R"(HOST_XCR0_FRAME_SLOT[\s\S]{0,500}xrstors64\s+\[rsp\][\s\S]{0,260}CTX_GUEST_XCR0[\s\S]{0,120}xsetbv)");
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
  CheckPattern(state, "fatal path records snapshot and parked boundaries",
               asm_source,
               R"(vmxHalt:[\s\S]{0,2200}call HvCaptureFatalSnapshotPreVmxoff[\s\S]{0,300}HV_TRACE_FATAL_SNAPSHOT_COMPLETE[\s\S]{0,500}call MarkCurrentVcpuParked[\s\S]{0,300}HV_TRACE_FATAL_PARKED)");
  CheckPattern(state, "invalid restore records snapshot and parked boundaries",
                asm_source,
                R"(restoreInvalid:[\s\S]{0,2200}call HvCaptureFatalSnapshotPreVmxoff[\s\S]{0,300}HV_TRACE_FATAL_SNAPSHOT_COMPLETE[\s\S]{0,500}call MarkCurrentVcpuParked[\s\S]{0,300}HV_TRACE_FATAL_PARKED)");
  CheckPattern(state, "fatal path clears current VMCS before VMXOFF",
               asm_source,
               R"(vmxHalt:[\s\S]{0,2600}call HvClearCurrentVmcsAndRecord[\s\S]{0,120}test al, al[\s\S]{0,120}jz vmxHaltVmclearFailed[\s\S]{0,120}vmxoff)");
  CheckPattern(state, "native teardown clears current VMCS before VMXOFF",
               asm_source,
               R"(HvRestoreStateAndReturn proc[\s\S]{0,12000}call HvClearCurrentVmcsAndRecord[\s\S]{0,120}test al, al[\s\S]{0,120}jz teardownVmclearFailed[\s\S]{0,120}vmxoff)");
  CheckPattern(state, "invalid restore clears current VMCS before VMXOFF",
               asm_source,
               R"(restoreInvalid:[\s\S]{0,2600}call HvClearCurrentVmcsAndRecord[\s\S]{0,120}test al, al[\s\S]{0,120}jz restoreInvalidVmclearFailed[\s\S]{0,120}vmxoff)");
  CheckPattern(state, "VMCS clear failure skips VMXOFF",
               asm_source,
               R"(teardownVmclearFailed:[\s\S]{0,180}call HvFailVmcsClear[\s\S]{0,120}jmp teardownVmxoffFailedLoop)");
  CheckPattern(state, "invalid restore reloads context after trace",
               asm_source,
               R"(restoreInvalid:[\s\S]{0,1500}call HvTraceCurrentVcpuEvent[\s\S]{0,360}mov r10, rbx[\s\S]{0,120}mov rcx, r10[\s\S]{0,220}call HvCaptureFatalSnapshotPreVmxoff)");
  const std::size_t guest_commit_begin =
      asm_source.find("vmxGuestStateCommit:");
  const std::size_t guest_commit_end =
      asm_source.find("vmresume", guest_commit_begin);
  const std::string guest_commit_source =
      guest_commit_begin != std::string::npos &&
              guest_commit_end > guest_commit_begin
          ? asm_source.substr(guest_commit_begin,
                              guest_commit_end - guest_commit_begin)
          : std::string{};
  Check(state, "guest restore commit tail has no calls",
        !guest_commit_source.empty() &&
            guest_commit_source.find("call ") == std::string::npos);
  const std::size_t pre_vmresume_trace =
      guest_commit_begin == std::string::npos
          ? std::string::npos
          : asm_source.rfind("HV_TRACE_PRE_VMRESUME", guest_commit_begin);
  const std::string pre_vmresume_source =
      pre_vmresume_trace != std::string::npos &&
              guest_commit_begin > pre_vmresume_trace
          ? asm_source.substr(pre_vmresume_trace,
                              guest_commit_begin - pre_vmresume_trace)
          : std::string{};
  Check(state, "pre-VMRESUME trace precedes guest restore commit",
        !pre_vmresume_source.empty() &&
            pre_vmresume_source.find("call HvTraceCurrentVcpuEvent") !=
                std::string::npos);
  CheckPattern(state, "fatal VMXOFF failure skips VMXE clear",
               asm_source,
               R"(vmxHalt:[\s\S]{0,3000}vmxoff\s+jc vmxHaltVmxoffFailed\s+jz vmxHaltVmxoffFailed)");
  CheckPattern(state, "native teardown VMXOFF failure is fail-stop",
               asm_source,
               R"(vmxoff\s+jc teardownVmxoffFailed\s+jz teardownVmxoffFailed[\s\S]{0,5000}teardownVmxoffFailed:[\s\S]{0,1200}call HvCaptureFatalSnapshotPreVmxoff[\s\S]{0,1200}call HvFatalBugCheck)");
  CheckPattern(state, "invalid restore VMXOFF failure skips VMXE clear",
               asm_source,
               R"(restoreInvalid:[\s\S]{0,3400}vmxoff\s+jc restoreInvalidVmxoffFailed\s+jz restoreInvalidVmxoffFailed)");
  const std::size_t vmxoff_wrapper_begin = asm_source.find("HvVmxOff proc");
  const std::size_t vmxoff_wrapper_end =
      asm_source.find("HvVmxOff endp", vmxoff_wrapper_begin);
  const std::string vmxoff_wrapper_source =
      vmxoff_wrapper_begin != std::string::npos &&
              vmxoff_wrapper_end > vmxoff_wrapper_begin
          ? asm_source.substr(vmxoff_wrapper_begin,
                              vmxoff_wrapper_end - vmxoff_wrapper_begin)
          : std::string{};
  CheckPattern(state, "HvVmxOff checks both VMX failure flags",
               vmxoff_wrapper_source,
               R"(vmxoff[\s\S]{0,260}pushfq[\s\S]{0,160}pop rax[\s\S]{0,420}jc hvVmxOffFailed[\s\S]{0,180}jz hvVmxOffFailed)");
  CheckPattern(state, "HvVmxOff failure is a non-returning fail-stop",
               vmxoff_wrapper_source,
               R"(hvVmxOffFailed:[\s\S]{0,1000}call HvCaptureFatalSnapshotPreVmxoff[\s\S]{0,1000}call MarkCurrentVcpuParked[\s\S]{0,1000}call HvFatalBugCheck[\s\S]{0,420}hvVmxOffFailedLoop:[\s\S]{0,160}hlt)");
  Check(state, "HvVmxOff failure records first flags atomically",
        asm_source.find("g_HvVmxOffFailureFlagsAsm dq 0") !=
                std::string::npos &&
            vmxoff_wrapper_source.find("lock cmpxchg qword ptr [g_HvVmxOffFailureFlagsAsm]") !=
                std::string::npos &&
            vmxoff_wrapper_source.find("bts rdx, 3Fh") != std::string::npos);
  CheckPattern(state, "vmxHalt direct VMXOFF records failure flags",
               asm_source,
               R"(vmxoff[\s\S]{0,80}jc vmxHaltVmxoffFailed[\s\S]{0,80}jz vmxHaltVmxoffFailed[\s\S]{0,900}vmxHaltVmxoffFailed:[\s\S]{0,220}pushfq[\s\S]{0,120}lock cmpxchg qword ptr \[g_HvVmxOffFailureFlagsAsm\])");
  CheckPattern(state, "teardown direct VMXOFF records failure flags",
               asm_source,
               R"(teardownVmxoffFailed:[\s\S]{0,620}pushfq[\s\S]{0,160}lock cmpxchg qword ptr \[g_HvVmxOffFailureFlagsAsm\])");
  CheckPattern(state, "invalid restore direct VMXOFF records failure flags",
               asm_source,
               R"(restoreInvalidVmxoffFailed:[\s\S]{0,220}pushfq[\s\S]{0,120}lock cmpxchg qword ptr \[g_HvVmxOffFailureFlagsAsm\])");
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
  const std::size_t teardown_begin =
      asm_source.find("HvRestoreStateAndReturn proc");
  const std::size_t teardown_end =
      asm_source.find("HvRestoreStateAndReturn endp", teardown_begin);
  const std::string teardown_source =
      teardown_begin != std::string::npos && teardown_end > teardown_begin
          ? asm_source.substr(teardown_begin, teardown_end - teardown_begin)
          : std::string{};
  const std::size_t teardown_failure_path =
      teardown_source.find("teardownVmxoffFailed:");
  const std::string normal_teardown_source =
      teardown_failure_path != std::string::npos
          ? teardown_source.substr(0, teardown_failure_path)
          : teardown_source;
  const std::size_t stopped_marker_call =
      normal_teardown_source.find("call MarkCurrentVcpuStopped");
  Check(state, "native teardown leaves stopped publication to the stop callback",
        !normal_teardown_source.empty() && stopped_marker_call == std::string::npos);
  const std::size_t ring0_begin = teardown_source.find("restoreRing0:");
  const std::size_t frame_ready =
      ring0_begin == std::string::npos
          ? std::string::npos
          : teardown_source.find("restoreFrameReady:", ring0_begin);
  const std::size_t spill_validation =
      ring0_begin == std::string::npos
          ? std::string::npos
          : teardown_source.find("restoreSpillCanonicalCompare:", ring0_begin);
  const std::size_t first_frame_store =
      ring0_begin == std::string::npos
          ? std::string::npos
          : teardown_source.find("mov [r8 + 00h], r14", ring0_begin);
  CheckPattern(state, "ring-0 native restore uses a three-slot IRETQ frame",
               teardown_source,
               R"(restoreRing0:[\s\S]{0,260}lea r8, \[r11 - 18h\][\s\S]{0,120}lea r9, \[r8 - 100h\])");
  Check(state, "derived IRETQ addresses are validated before frame stores",
        ring0_begin != std::string::npos && frame_ready != std::string::npos &&
            spill_validation != std::string::npos &&
            first_frame_store != std::string::npos &&
            spill_validation < first_frame_store &&
            first_frame_store > frame_ready);
  CheckPattern(state, "ring-0 IRETQ writes exactly three frame slots after validation",
               teardown_source,
               R"(restoreFrameReady:[\s\S]{0,180}mov \[r8 \+ 00h\], r14[\s\S]{0,80}mov \[r8 \+ 08h\], r12[\s\S]{0,80}mov \[r8 \+ 10h\], r15[\s\S]{0,100}mov rax, \[r10 \+ CTX_RAX\])");
  const std::size_t iret_frame_start =
      teardown_source.find("restoreFrameReady:");
  const std::size_t iretq_instruction =
      teardown_source.find("iretq", iret_frame_start);
  const std::size_t outer_rsp_store =
      iret_frame_start == std::string::npos
          ? std::string::npos
          : teardown_source.find("mov [r8 + 18h]", iret_frame_start);
  const std::size_t outer_ss_store =
      iret_frame_start == std::string::npos
          ? std::string::npos
          : teardown_source.find("mov [r8 + 20h]", iret_frame_start);
  Check(state, "ring-0 IRETQ does not write outer-privilege slots",
        iret_frame_start != std::string::npos &&
            iretq_instruction > iret_frame_start &&
            (outer_rsp_store == std::string::npos ||
             outer_rsp_store > iretq_instruction) &&
            (outer_ss_store == std::string::npos ||
             outer_ss_store > iretq_instruction));
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
  const std::string tearing_down_source = SliceSource(
      vmm, "extern \"C\" bool MarkCurrentVcpuTearingDown()",
      "extern \"C\" void MarkCurrentVcpuStopped()");
  const std::string stopped_source = SliceSource(
      vmm, "extern \"C\" void MarkCurrentVcpuStopped()",
      "// ==============================================================================\n// Helper Functions");
  Check(state, "native teardown has an atomic intermediate lifecycle state",
        !tearing_down_source.empty() &&
            tearing_down_source.find("VcpuTearingDown") != std::string::npos &&
            tearing_down_source.find("InterlockedCompareExchange(&vcpu->State") !=
                std::string::npos &&
            tearing_down_source.find("LaunchStageTeardown") !=
                std::string::npos &&
            (ContainsAny(tearing_down_source,
                         {"state == VcpuTearingDown",
                          "currentState == VcpuTearingDown",
                          "previous == VcpuTearingDown"}) ||
             std::regex_search(
                 tearing_down_source,
                 std::regex(R"(InterlockedCompareExchange\(\s*&vcpu->State[\s\S]{0,120}!=\s*VcpuTearingDown)"))) &&
            tearing_down_source.find("const long state = vcpu->State") ==
                std::string::npos &&
            tearing_down_source.find("InterlockedExchange(&vcpu->State, VcpuTearingDown)") ==
                std::string::npos);
  Check(state, "stopped state requires teardown quiescence and ownership CAS",
        !stopped_source.empty() &&
            stopped_source.find("TeardownQuiesced") != std::string::npos &&
            stopped_source.find("InterlockedCompareExchange(&vcpu->State") !=
                std::string::npos &&
            stopped_source.find("VcpuTearingDown") != std::string::npos &&
            stopped_source.find("VcpuStopped") != std::string::npos &&
            ContainsAny(stopped_source,
                        {"TeardownQuiesced == 0",
                         "InterlockedCompareExchange(&vcpu->TeardownQuiesced"}) &&
            stopped_source.find("const long state = vcpu->State") ==
                std::string::npos &&
            stopped_source.find("state == VcpuLaunched") == std::string::npos &&
            stopped_source.find("state == VcpuVmxOn") == std::string::npos);
  const std::string launch_lifecycle_enum = SliceSource(
      vmm, "enum LaunchLifecycleStage : long", "};");
  Check(state, "launch lifecycle names the handoff and guest-active stages",
        !launch_lifecycle_enum.empty() &&
            launch_lifecycle_enum.find("LaunchStageHandoff = 5") !=
                std::string::npos &&
            launch_lifecycle_enum.find("LaunchStageGuestActive = 10") !=
                std::string::npos &&
            launch_lifecycle_enum.find("LaunchStageTeardown = 8") !=
                std::string::npos &&
            launch_lifecycle_enum.find("LaunchStageStopped = 9") !=
                std::string::npos);
  const std::string running_marker_source = SliceSource(
      vmm, "extern \"C\" void MarkCurrentVcpuRunning()",
      "extern \"C\" void MarkCurrentVcpuParked()");
  const std::size_t running_stage_cas = running_marker_source.find(
      "InterlockedCompareExchange(&vcpu->LaunchStage");
  const bool running_stage_cas_present =
      running_stage_cas != std::string::npos ||
      std::regex_search(
          running_marker_source,
          std::regex(R"(InterlockedCompareExchange\(\s*&vcpu->LaunchStage)"));
  const std::size_t running_state_check =
      running_marker_source.find("VcpuLaunched");
  const bool running_void_return =
      running_marker_source.find("return;") != std::string::npos;
  const bool running_bool_return =
      running_marker_source.find("return false") != std::string::npos &&
      running_marker_source.find("return true") != std::string::npos;
  Check(state, "guest-active marker claims the handoff exactly once",
        !running_marker_source.empty() &&
            running_stage_cas_present &&
            running_marker_source.find("LaunchStageGuestActive") !=
                std::string::npos &&
            running_marker_source.find("LaunchStageHandoff") !=
                std::string::npos &&
            running_state_check != std::string::npos &&
            (running_void_return || running_bool_return) &&
            running_marker_source.find(
                "InterlockedExchange(&vcpu->LaunchStage") ==
                std::string::npos);
  const std::string stop_callback_source = SliceSource(
      vmm, "ULONG_PTR StopHvCallback(ULONG_PTR Context)",
      "// ==============================================================================\n// Public API");
  const std::size_t stop_first_vmx_call =
      stop_callback_source.find("HvCall(");
  const std::size_t stop_second_vmx_call =
      stop_callback_source.find("HvVmxOff(");
  const std::size_t stop_stage_cas =
      stop_callback_source.find("InterlockedCompareExchange(&vcpu->LaunchStage");
  const std::size_t stop_owner_cas =
      stop_callback_source.find("InterlockedCompareExchange(&vcpu->State");
  const bool stop_vmx_claimed_before_call =
      stop_stage_cas != std::string::npos && stop_owner_cas != std::string::npos &&
      ((stop_first_vmx_call == std::string::npos ||
        stop_owner_cas < stop_first_vmx_call) &&
       (stop_second_vmx_call == std::string::npos ||
        stop_owner_cas < stop_second_vmx_call));
  Check(state, "stop callback leaves a tearing down CPU alone",
        !stop_callback_source.empty() &&
            stop_callback_source.find("VcpuTearingDown") != std::string::npos &&
            stop_callback_source.find("return 0") != std::string::npos);
  Check(state, "stop callback claims VMX ownership before VMX instructions",
        stop_vmx_claimed_before_call &&
            stop_callback_source.find("LaunchStage") != std::string::npos &&
            stop_callback_source.find("VcpuTearingDown") != std::string::npos);
  const std::size_t stop_magic_call =
      stop_callback_source.find("HYPERVISOR_MAGIC", stop_first_vmx_call);
  const std::size_t stop_unload_call =
      stop_callback_source.find("VMCALL_UNLOAD", stop_magic_call);
  Check(state, "stop callback issues the authenticated unload VMCALL",
        stop_first_vmx_call != std::string::npos &&
            stop_magic_call > stop_first_vmx_call &&
            stop_unload_call > stop_magic_call &&
            stop_owner_cas < stop_first_vmx_call &&
            stop_stage_cas < stop_first_vmx_call);
  const std::size_t stop_stage_guard =
      stop_callback_source.find("LaunchStageGuestActive");
  const std::size_t stop_handoff_guard =
      stop_callback_source.find("LaunchStageHandoff");
  const bool stop_requires_guest_active =
      stop_callback_source.find("stage != LaunchStageGuestActive") !=
          std::string::npos ||
      stop_callback_source.find("launchStage != LaunchStageGuestActive") !=
          std::string::npos ||
      stop_callback_source.find("stage == LaunchStageHandoff") !=
          std::string::npos;
  const bool stop_requires_launched_state =
      stop_callback_source.find("state != VcpuLaunched") !=
          std::string::npos ||
      stop_callback_source.find("state == VcpuLaunched") !=
          std::string::npos;
  Check(state, "stop callback refuses the pre-VMLAUNCH handoff stage",
        stop_stage_guard != std::string::npos &&
            stop_handoff_guard != std::string::npos &&
            stop_requires_guest_active && stop_requires_launched_state &&
            (stop_first_vmx_call == std::string::npos ||
             (stop_stage_guard < stop_first_vmx_call &&
              stop_handoff_guard < stop_first_vmx_call)));
  const std::size_t stop_stage_teardown =
      stop_callback_source.find("LaunchStageTeardown");
  Check(state, "stop callback transitions only an active launched CPU",
        stop_stage_teardown != std::string::npos &&
            stop_stage_cas != std::string::npos &&
            stop_stage_cas < stop_first_vmx_call &&
            stop_callback_source.find("LaunchStageGuestActive",
                                     stop_stage_cas) != std::string::npos &&
            stop_callback_source.find("VcpuLaunched", stop_stage_cas) !=
                std::string::npos);
  const std::size_t stop_quiesced =
      stop_callback_source.find("InterlockedExchange(&vcpu->TeardownQuiesced");
  const std::size_t stop_stopped_cas =
      stop_callback_source.find("InterlockedCompareExchange(&vcpu->State",
                                  stop_quiesced);
  Check(state, "stop callback publishes stopped only after quiescence",
        stop_quiesced != std::string::npos &&
            stop_stopped_cas != std::string::npos &&
            stop_stopped_cas > stop_quiesced &&
            stop_callback_source.find("InterlockedExchange(&vcpu->State, VcpuStopped)") ==
                std::string::npos);
  const std::string live_scan_source = SliceSource(
      vmm, "static bool HasLiveVcpu()", "// A failed launch can still leave VMX active");
  const std::string unresolved_scan_source = SliceSource(
      vmm, "static bool HasUnresolvedVcpu()",
      "static void PinImageForParkedCpu()");
  Check(state, "lifecycle scans use atomic state snapshots",
        !live_scan_source.empty() && !unresolved_scan_source.empty() &&
            live_scan_source.find("InterlockedCompareExchange") != std::string::npos &&
            unresolved_scan_source.find("InterlockedCompareExchange") != std::string::npos &&
            live_scan_source.find("g_VcpuData[i].State ==") == std::string::npos &&
            unresolved_scan_source.find("const long state = g_VcpuData[i].State") ==
                std::string::npos);
  const std::string teardown_request_source = SliceSource(
      vmm, "static __forceinline void RequestAuthenticatedUnload(",
      "extern \"C\" ULONG HandleVmResumeFailure");
  const std::string vmcall_handler_source = SliceSource(
      vmm, "bool HandleVmCall(GuestContext* Ctx) {",
      "bool HandleMsrRead(GuestContext* Ctx) {");
  const std::size_t teardown_authorize =
      teardown_request_source.find("AbortVm = 1");
  const std::size_t teardown_halt_clear =
      teardown_request_source.find("HaltVm = 0", teardown_authorize);
  const std::size_t vmcall_privilege_guard =
      vmcall_handler_source.find("(Ctx->GuestCs & 3U) == 0");
  const std::size_t vmcall_magic_check =
      vmcall_handler_source.find("Ctx->Rcx == HYPERVISOR_MAGIC",
                                 vmcall_privilege_guard);
  const std::size_t vmcall_authorize =
      vmcall_handler_source.find("RequestAuthenticatedUnload",
                                 vmcall_magic_check);
  const std::size_t vmcall_result =
      vmcall_handler_source.find("return Ctx->AbortVm", vmcall_authorize);
  const std::size_t first_abort_enable = vmm.find("AbortVm = 1");
  const std::size_t second_abort_enable =
      first_abort_enable == std::string::npos
          ? std::string::npos
          : vmm.find("AbortVm = 1", first_abort_enable + 1);
  const std::size_t teardown_call =
      teardown_source.find("call MarkCurrentVcpuTearingDown");
  const std::size_t second_teardown_call =
      teardown_call == std::string::npos
          ? std::string::npos
          : teardown_source.find("call MarkCurrentVcpuTearingDown",
                                 teardown_call + 1);
  Check(state, "TeardownRequest has one authenticated authorization",
        !teardown_request_source.empty() && teardown_authorize != std::string::npos &&
            teardown_halt_clear > teardown_authorize &&
            second_abort_enable == std::string::npos &&
            vmcall_privilege_guard != std::string::npos &&
            vmcall_magic_check > vmcall_privilege_guard &&
            vmcall_authorize > vmcall_magic_check &&
            vmcall_result > vmcall_authorize &&
            first_abort_enable != std::string::npos &&
            (teardown_request_source.find("c->AbortVm = 1") !=
                 std::string::npos ||
             teardown_request_source.find("Ctx->AbortVm = 1") !=
                 std::string::npos) &&
            teardown_call != std::string::npos &&
            second_teardown_call == std::string::npos);
  const std::string abort_owner_source = SliceSource(
      vmm, "extern \"C\" void AbortHvLaunch(u64 Rflags) {",
      "// ==============================================================================\n// Stop Logic");
  std::smatch abort_stage_match;
  const bool abort_stage_cas = std::regex_search(
      abort_owner_source, abort_stage_match,
      std::regex(R"(InterlockedCompareExchange\(\s*&vcpu->LaunchStage\s*,\s*(?:LaunchStageAbort|6)\s*,)"));
  const std::size_t abort_stage_owner =
      abort_stage_cas
          ? static_cast<std::size_t>(abort_stage_match.position(0))
          : std::string::npos;
  const std::size_t abort_state_owner = abort_owner_source.find(
      "InterlockedCompareExchange(&vcpu->State", abort_stage_owner);
  const std::size_t abort_vmxoff_owner =
      abort_owner_source.find("HvVmxOff(", abort_state_owner);
  const std::size_t abort_vmclear_owner =
      abort_owner_source.find("HvClearCurrentVmcsAndRecord()",
                             abort_state_owner);
  const std::size_t abort_vmx_owner_guard =
      abort_owner_source.find("if (ownsVmx)");
  const std::size_t abort_marker_guard =
      abort_owner_source.find("markerFailure");
  const std::size_t abort_instruction_guard =
      abort_owner_source.find("vmxInstructionFailure", abort_marker_guard);
  Check(state, "AbortHvLaunch claims an abort stage owner before VMXOFF",
        !abort_owner_source.empty() && abort_stage_cas &&
            abort_stage_owner != std::string::npos &&
            abort_state_owner > abort_stage_owner &&
            abort_vmxoff_owner > abort_state_owner &&
            abort_vmclear_owner > abort_state_owner &&
            abort_vmclear_owner < abort_vmxoff_owner &&
            abort_vmx_owner_guard != std::string::npos &&
            abort_vmx_owner_guard < abort_vmxoff_owner &&
            !std::regex_search(
                abort_owner_source,
                std::regex(R"(InterlockedExchange\(\s*&vcpu->LaunchStage)")) &&
            abort_marker_guard != std::string::npos &&
            abort_instruction_guard > abort_marker_guard &&
            abort_instruction_guard < abort_vmxoff_owner);
  const std::size_t abort_error_read = abort_owner_source.find(
      "VmReadChecked(VM_INSTRUCTION_ERROR");
  const std::size_t abort_error_publish = abort_owner_source.find(
      "vcpu->LastVmInstructionError = errorCode");
  const std::size_t abort_error_log = abort_owner_source.find(
      "error 0x%llX marker=%u vmx=%u");
  Check(state, "VMLAUNCH rollback reads and logs the current instruction error",
        abort_error_read != std::string::npos &&
            abort_error_publish > abort_error_read &&
            abort_error_log > abort_error_publish);
  const std::string prepare_source = SliceSource(
      vmm, "extern \"C\" ULONG PrepareHvCallback(ULONG_PTR Context",
      "extern \"C\" void AbortHvLaunch(u64 Rflags)");
  const std::size_t vmptrld_error_guard = prepare_source.find(
      "const bool currentVmcsMatches");
  const std::size_t vmptrst_probe = prepare_source.find(
      "HvVmPtrSt(&currentPhys)");
  const std::size_t guarded_error_read = prepare_source.find(
      "currentVmcsMatches &&", vmptrst_probe);
  const std::size_t prepare_vmcs_clear = prepare_source.find(
      "HvClearCurrentVmcsAndRecord()", guarded_error_read);
  Check(state, "VMPTRLD diagnostics prove the current VMCS before VMREAD",
        !prepare_source.empty() &&
            vmptrld_error_guard != std::string::npos &&
            vmptrst_probe != std::string::npos &&
            vmptrst_probe < vmptrld_error_guard &&
            guarded_error_read > vmptrst_probe &&
            prepare_vmcs_clear > guarded_error_read);
  Check(state, "VMLAUNCH rollback clears its current VMCS",
        abort_vmclear_owner != std::string::npos &&
            abort_vmxoff_owner > abort_vmclear_owner &&
            abort_owner_source.find("HvFailVmcsClear()") !=
                std::string::npos);
  const std::string stop_internal_source = SliceSource(
      vmm, "static void StopHypervisorInternal(bool startRollback) {",
      "extern \"C\" void StopHypervisor() {");
  const std::size_t stop_scan_begin =
      stop_internal_source.find("if (coordinatorBound)");
  const std::size_t stop_scan_end =
      stop_internal_source.find("if (unresolved || stopFailed", stop_scan_begin);
  const std::string stop_state_scan =
      stop_scan_begin != std::string::npos && stop_scan_end > stop_scan_begin
          ? stop_internal_source.substr(stop_scan_begin,
                                        stop_scan_end - stop_scan_begin)
          : std::string{};
  const bool stop_has_atomic_index_state =
      std::regex_search(
          stop_state_scan,
          std::regex(R"(InterlockedCompareExchange\(\s*&g_VcpuData\s*\[\s*i\s*\]\s*\.State\s*,\s*0\s*,\s*0\s*\))"));
  const bool stop_has_atomic_reserved_state =
      std::regex_search(
          stop_state_scan,
          std::regex(R"(InterlockedCompareExchange\(\s*&g_VcpuData\s*\[\s*reservedProcessor\s*\]\s*\.State\s*,\s*0\s*,\s*0\s*\))"));
  Check(state, "StopHypervisorInternal snapshots every Vcpu state atomically",
        !stop_state_scan.empty() && stop_has_atomic_index_state &&
            stop_has_atomic_reserved_state &&
            stop_state_scan.find("const long state = g_VcpuData[i].State") ==
                std::string::npos &&
            stop_state_scan.find(
                "const long reservedState = g_VcpuData[reservedProcessor].State") ==
                std::string::npos &&
            stop_state_scan.find("IsVcpuStopTerminal(g_VcpuData[i].State)") ==
                std::string::npos &&
             stop_state_scan.find("g_VcpuData[i].State == VcpuLaunched") ==
                 std::string::npos);
  const std::size_t stop_release_gate =
      stop_internal_source.find("if (unresolved || stopFailed");
  Check(state, "resource release requires a cleared VMCS",
        stop_release_gate != std::string::npos &&
            stop_internal_source.find("HasUnclearedVmcs()",
                                     stop_release_gate) !=
                std::string::npos &&
            stop_internal_source.find("MmFreeContiguousMemory",
                                     stop_release_gate) !=
                std::string::npos);
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
  const std::size_t xsaves_exit_begin =
      vmm.find("case VM_EXIT_REASON_XSAVES");
  const std::size_t xsaves_exit_end =
      vmm.find("case VM_EXIT_REASON_EXTERNAL_INTERRUPT", xsaves_exit_begin);
  const std::string xsaves_exit_source =
      xsaves_exit_begin != std::string::npos &&
              xsaves_exit_end > xsaves_exit_begin
          ? vmm.substr(xsaves_exit_begin,
                       xsaves_exit_end - xsaves_exit_begin)
          : std::string{};
  const std::size_t xsaves_abort =
      xsaves_exit_source.find("Ctx->AbortVm = 0");
  const std::size_t xsaves_halt =
      xsaves_exit_source.find("Ctx->HaltVm = 1", xsaves_abort);
  const std::size_t xsaves_no_advance =
      xsaves_exit_source.find("AdvanceRip = false", xsaves_halt);
  Check(state, "XSAVES/XRSTORS exits use fatal stop",
        !xsaves_exit_source.empty() &&
            xsaves_exit_source.find("case VM_EXIT_REASON_XRSTORS") !=
                std::string::npos &&
            xsaves_abort != std::string::npos &&
            xsaves_halt > xsaves_abort &&
            xsaves_no_advance > xsaves_halt &&
            xsaves_exit_source.find("RequestAuthenticatedUnload") ==
                std::string::npos &&
            xsaves_exit_source.find("Ctx->AbortVm = 1") ==
                std::string::npos);
  const std::size_t unsupported_exit_begin =
      vmm.find("case VM_EXIT_REASON_GETSEC");
  const std::size_t unsupported_exit_end =
      vmm.find("case VM_EXIT_REASON_XSETBV", unsupported_exit_begin);
  const std::string unsupported_exit_source =
      unsupported_exit_begin != std::string::npos &&
              unsupported_exit_end > unsupported_exit_begin
          ? vmm.substr(unsupported_exit_begin,
                       unsupported_exit_end - unsupported_exit_begin)
          : std::string{};
  Check(state, "unconditional non-root exits inject #UD",
        !unsupported_exit_source.empty() &&
            unsupported_exit_source.find("case VM_EXIT_REASON_INVD") !=
                std::string::npos &&
            unsupported_exit_source.find("case VM_EXIT_REASON_INVEPT") !=
                std::string::npos &&
            unsupported_exit_source.find("case VM_EXIT_REASON_INVVPID") !=
                std::string::npos &&
            unsupported_exit_source.find("InjectGuestException(Ctx, 6, false)") !=
                std::string::npos &&
            unsupported_exit_source.find("AdvanceRip = false") !=
                std::string::npos);
  const std::size_t vmexit_clear_begin =
      vmm.find("extern \"C\" void VmExitHandler");
  const std::size_t vmexit_clear_end =
      vmexit_clear_begin == std::string::npos
          ? std::string::npos
          : vmm.find("// VMCS Setup", vmexit_clear_begin);
  const std::size_t entry_clear_info_position =
      vmexit_clear_begin == std::string::npos
          ? std::string::npos
          : vmm.find("VmWriteChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD, 0)",
                     vmexit_clear_begin);
  const std::size_t entry_clear_error_position =
      entry_clear_info_position == std::string::npos
          ? std::string::npos
          : vmm.find(
                "VmWriteChecked(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE, 0)",
                entry_clear_info_position);
  const std::size_t entry_clear_length_position =
      entry_clear_error_position == std::string::npos
          ? std::string::npos
          : vmm.find(
                "VmWriteChecked(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH, 0)",
                entry_clear_error_position);
  Check(state, "VM-entry injection is cleared per exit",
        vmexit_clear_begin != std::string::npos &&
            vmexit_clear_end > vmexit_clear_begin &&
            entry_clear_info_position > vmexit_clear_begin &&
            entry_clear_error_position > entry_clear_info_position &&
            entry_clear_length_position > entry_clear_error_position &&
            entry_clear_length_position < vmexit_clear_end);
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
  const std::size_t entry_failure_begin =
      exit_source.find("if (entryFailure)");
  const std::size_t entry_failure_end =
      entry_failure_begin == std::string::npos
          ? std::string::npos
          : exit_source.find("// Snapshot every event-delivery field",
                             entry_failure_begin);
  const std::string entry_failure_source =
      entry_failure_begin != std::string::npos &&
              entry_failure_end > entry_failure_begin
          ? exit_source.substr(entry_failure_begin,
                               entry_failure_end - entry_failure_begin)
          : std::string{};
  Check(state, "VM-entry failure keeps only defined qualification",
        !entry_failure_source.empty() &&
            entry_failure_source.find(
                "IsVmEntryFailureQualificationDefined(rawExitReason)") !=
                std::string::npos &&
            entry_failure_source.find("VmReadChecked(EXIT_QUALIFICATION") !=
                std::string::npos &&
            entry_failure_source.find("HvVmcsValidityExitQualification") !=
                std::string::npos &&
            entry_failure_source.find("VmReadChecked(VM_INSTRUCTION_ERROR") ==
                std::string::npos &&
            entry_failure_source.find("HvVmcsValidityVmInstructionError") ==
                std::string::npos &&
            entry_failure_source.find("HaltVm = 1") != std::string::npos &&
            entry_failure_source.find("return;") != std::string::npos);
  Check(state, "fatal snapshot refreshes entry-failure reason",
        vmm.find("bool entryFailure = false") != std::string::npos &&
            vmm.find("bool reasonValid = false") != std::string::npos &&
            vmm.find("entryFailure = (static_cast<u32>(value) & 0x80000000U)") !=
                std::string::npos &&
            vmm.find("!reasonValid || resumeFailureBoundary || entryFailure") !=
                std::string::npos);
  Check(state, "entry-failure qualification reasons are allow-listed",
        vmx.find("VM_EXIT_REASON_MSR_LOADING") != std::string::npos &&
            vmx.find("VM_EXIT_REASON_MACHINE_CHECK") != std::string::npos &&
            vmm.find("IsVmEntryFailureQualificationDefined") !=
                std::string::npos);
  CheckPattern(state, "VMRESUME flags are passed to C++", asm_source,
               R"(vmxResumeFailure:[\s\S]{0,700}pushfq[\s\S]{0,900}mov rdx, rbx[\s\S]{0,180}call HandleVmResumeFailure)");
  CheckPattern(state, "VMRESUME failure reads instruction error only for ZF",
               vmm,
               R"(vmFailValid\s*=\s*\(resumeFlags\s*&\s*\(1ULL\s*<<\s*6\)\)[\s\S]{0,500}VM_INSTRUCTION_ERROR)");
  const std::size_t unload_begin =
      vmm.find("static __forceinline void RequestAuthenticatedUnload");
  const std::size_t unload_end =
      unload_begin == std::string::npos
          ? std::string::npos
          : vmm.find("extern \"C\" ULONG HandleVmResumeFailure", unload_begin);
  const std::string unload_source =
      unload_begin != std::string::npos && unload_end > unload_begin
          ? vmm.substr(unload_begin, unload_end - unload_begin)
          : std::string{};
  const std::size_t descriptor_contract =
      unload_source.find("const bool descriptorContractSafe");
  const std::size_t native_teardown_safe =
      unload_source.find("vcpu->NativeTeardownSafe", descriptor_contract);
  const std::size_t authenticated_gate = unload_source.find(
      "if (authenticatedUnload && descriptorContractSafe && noPendingEvent",
      native_teardown_safe);
  const std::size_t authenticated_abort =
      unload_source.find("c->AbortVm = 1", authenticated_gate);
  const std::size_t authenticated_calculation =
      unload_source.find("const bool authenticatedUnload");
  const std::size_t teardown_refresh =
      unload_source.find("UpdateNativeTeardownContract(vcpu)");
  const std::size_t teardown_mask_read =
      unload_source.find("ReadNativeTeardownRejectMask(vcpu)");
  Check(state, "authenticated unload validates descriptor state",
        !unload_source.empty() && descriptor_contract != std::string::npos &&
            native_teardown_safe > descriptor_contract);
  Check(state, "safe exit requires descriptor contract",
        authenticated_gate != std::string::npos &&
            authenticated_abort > authenticated_gate);
  Check(state, "descriptor refresh is limited to authenticated unload",
        authenticated_calculation != std::string::npos &&
            teardown_refresh > authenticated_calculation &&
            teardown_refresh < teardown_mask_read &&
            exit_source.find("UpdateNativeTeardownContract(vcpu)") ==
                std::string::npos);
  const std::string resume_failure_source = SliceSource(
      vmm, "extern \"C\" ULONG HandleVmResumeFailure",
      "static void ReleaseHvCrashBlob");
  Check(state, "VMRESUME failure path does not refresh teardown descriptors",
        !resume_failure_source.empty() &&
            resume_failure_source.find("UpdateNativeTeardownContract(vcpu)") ==
                std::string::npos);
  const std::size_t fatal_exit_begin =
      exit_source.find("case VM_EXIT_REASON_TRIPLE_FAULT");
  const std::size_t fatal_exit_end =
      exit_source.find("case 0:", fatal_exit_begin);
  const std::string fatal_exit_source =
      fatal_exit_begin != std::string::npos &&
              fatal_exit_end > fatal_exit_begin
          ? exit_source.substr(fatal_exit_begin,
                               fatal_exit_end - fatal_exit_begin)
          : std::string{};
  Check(state, "triple fault cannot use native continuation",
        !fatal_exit_source.empty() &&
            fatal_exit_source.find("HvTraceEventFatalVmexit") !=
                std::string::npos &&
            fatal_exit_source.find("Ctx->AbortVm = 0") !=
                std::string::npos &&
            fatal_exit_source.find("Ctx->HaltVm = 1") !=
                std::string::npos &&
            fatal_exit_source.find("RequestSafeExit") == std::string::npos);
  const std::size_t exception_exit_begin = exit_source.find("case 0:");
  const std::size_t exception_exit_end =
      exception_exit_begin == std::string::npos
          ? std::string::npos
          : exit_source.find("default:", exception_exit_begin);
  const std::string exception_exit_source =
      exception_exit_begin != std::string::npos &&
              exception_exit_end > exception_exit_begin
          ? exit_source.substr(exception_exit_begin,
                               exception_exit_end - exception_exit_begin)
          : std::string{};
  Check(state, "double fault exits before native continuation",
        !exception_exit_source.empty() &&
            exception_exit_source.find("VMX_EXCEPTION_VECTOR_DOUBLE_FAULT") !=
                std::string::npos &&
            exception_exit_source.find("HvTraceEventFatalVmexit") !=
                std::string::npos &&
            exception_exit_source.find("Ctx->HaltVm = 1") !=
                std::string::npos);
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
               R"(requestedExit\s*=\s*VM_EXIT_HOST_ADDRESS_SPACE_SIZE[\s\S]{0,180}VM_EXIT_SAVE_DEBUG_CONTROLS[\s\S]{0,1500}requestedEntry\s*=\s*VM_ENTRY_IA32E_MODE_GUEST[\s\S]{0,180}VM_ENTRY_LOAD_DEBUG_CONTROLS)");
  Check(state, "CET does not depend on VMX BASIC bit 56",
        vmm.find("VMX_BASIC_NO_HW_ERROR_CODE") == std::string::npos);
  const std::size_t setup_begin = vmm.find("bool SetupVmcs(");
  const std::size_t setup_end = vmm.find(
      "// ==============================================================================\n// Launch Logic", setup_begin);
  const std::string setup_source =
      setup_begin != std::string::npos && setup_end > setup_begin
          ? vmm.substr(setup_begin, setup_end - setup_begin)
          : std::string{};
  Check(state, "VMCS optional controls start from an explicit baseline",
        !setup_source.empty() &&
            TokensInOrder(setup_source,
                          {"VmWriteChecked(CONTROL_TSC_OFFSET, 0ULL)",
                           "VmWriteChecked(CONTROL_PAGE_FAULT_ERROR_CODE_MASK, 0ULL)",
                           "VmWriteChecked(CONTROL_PAGE_FAULT_ERROR_CODE_MATCH, 0ULL)",
                           "VmWriteChecked(CONTROL_CR3_TARGET_COUNT, 0ULL)",
                           "VmWriteChecked(CONTROL_VM_EXIT_MSR_STORE_COUNT, 0ULL)",
                           "VmWriteChecked(CONTROL_VM_EXIT_MSR_LOAD_COUNT, 0ULL)",
                           "VmWriteChecked(CONTROL_VM_ENTRY_MSR_LOAD_COUNT, 0ULL)"}));
  Check(state, "targeted launch masks IF during frame handoff",
        setup_begin != std::string::npos && setup_end > setup_begin &&
            vmm.substr(setup_begin, setup_end - setup_begin).find(
                "u64 guestRflags = GetRflags()") != std::string::npos &&
            vmm.substr(setup_begin, setup_end - setup_begin).find(
                "(1ULL << 17)") != std::string::npos &&
            vmm.substr(setup_begin, setup_end - setup_begin).find(
                "guestRflags &= ~((1ULL << 9)") != std::string::npos &&
            vmm.substr(setup_begin, setup_end - setup_begin).find(
                "keep interrupts masked while the launch frame") !=
                std::string::npos &&
            vmm.substr(setup_begin, setup_end - setup_begin).find(
                "handoff_if=%u") !=
                std::string::npos);
  const std::size_t vmexit_domain_begin = vmm.find("// VM-Exit Handling");
  const std::size_t vmexit_domain_end =
      vmm.find("// VMCS Setup", vmexit_domain_begin);
  const std::string vmexit_domain =
      vmexit_domain_begin != std::string::npos &&
              vmexit_domain_end > vmexit_domain_begin
          ? vmm.substr(vmexit_domain_begin,
                       vmexit_domain_end - vmexit_domain_begin)
          : std::string{};
  Check(state, "VM-exit domain never formats debugger output",
        !vmexit_domain.empty() &&
            vmexit_domain.find("DbgPrint") == std::string::npos &&
            vmexit_domain.find("HV_PASSIVE_PRINT") == std::string::npos &&
            vmexit_domain.find("HV_VERBOSE_PRINT") == std::string::npos);
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
  const std::size_t gdt_bound_check = selector_validator_source.find(
      "gdtLimit - offset < 7U");
  const std::size_t descriptor_access = selector_validator_source.find(
      "descriptor[5]");
  Check(state, "GDT validation bounds the descriptor before reading access",
        gdt_bound_check != std::string::npos &&
            descriptor_access > gdt_bound_check);
  CheckPattern(state, "VMCS accepts current user data selectors", vmm,
               R"(dsSelector,\s*true,\s*false,\s*false,\s*false,\s*false[\s\S]{0,180}esSelector,\s*true,\s*false,\s*false,\s*false,\s*false)");
  CheckPattern(state, "VMCS keeps CS and SS at kernel privilege", vmm,
               R"(csSelector,\s*false,\s*false,\s*true,\s*true,\s*false[\s\S]{0,260}ssSelector,\s*false,\s*false,\s*false,\s*true,\s*true)");
  const std::size_t guest_tr_helper =
      vmm.find("static bool IsGuestTrSelectorUsable(");
  const std::size_t guest_tr_type =
      vmm.find("return type == 0xBU;", guest_tr_helper);
  const std::size_t guest_tr_call =
      vmm.find("IsGuestTrSelectorUsable(gdtBase, gdtLimit, trSelector)",
               setup_begin);
  Check(state, "guest TR requires a busy 64-bit TSS",
        guest_tr_helper != std::string::npos &&
            guest_tr_type > guest_tr_helper &&
            guest_tr_call != std::string::npos);
  Check(state, "VMCS readback covers the guest TR contract",
        setup_readback_compare != std::string::npos &&
            vmm.find("VmReadChecked(GUEST_TR_SELECTOR", setup_begin) !=
                std::string::npos &&
            vmm.find("VmReadChecked(GUEST_TR_LIMIT", setup_begin) !=
                std::string::npos &&
            vmm.find("VmReadChecked(GUEST_TR_AR_BYTES", setup_begin) !=
                std::string::npos &&
            vmm.find("VmReadChecked(GUEST_TR_BASE", setup_begin) !=
                std::string::npos &&
            vmm.find("GUEST_TR_AR_BYTES, vmcsGuestTrAr", setup_readback_compare) !=
                std::string::npos);
  const std::size_t guest_cr_cache =
      vmm.find("const u64 guestCr0 = AdjustCr0(hostCr0)", setup_begin);
  const std::size_t guest_cr4_cache =
      vmm.find("const u64 guestCr4 = AdjustCr4(hostCr4)", setup_begin);
  const std::size_t setup_guest_cr0_recompute =
      vmm.find("AdjustCr0(__readcr0())", setup_begin);
  const std::size_t setup_guest_cr4_recompute =
      vmm.find("AdjustCr4(__readcr4())", setup_begin);
  Check(state, "VMCS readback reuses the sampled guest CR values",
        guest_cr_cache != std::string::npos &&
            guest_cr4_cache != std::string::npos &&
            setup_guest_cr0_recompute == std::string::npos &&
            setup_guest_cr4_recompute == std::string::npos);
  CheckPattern(state, "TSS base is canonical before VMCS write", vmm,
               R"(base\s*\|=\s*\(high\s*<<\s*32\)[\s\S]{0,120}return\s+IsCanonical\(base\)\s*\?\s*base\s*:\s*0)");
  CheckPattern(state, "feature contract has a sticky validity result", vmm,
               R"(g_VmxFeatureContractInitialized\s*=\s*true)");
  CheckPattern(state, "production mode reserves the startup coordinator", vmm,
               R"(kReserveCoordinatorCpu\s*=\s*true)");
  CheckPattern(state, "reserved coordinator is excluded from launch count", vmm,
               R"(ExpectedLaunchProcessorCount\(\)[\s\S]{0,260}g_ProcessorCount\s*-\s*\(kReserveCoordinatorCpu\s*\?\s*1U\s*:\s*0U\))");
  Check(state, "staged production launch requires a coordinator CPU",
        vmm.find("!kDebugSingleCpu && g_ProcessorCount < 2") !=
            std::string::npos);
  const std::size_t generic_dpc_begin =
      vmm.find("static VOID HyperDbgLaunchDpcRoutine");
  const std::size_t generic_dpc_end =
      vmm.find("extern \"C\" ULONG PrepareHvCallback", generic_dpc_begin);
  const std::size_t generic_dpc_call =
      vmm.find("KeGenericCallDpc(HyperDbgLaunchDpcRoutine");
  const std::string generic_dpc_source =
      generic_dpc_begin != std::string::npos && generic_dpc_end > generic_dpc_begin
          ? vmm.substr(generic_dpc_begin, generic_dpc_end - generic_dpc_begin)
          : std::string{};
  Check(state, "startup uses the HyperDbg generic DPC rendezvous",
        !generic_dpc_source.empty() &&
            generic_dpc_source.find("KeSignalCallDpcSynchronize") !=
                std::string::npos &&
            generic_dpc_source.find("KeSignalCallDpcDone") !=
                std::string::npos && generic_dpc_call != std::string::npos);
  CheckPattern(state, "generic DPC uses the correct synchronization arguments",
               generic_dpc_source,
               R"(KeSignalCallDpcSynchronize\(SystemArgument2\)[\s\S]{0,120}KeSignalCallDpcDone\(SystemArgument1\))");
  Check(state, "generic DPC is opt-in during bring-up",
        vmm.find("kUseHyperDbgGenericLaunch = false") != std::string::npos &&
            vmm.find("if constexpr (kUseHyperDbgGenericLaunch)") !=
                std::string::npos);
  Check(state, "default launch uses finite staged target DPCs",
        vmm.find("launching processors through staged target DPCs") !=
                std::string::npos &&
            vmm.find("QueueTargetLaunchDpc(i)") != std::string::npos &&
            vmm.find("WaitTargetLaunchDpc(i, launchDeadline") !=
                std::string::npos);
  Check(state, "staged launch leaves the coordinator native",
        vmm.find("coordinator CPU %u remains native for KD") ==
                std::string::npos &&
            vmm.find("ReleaseCoordinatorAffinity(&coordinatorAffinity") !=
                std::string::npos &&
            vmm.find("QueueTargetLaunchDpc(reservedProcessor)") ==
                std::string::npos);
  const std::size_t staged_dpc_begin =
      vmm.find("static VOID TargetLaunchDpcRoutine");
  const std::size_t staged_entry_boundary =
      vmm.find("LaunchCheckEntry", staged_dpc_begin);
  const std::size_t staged_dispatch_boundary =
      vmm.find("RecordLaunchBoundary(&g_HvLaunchDispatchEntered",
               staged_entry_boundary);
  Check(state, "staged DPC publishes its entry boundary",
        staged_entry_boundary != std::string::npos &&
            staged_dispatch_boundary != std::string::npos &&
            staged_dispatch_boundary - staged_entry_boundary <= 220);
  Check(state, "staged launch retains per CPU diagnostics",
        vmm.find("CPU %u staged launch: status=0x%08X state=%ld ") !=
                std::string::npos &&
            vmm.find("stage=%ld check=%ld vmexits=%ld") !=
                std::string::npos);
  Check(state, "staged launch reports exit reason and instruction state",
        vmm.find("raw_reason=0x%08X") != std::string::npos &&
            vmm.find("msr_value=0x%llX") != std::string::npos &&
            vmm.find("exit_len=%llu") != std::string::npos &&
            vmm.find("action=%ld") != std::string::npos &&
            vmm.find("resume_flags=0x%llX") != std::string::npos);
  Check(state, "staged launch reports the CR3 boundary record",
        vmm.find("cr3_guest=0x%llX cr3_host=0x%llX") != std::string::npos &&
            vmm.find("cr3_meta=0x%llX") != std::string::npos &&
            vmm.find("LaunchRawGuestCr3 = 0") != std::string::npos &&
            vmm.find("LaunchRawHostCr3 = 0") != std::string::npos);
  Check(state, "staged launch keeps raw CR3 in a short diagnostic record",
         vmm.find("[HV] CPU %u staged CR3: raw_guest=0x%llX") !=
                 std::string::npos &&
            vmm.find("raw_host=0x%llX host=0x%llX meta=0x%llX") !=
                std::string::npos &&
             vmm.find("ReadLaunchCr3Field(&g_VcpuData[i].LaunchRawGuestCr3)") !=
                 std::string::npos);
  Check(state, "failure diagnostics stay below the debugger burst limit",
        vmm.find("launch failure: state=%ld") != std::string::npos &&
            vmm.find("launch transition: msr=0x%08X") != std::string::npos &&
            vmm.find("VMCS access: setup_phase=%ld") != std::string::npos &&
            vmm.find("VMCS image: mismatch=%ld") != std::string::npos &&
            vmm.find("VMCS capabilities: primary=0x%llX") !=
                std::string::npos);
  Check(state, "host stack top stays inside the allocation",
        vmm.find("const u64 stackLastByte") != std::string::npos &&
            vmm.find("kVmxHostStackSize - 1") != std::string::npos &&
            vmm.find("stackLastByte & ~(kVmxHostStackAlignment - 1)") !=
                std::string::npos);
  CheckPattern(
      state, "successful launch output is compact", vmm,
      R"(LaunchResultNeedsDetail[\s\S]{0,1200}keep the normal path below the debugger transport's burst size[\s\S]{0,500}reason=0x%08X)");
  Check(state, "launch diagnostics are scoped to participating processors",
        vmm.find("static __forceinline bool ShouldReportLaunchResult") !=
                std::string::npos &&
            vmm.find("ShouldLaunchOnThisProcessor(processorIndex)") !=
                std::string::npos &&
            vmm.find("if (!ShouldReportLaunchResult(processorIndex)) return;") !=
                std::string::npos);
  Check(state, "launch diagnostics use the participation predicate only",
        vmm.find("return ShouldLaunchOnThisProcessor(processorIndex);") !=
            std::string::npos &&
            vmm.find("return kUseHyperDbgGenericLaunch ||") ==
                std::string::npos);
  Check(state, "staged success output is conditional",
        vmm.find("LaunchResultNeedsDetail(i, g_VcpuData[i])") !=
                std::string::npos &&
            vmm.find("[HV] staged launch completed: %u/%u participating processors") !=
                std::string::npos);
  Check(state, "failed launch output keeps split diagnostic records",
        vmm.find("keep each failure record below DbgPrintEx's 512-byte call limit") !=
                std::string::npos &&
            vmm.find("launch failure: state=%ld") != std::string::npos &&
            vmm.find("launch transition: msr=0x%08X") != std::string::npos &&
            vmm.find("VMCS access: setup_phase=%ld") != std::string::npos &&
            vmm.find("VMCS image: mismatch=%ld") != std::string::npos &&
            vmm.find("VMCS capabilities: primary=0x%llX") !=
                std::string::npos);
  CheckPattern(state, "target workers retain the driver object", vmm,
               R"(IoCreateSystemThread\(g_HvDriverObject[\s\S]{0,600}TargetCpuWorker)");
  CheckPattern(state, "target workers bind and verify processor identity", vmm,
               R"(KeSetSystemGroupAffinityThread[\s\S]{0,600}KeGetCurrentProcessorNumberEx[\s\S]{0,500}TargetWorkExecuting)");
  CheckPattern(state, "target waits use a finite relative deadline", vmm,
               R"(RemainingTargetTimeout[\s\S]{0,500}timeout\.QuadPart\s*=\s*-static_cast<LONGLONG>[\s\S]{0,1400}STATUS_TIMEOUT)");
  CheckPattern(state, "debug isolation keeps a target DPC path", vmm,
               R"(QueueTargetLaunchDpc[\s\S]{0,1700}KeSetTargetProcessorDpcEx[\s\S]{0,520}KeInsertQueueDpc)");
  Check(state, "generic launch DPC calls the assembly entry directly",
        generic_dpc_source.find("EnableHvCallback(0)") != std::string::npos &&
            generic_dpc_source.find("LaunchIpiDispatchCallback") ==
                std::string::npos);
  CheckPattern(state, "launch result exposes transition counters", vmm,
               R"(generic DPC launch result[\s\S]{0,900}vmexit_asm[\s\S]{0,180}dispatch_returned)");
  CheckPattern(state, "launch result exposes the failed contract block", vmm,
               R"(generic DPC launch result:[\s\S]{0,180}check=%ld)");
  CheckPattern(state, "debug launch DPC waits for callback rundown", vmm,
               R"(WaitTargetLaunchDpc[\s\S]{0,900}KeWaitForSingleObject[\s\S]{0,500}KeRemoveQueueDpcEx\(&work->Dpc, TRUE\))");
  const std::size_t launch_dpc_begin =
      vmm.find("static VOID TargetLaunchDpcRoutine");
  const std::size_t launch_dpc_end =
      vmm.find("static LARGE_INTEGER RemainingTargetTimeout", launch_dpc_begin);
  const std::string launch_dpc_source =
      launch_dpc_begin != std::string::npos && launch_dpc_end > launch_dpc_begin
          ? vmm.substr(launch_dpc_begin, launch_dpc_end - launch_dpc_begin)
          : std::string{};
  Check(state, "staged launch calls the assembly entry directly",
        !launch_dpc_source.empty() &&
            launch_dpc_source.find("EnableHvCallback(0)") !=
                std::string::npos &&
            launch_dpc_source.find("LaunchIpiDispatchCallback") ==
                std::string::npos);
  const std::size_t launch_dpc_entry =
      launch_dpc_source.find("EnableHvCallback(0)");
  const std::size_t launch_dpc_state =
      launch_dpc_source.find("State == VcpuLaunched", launch_dpc_entry);
  const std::size_t launch_dpc_complete =
      launch_dpc_source.find("DpcCompleted", launch_dpc_state);
  Check(state, "staged DPC publishes completion after launch state",
        launch_dpc_entry != std::string::npos &&
            launch_dpc_state > launch_dpc_entry &&
            launch_dpc_complete > launch_dpc_state &&
            launch_dpc_source.find("State, VcpuStopped") == std::string::npos);
  const std::size_t staged_running_call =
      launch_dpc_source.find("MarkCurrentVcpuRunning");
  const std::size_t staged_running_state =
      launch_dpc_source.find("VcpuLaunched", launch_dpc_entry);
  const std::size_t staged_running_barrier =
      launch_dpc_source.find("MemoryBarrier", staged_running_call);
  const std::size_t staged_active_stage =
      launch_dpc_source.find("LaunchStageGuestActive", staged_running_call);
  Check(state, "staged DPC marks guest active before completion",
        staged_running_call != std::string::npos &&
            staged_running_state != std::string::npos &&
            staged_running_call > launch_dpc_entry &&
            staged_running_call > staged_running_state &&
            staged_running_call < launch_dpc_complete &&
            staged_running_barrier != std::string::npos &&
            staged_running_barrier < launch_dpc_complete &&
            staged_active_stage != std::string::npos &&
            staged_active_stage > staged_running_call &&
            staged_active_stage < launch_dpc_complete);
  const std::size_t staged_return_boundary =
      launch_dpc_source.find("RecordLaunchBoundary(&g_HvLaunchDispatchReturned",
                             staged_active_stage);
  Check(state, "staged DPC publishes return boundary before completion",
        staged_return_boundary != std::string::npos &&
            staged_return_boundary > staged_active_stage &&
            staged_return_boundary < launch_dpc_complete);
  const std::size_t launch_probe_gate = launch_dpc_source.find(
      "if constexpr (kEnableLaunchFirstExitProbe)", staged_active_stage);
  const std::size_t first_exit_probe_call =
      launch_dpc_source.find("RunFirstExitProbe", launch_probe_gate);
  const std::size_t default_probe_init = launch_dpc_source.find(
      "bool firstExitProbePassed = guestActive", staged_active_stage);
  Check(state, "staged DPC keeps the first-exit probe opt-in",
        vmm.find("kEnableLaunchFirstExitProbe = false") !=
            std::string::npos &&
            default_probe_init != std::string::npos &&
            launch_probe_gate > default_probe_init &&
            first_exit_probe_call > launch_probe_gate &&
            first_exit_probe_call < staged_return_boundary &&
            first_exit_probe_call < launch_dpc_complete);
  const std::string vmexit_handler_source = SliceSource(
      vmm, "extern \"C\" void VmExitHandler",
      "// VMCS Setup");
  const std::size_t final_probe_fault_gate = vmexit_handler_source.find(
      "ShouldInjectFault(cpuId, HvFaultBeforeVmresume)");
  const std::size_t final_probe_complete = vmexit_handler_source.find(
      "CompleteFirstExitProbe", final_probe_fault_gate);
  const std::size_t final_probe_resume = vmexit_handler_source.find(
      "InterlockedIncrement(&vcpu->VmResumeAttempts)", final_probe_complete);
  Check(state, "first VM-exit proof follows final action and precedes VMRESUME",
        !vmexit_handler_source.empty() &&
            final_probe_fault_gate != std::string::npos &&
            final_probe_complete > final_probe_fault_gate &&
            final_probe_resume > final_probe_complete &&
            vmexit_handler_source.find("FailFirstExitProbeAtFatalBoundary") !=
                std::string::npos);
  const std::string vmresume_failure_source = SliceSource(
      vmm, "extern \"C\" ULONG HandleVmResumeFailure",
      "static void ReleaseHvCrashBlob");
  Check(state, "VMRESUME failure invalidates the first-exit proof",
        !vmresume_failure_source.empty() &&
            vmresume_failure_source.find("LastVmResumeFlags") !=
                std::string::npos &&
            vmresume_failure_source.find("FailFirstExitProbeAtFatalBoundary") !=
                std::string::npos);
  const std::string first_exit_probe_failure_source = SliceSource(
      vmm, "static void FailFirstExitProbeIfActive",
      "static void MarkFirstExitProbeVmExitEntered");
  const std::string validated_probe_invalidation_source = SliceSource(
      vmm, "static void InvalidateValidatedFirstExitProbe",
      "static void FailFirstExitProbeAtFatalBoundary");
  Check(state, "ordinary probe failure preserves a validated proof",
        !first_exit_probe_failure_source.empty() &&
            first_exit_probe_failure_source.find(
                "state != FirstExitProbeExitValidated") ==
                std::string::npos &&
            !validated_probe_invalidation_source.empty() &&
            validated_probe_invalidation_source.find(
                "FirstExitProbeExitValidated") != std::string::npos &&
            validated_probe_invalidation_source.find(
                "FirstExitProbeReason") != std::string::npos);
  const std::string first_exit_probe_layout = SliceSource(
      common, "struct VcpuContext", "static_assert");
  Check(state, "first VM-exit proof is per VCPU",
        !first_exit_probe_layout.empty() &&
            TokensInOrder(first_exit_probe_layout,
                          {"FirstExitProbeState",
                           "FirstExitProbeBaselineVmExits",
                           "FirstExitProbeObservedVmExits",
                           "FirstExitProbeReason",
                           "FirstExitProbeAction"}));
  const std::string first_exit_probe_source = SliceSource(
      vmm, "static bool VerifyFirstExitProbeReturn",
      "static __forceinline void RequestFatalStop");
  Check(state, "first VM-exit proof uses the private CPUID response",
        !first_exit_probe_source.empty() &&
            first_exit_probe_source.find("__cpuidex") != std::string::npos &&
            first_exit_probe_source.find("kFirstExitProbeLeaf") !=
                std::string::npos &&
            first_exit_probe_source.find("kFirstExitProbeEbx") !=
                std::string::npos &&
            first_exit_probe_source.find("kFirstExitProbeEcx") !=
                std::string::npos &&
            first_exit_probe_source.find("kFirstExitProbeEdx") !=
                std::string::npos);
  Check(state, "first VM-exit proof tolerates a nonzero baseline",
        !first_exit_probe_source.empty() &&
            first_exit_probe_source.find("baselineExits == 0") ==
                std::string::npos &&
            first_exit_probe_source.find("baselineResumes == 0") ==
                std::string::npos &&
            first_exit_probe_source.find("currentExits >= baselineExits + 1") !=
                std::string::npos &&
            first_exit_probe_source.find(
                "currentResumes >= baselineResumes + 1") !=
                std::string::npos);
  const std::string first_exit_probe_complete = SliceSource(
      vmm, "static void CompleteFirstExitProbe",
      "static bool ArmFirstExitProbe");
  Check(state, "probe completion tolerates exits before the sentinel",
        !first_exit_probe_complete.empty() &&
            first_exit_probe_complete.find("observedExits >= baselineExits + 1") !=
                std::string::npos &&
            first_exit_probe_complete.find("observedResumes >= baselineResumes") !=
                std::string::npos &&
            first_exit_probe_complete.find("observedExits == baselineExits + 1") ==
                std::string::npos);
  Check(state, "private CPUID response is limited to an armed probe",
        vmm.find("leaf == kFirstExitProbeLeaf && subleaf == 0") !=
                std::string::npos &&
            vmm.find("probeState == FirstExitProbeArmed") !=
                std::string::npos &&
            vmm.find("probeState == FirstExitProbeVmExitEntered") !=
                std::string::npos);
  const std::size_t cpuid_case = vmexit_handler_source.find(
      "case VM_EXIT_REASON_CPUID");
  const std::size_t probe_marker = vmexit_handler_source.find(
      "MarkFirstExitProbeVmExitEntered");
  const std::size_t diagnostic_transaction = vmexit_handler_source.find(
      "SetVmcsDiagnosticValidity(vcpu, HvVmcsValidityExitReason)");
  Check(state, "first-exit token is claimed only by the probe CPUID",
        cpuid_case != std::string::npos && probe_marker > cpuid_case &&
            diagnostic_transaction != std::string::npos &&
            diagnostic_transaction < cpuid_case);
  const std::size_t generic_running_call =
      generic_dpc_source.find("MarkCurrentVcpuRunning");
  const std::size_t generic_running_state =
      generic_dpc_source.find("VcpuLaunched");
  const std::size_t generic_running_barrier =
      generic_dpc_source.find("MemoryBarrier", generic_running_call);
  const std::size_t generic_active_stage =
      generic_dpc_source.find("LaunchStageGuestActive", generic_running_call);
  const std::size_t generic_done =
      generic_dpc_source.find("KeSignalCallDpcDone");
  Check(state, "generic DPC marks guest active before rendezvous done",
        generic_running_call != std::string::npos &&
            generic_running_state != std::string::npos &&
            generic_running_call > generic_running_state &&
            generic_done != std::string::npos &&
            generic_running_call < generic_done &&
            generic_running_barrier != std::string::npos &&
            generic_running_barrier < generic_done &&
            generic_active_stage != std::string::npos &&
            generic_active_stage > generic_running_call &&
            generic_active_stage < generic_done);
  Check(state, "temporary target worker cannot launch VMX",
        [&]() {
          const std::size_t worker_begin = vmm.find("static VOID TargetCpuWorker");
          const std::size_t worker_end = vmm.find("static VOID TargetLaunchDpcRoutine", worker_begin);
          return worker_begin != std::string::npos && worker_end > worker_begin &&
                 vmm.substr(worker_begin, worker_end - worker_begin).find(
                     "LaunchIpiDispatchCallback") == std::string::npos;
        }());
  CheckPattern(state, "CPU generation profile has explicit branches", vmm,
               R"(VmxProfileLegacyControls[\s\S]{0,900}VmxProfileTrueControls[\s\S]{0,900}VmxProfileXsaves[\s\S]{0,900}VmxProfileRdtscp[\s\S]{0,900}VmxProfileInvpcid)");
  CheckPattern(state, "CPU generation profile checks optional controls", vmm,
               R"(BuildVmxCapabilityProfile\([\s\S]{0,3200}VmxProfileTertiaryControls)");
  CheckPattern(state, "CPU generation selects explicit VMX control branches", vmm,
               R"(SelectVmxControlGeneration[\s\S]{0,700}VmxGenerationLegacy[\s\S]{0,700}VmxGenerationTrueTertiary)");
  CheckPattern(state, "CPU generation controls use the local profile", vmm,
               R"(const u32 profile\s*=\s*Vcpu->VmxProfile[\s\S]{0,500}VmxProfileInvpcid[\s\S]{0,500}VmxProfileRdtscp)");
  const std::string cpu_branch_select_source = SliceSource(
      vmm, "static IntelCpuBranch SelectIntelCpuBranch",
      "static IntelCpuIdentity QueryIntelCpuIdentity");
  const std::string cpu_identity_query_source = SliceSource(
      vmm, "static IntelCpuIdentity QueryIntelCpuIdentity",
      "static const char* IntelCpuBranchName");
  const std::string cpu_branch_compat_source = SliceSource(
      vmm, "static bool IsIntelCpuBranchCompatible",
      "// CPUID.0D.1:EBX describes");
  Check(state, "CPU identity selects model and hybrid branches explicitly",
        !cpu_branch_select_source.empty() &&
            cpu_branch_select_source.find("UNREFERENCED_PARAMETER(model)") ==
                std::string::npos &&
            cpu_branch_select_source.find("model") != std::string::npos &&
            cpu_branch_select_source.find("knownHybridModel") !=
                std::string::npos &&
            cpu_branch_select_source.find("knownHybridModel ?") !=
                std::string::npos &&
            cpu_branch_select_source.find("IntelCpuBranchLegacy") !=
                std::string::npos &&
            cpu_branch_select_source.find("IntelCpuBranchModern") !=
                std::string::npos &&
            cpu_branch_select_source.find("IntelCpuBranchHybridPerformance") !=
                std::string::npos &&
            cpu_branch_select_source.find("IntelCpuBranchHybridEfficient") !=
                std::string::npos &&
            cpu_branch_select_source.find("IntelCpuBranchHybridUnknown") !=
                std::string::npos);
  Check(state, "CPU identity query is vendor and leaf guarded",
        !cpu_identity_query_source.empty() &&
            TokensInOrder(cpu_identity_query_source,
                          {"__cpuid(regs, 0)", "GenuineIntel",
                           "__cpuidex(regs, 1, 0)", "identity.Family",
                           "identity.Model", "identity.Stepping",
                           "maxBasicLeaf >= 0x1A", "__cpuidex(regs, 0x1A, 0)",
                           "SelectIntelCpuBranch"}));
  Check(state, "CPU identity compatibility rejects unknown vendors and cores",
        !cpu_branch_compat_source.empty() &&
            cpu_branch_compat_source.find("!identity.GenuineIntel") !=
                std::string::npos &&
            cpu_branch_compat_source.find("IntelCpuBranchUnknown") !=
                std::string::npos &&
            cpu_branch_compat_source.find("IntelCpuBranchHybridUnknown") !=
                std::string::npos &&
            cpu_branch_compat_source.find("VmxProfileTrueControls") !=
                std::string::npos);
  const std::string identity_prepare_source = SliceSource(
      vmm, "extern \"C\" ULONG PrepareHvCallback(",
      "extern \"C\" void AbortHvLaunch");
  const std::size_t identity_query_call =
      identity_prepare_source.find("QueryIntelCpuIdentity");
  const std::size_t identity_compat_call =
      identity_prepare_source.find("IsIntelCpuBranchCompatible",
                                  identity_query_call);
  const std::size_t first_prepare_cr_write =
      identity_prepare_source.find("__writecr0");
  const std::size_t prepare_vmxon = identity_prepare_source.find("HvVmxOn(");
  Check(state, "each CPU validates identity before VMX state changes",
        identity_query_call != std::string::npos &&
            identity_compat_call > identity_query_call &&
            first_prepare_cr_write > identity_compat_call &&
            prepare_vmxon > identity_compat_call &&
            TokensInOrder(identity_prepare_source,
                          {"vcpu->CpuFamily", "vcpu->CpuModel",
                           "vcpu->CpuStepping", "vcpu->CpuCoreType",
                           "vcpu->CpuBranch"}));
  Check(state, "CPU identity branch is present in launch diagnostics",
        vmm.find("IntelCpuBranchName") != std::string::npos &&
            (identity_prepare_source.find("IntelCpuBranchName") !=
                 std::string::npos ||
             vmm.find("branch=%s") != std::string::npos));
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
  const std::size_t optional_launch_begin =
      start_source.find("const u32 expected = ExpectedLaunchProcessorCount()");
  const std::size_t optional_publish = start_source.find(
      "InterlockedExchange(&g_VmxGuestOptionalProfile,", optional_launch_begin);
  const std::size_t optional_publish_value =
      optional_publish != std::string::npos
          ? start_source.find("candidateOptionalProfile", optional_publish)
          : std::string::npos;
  const std::size_t launch_result = start_source.find("if (ok != expected)");
  Check(state, "guest optional profile publishes after launch orchestration",
        optional_zero_value &&
            optional_seed != std::string::npos &&
            optional_launch_begin != std::string::npos &&
            optional_publish != std::string::npos &&
            optional_publish_value != std::string::npos &&
            launch_result != std::string::npos &&
            optional_seed < optional_launch_begin &&
            optional_launch_begin < launch_result &&
            launch_result < optional_publish &&
            optional_publish < optional_publish_value);
  CheckPattern(state, "feature control is never provisioned by the driver", vmm,
               R"(EnsureFeatureControlForVmx\([\s\S]{0,500}return \(featureControl & required\) == required)");
  CheckPattern(state, "feature contract resets only while idle", vmm,
               R"(if\s*\(g_VcpuData\s*==\s*nullptr\)[\s\S]{0,500}g_VmxFeatureContractInitialized\s*=\s*false)");
  CheckPattern(state, "VMX region allocation follows VMX BASIC", vmm,
               R"(g_VmxRequires32BitPhysicalAddress\s*=\s*\([\s\S]{0,180}VMX_BASIC_PHYSICAL_ADDRESS_32)");
  const std::string feature_contract_source =
      SliceSource(vmm, "bool InitializeVmxFeatureContract()",
                  "static constexpr u64 kHvCrashBlobSignature");
  const std::size_t frame_mask_begin =
      feature_contract_source.rfind("// the frame mask is immutable");
  const std::string frame_mask_source =
      frame_mask_begin != std::string::npos
          ? feature_contract_source.substr(frame_mask_begin)
          : std::string{};
  const std::size_t xsaves_mask_assign =
      frame_mask_source.find("g_XsavesMask =");
  const std::size_t supported_xss_assign =
      frame_mask_source.find("g_SupportedXssMask =");
  const std::size_t guest_xss_write_assign =
      frame_mask_source.find("g_GuestXssWriteMask =");
  Check(state, "CPUID XSS mask is restricted to preserved components",
        !frame_mask_source.empty() && xsaves_mask_assign != std::string::npos &&
            supported_xss_assign > xsaves_mask_assign &&
            frame_mask_source.find("g_HostXssMask") != std::string::npos &&
            frame_mask_source.find("enumeratedXss") != std::string::npos &&
            frame_mask_source.find("IA32_XSS_PRESERVABLE_MASK") !=
                std::string::npos &&
            guest_xss_write_assign > supported_xss_assign);
  CheckPattern(state, "XSAVES fixed mask preserves host XSS", vmm,
               R"(g_XsavesMask\s*=\s*g_XsavesEnabled[\s\S]{0,120}\?\s*g_HostXssMask\s*:\s*0)");
  Check(state, "guest XSS stays inside fixed frame mask",
        !frame_mask_source.empty() &&
            frame_mask_source.find("g_XsavesMask & enumeratedXss") !=
                std::string::npos &&
            frame_mask_source.find("g_GuestXssWriteMask = g_SupportedXssMask") !=
                std::string::npos);
  Check(state, "guest XSS write policy follows the preserved mask",
        guest_xss_write_assign != std::string::npos &&
            frame_mask_source.find("g_GuestXssWriteMask = g_SupportedXssMask") !=
                std::string::npos);
  CheckPattern(state, "preservation contract includes PT and CET_U", vmx,
               R"(IA32_XSS_PRESERVABLE_MASK\s+\(IA32_XSS_IPT\s*\|\s*IA32_XSS_CET_U\))");
  Check(state, "XSAVES computed frame matches the live CPUID selection",
        vmm.find("g_XsaveStateSize != xsavesSize") != std::string::npos &&
            vmm.find("localXsavesSize != localXsaveStateSize") !=
                std::string::npos);
  CheckPattern(state, "IPT XSS requires VMX PT support", vmm,
               R"(IA32_XSS_IPT[\s\S]{0,500}MSR_IA32_VMX_MISC[\s\S]{0,400}vmxMisc\s*&\s*VMX_MISC_INTEL_PT[\s\S]{0,180}return false)");
  CheckPattern(state, "active PT is rejected before VMX", vmm,
               R"(MSR_IA32_RTIT_CTL[\s\S]{0,700}ptControl\s*&\s*IA32_RTIT_CTL_TRACEEN[\s\S]{0,180}return false)");
  const std::string prepare_contract_source =
      SliceSource(vmm, "extern \"C\" ULONG PrepareHvCallback(",
                  "extern \"C\" void AbortHvLaunch");
  const std::size_t host_xss_assign =
      prepare_contract_source.find("vcpu->HostXss = hostXss");
  const std::size_t guest_xss_assign =
      host_xss_assign == std::string::npos
          ? std::string::npos
          : prepare_contract_source.find("vcpu->GuestXss =", host_xss_assign);
  const bool guest_xss_copies_host =
      guest_xss_assign != std::string::npos &&
      (prepare_contract_source.compare(guest_xss_assign,
                                       std::string_view("vcpu->GuestXss = hostXss").size(),
                                       "vcpu->GuestXss = hostXss") == 0 ||
       prepare_contract_source.compare(guest_xss_assign,
                                       std::string_view("vcpu->GuestXss = vcpu->HostXss").size(),
                                       "vcpu->GuestXss = vcpu->HostXss") == 0);
  Check(state, "guest XSS starts with the interrupted host state",
        host_xss_assign != std::string::npos && guest_xss_copies_host &&
            guest_xss_assign > host_xss_assign);
  const std::string handle_msr_write_source =
      SliceSource(vmm, "bool HandleMsrWrite(", "static bool ConfigureMsrBitmap");
  const std::size_t live_xss_mask =
      exit_source.find("Ctx->GuestXss & ~g_XsavesMask");
  const std::size_t write_xss_mask =
      handle_msr_write_source.find("value.QuadPart & ~g_GuestXssWriteMask");
  Check(state, "live XSS validation is separate from guest write policy",
        live_xss_mask != std::string::npos && write_xss_mask != std::string::npos &&
            handle_msr_write_source.find("RequestFatalStop") == std::string::npos);
  CheckPattern(state, "XSS preservation failures use the flight recorder", vmm,
               R"(WriteHvTrace\([\s\S]{0,160}HvTraceEventXssPreservationFail[\s\S]{0,200}g_GuestXssWriteMask[\s\S]{0,80}g_HostXssMask)");
  const std::size_t xss_branch =
      handle_msr_write_source.find("if (msrIndex == MSR_IA32_XSS)");
  const std::size_t xss_end =
      handle_msr_write_source.find("if (msrIndex == MSR_IA32_U_CET", xss_branch);
  const std::string xss_write_source =
      xss_branch != std::string::npos && xss_end > xss_branch
          ? handle_msr_write_source.substr(xss_branch, xss_end - xss_branch)
          : std::string{};
  const std::size_t xss_legacy_gate =
      xss_write_source.find("if (!g_XsavesEnabled)");
  const std::size_t xss_legacy_change =
      xss_write_source.find("value.QuadPart != 0", xss_legacy_gate);
  const std::size_t xss_legacy_gp =
      xss_write_source.find("InjectGuestException(Ctx, 13, true, 0)",
                            xss_legacy_change);
  const std::size_t xss_mask_check =
      xss_write_source.find("value.QuadPart & ~g_GuestXssWriteMask");
  const std::size_t xss_mask_gp =
      xss_write_source.find("InjectGuestException(Ctx, 13, true, 0)",
                            xss_mask_check);
  const std::size_t xss_shadow =
      xss_write_source.find("Ctx->GuestXss = value.QuadPart", xss_mask_gp);
  Check(state, "invalid guest XSS writes inject #GP",
        !xss_write_source.empty() && xss_legacy_gate != std::string::npos &&
            xss_legacy_change > xss_legacy_gate &&
            xss_legacy_gp > xss_legacy_change &&
            xss_mask_check != std::string::npos && xss_mask_gp > xss_mask_check &&
            xss_shadow > xss_mask_gp &&
            xss_write_source.find("RequestFatalStop") == std::string::npos);
  Check(state, "legal guest XSS writes update the per-vCPU shadow",
        xss_shadow != std::string::npos &&
            xss_write_source.find("g_VcpuData[id].GuestXss = value.QuadPart",
                                  xss_shadow) != std::string::npos);
  const std::string handle_msr_read_source =
      SliceSource(vmm, "bool HandleMsrRead(", "bool HandleMsrWrite(");
  const std::size_t hidden_read =
      handle_msr_read_source.find("IsIntelPtMsr(msrIndex) || IsCetStateMsr(msrIndex)");
  const std::size_t hidden_write =
      handle_msr_write_source.find("IsIntelPtMsr(msrIndex) || IsCetStateMsr(msrIndex)");
  Check(state, "PT and unsupported CET accesses inject #GP",
        hidden_read != std::string::npos && hidden_write != std::string::npos &&
            handle_msr_read_source.find("InjectGuestException(Ctx, 13, true, 0)",
                                        hidden_read) != std::string::npos &&
            handle_msr_write_source.find("InjectGuestException(Ctx, 13, true, 0)",
                                         hidden_write) != std::string::npos &&
            handle_msr_read_source.find("RequestFatalStop") == std::string::npos &&
            handle_msr_write_source.find("RequestFatalStop") == std::string::npos);
  const std::string guest_state_validation_source = SliceSource(
      vmm, "static __forceinline bool IsValidGuestState(const GuestContext* c)",
      "static __forceinline long AcquireFatalSnapshotCommitState");
  Check(state, "guest-state validation covers both XCR0 and XSS",
        !guest_state_validation_source.empty() &&
            guest_state_validation_source.find("GuestXcr0") != std::string::npos &&
            guest_state_validation_source.find("GuestXss") != std::string::npos &&
            guest_state_validation_source.find("return false") != std::string::npos);
  const bool fxsave_xstate_guard =
      guest_state_validation_source.find("XstateSaveFxsave") != std::string::npos &&
      ContainsAny(guest_state_validation_source,
                  {"GuestXcr0 != 0", "GuestXss != 0",
                   "GuestXcr0 != g_HostXcr0", "GuestXss != g_HostXss"});
  const bool xsave_xcr0_subset =
      ContainsAny(guest_state_validation_source,
                  {"GuestXcr0 & ~g_HostXcr0Mask",
                   "GuestXcr0 & ~g_HostXcr0", "GuestXcr0 & ~HostXcr0",
                   "GuestXcr0 & ~hostXcr0", "c->GuestXcr0 & ~"});
  const bool xsaves_xss_subset =
      ContainsAny(guest_state_validation_source,
                  {"GuestXss & ~g_XsavesMask",
                   "GuestXss & ~g_SupportedXssMask",
                   "GuestXss & ~XsavesMask", "c->GuestXss & ~"});
  const bool xsave_mode_guard =
      ContainsAny(guest_state_validation_source,
                  {"g_XstateMode != XstateSaveFxsave",
                   "g_XstateMode == XstateSaveFxsave"});
  Check(state, "guest-state validation is mode-aware and mask-bounded",
        fxsave_xstate_guard && xsave_mode_guard && xsave_xcr0_subset &&
            xsaves_xss_subset &&
            guest_state_validation_source.find("g_XsavesEnabled") !=
                std::string::npos);
  Check(state, "per-vCPU VM-entry event snapshot fields are present",
        common.find("LastVmEntryIntrInfo") != std::string::npos &&
            common.find("LastVmEntryIntrError") != std::string::npos &&
            common.find("LastVmEntryInstructionLength") != std::string::npos);
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
               R"(g_XsavesEnabled\s*\)[\s\S]{0,900}localXsaveFeatures\s*&\s*CPUID_D1_XSAVES)");
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
  const std::string msr_bitmap_source = SliceSource(
      vmm, "static bool ConfigureMsrBitmap(VcpuContext* vcpu)",
      "static __forceinline u32 ControlMsr");
  Check(state, "managed Windows MSRs are intercepted", [&]() {
    if (msr_bitmap_source.empty()) return false;
    return TokensInOrder(msr_bitmap_source,
                         {"MSR_FS_BASE", "MSR_GS_BASE",
                          "MSR_IA32_EFER", "MSR_IA32_PAT",
                          "MSR_IA32_DEBUGCTL",
                          "MSR_IA32_SYSENTER_CS", "MSR_IA32_SYSENTER_ESP",
                          "MSR_IA32_SYSENTER_EIP"});
  }());
  Check(state, "KERNEL_GS_BASE follows HyperDbg pass-through", [&]() {
    if (msr_bitmap_source.empty()) return false;
    const std::size_t managed_begin = msr_bitmap_source.find(
        "constexpr u32 vmxManagedWriteMsrs[]");
    const std::size_t managed_end =
        managed_begin == std::string::npos
            ? std::string::npos
            : msr_bitmap_source.find("};", managed_begin);
    if (managed_begin == std::string::npos || managed_end == std::string::npos) {
      return false;
    }
    const std::string managed = msr_bitmap_source.substr(
        managed_begin, managed_end - managed_begin);
    return managed.find("MSR_IA32_KERNEL_GS_BASE") == std::string::npos &&
           asm_source.find("CTX_GUEST_KGS") != std::string::npos &&
           asm_source.find("MSR_KERNEL_GS_BASE") != std::string::npos;
  }());
  constexpr std::array<std::uint32_t, 8> managedMsrs = {
      0xC0000100U,  // fs base
      0xC0000101U,  // gs base
      0xC0000080U,  // efer
      0x00000277U,  // pat
      0x000001D9U,  // debugctl
      0x00000174U,  // sysenter cs
      0x00000175U,  // sysenter esp
      0x00000176U,  // sysenter eip
  };
  MsrBitmapModel managedBitmap;
  bool managedConfigured = true;
  for (const std::uint32_t msr : managedMsrs) {
    managedConfigured = managedBitmap.Set(msr, true) && managedConfigured;
  }
  const bool managedReadsRemainNative = std::all_of(
      managedMsrs.begin(), managedMsrs.end(), [&](const std::uint32_t msr) {
        return !managedBitmap.IsSet(msr, false);
      });
  const bool managedWritesTrap = std::all_of(
      managedMsrs.begin(), managedMsrs.end(), [&](const std::uint32_t msr) {
        return managedBitmap.IsSet(msr, true);
      });
  Check(state, "MSR bitmap model leaves managed RDMSR native",
        managedConfigured && managedReadsRemainNative);
  Check(state, "MSR bitmap model retains managed WRMSR exits",
        managedConfigured && managedWritesTrap);
  struct MsrBitmapExpectation {
    std::uint32_t msr;
    std::size_t readOffset;
    std::uint8_t readMask;
    std::size_t writeOffset;
    std::uint8_t writeMask;
  };
  constexpr std::array<MsrBitmapExpectation, 8> bitmapExpectations = {{
      {0xC0000100U, 0x420, 0x01, 0xC20, 0x01},
      {0xC0000101U, 0x420, 0x02, 0xC20, 0x02},
      {0xC0000080U, 0x410, 0x01, 0xC10, 0x01},
      {0x00000277U, 0x04E, 0x80, 0x84E, 0x80},
      {0x000001D9U, 0x03B, 0x02, 0x83B, 0x02},
      {0x00000174U, 0x02E, 0x10, 0x82E, 0x10},
      {0x00000175U, 0x02E, 0x20, 0x82E, 0x20},
      {0x00000176U, 0x02E, 0x40, 0x82E, 0x40},
  }};
  const bool bitmapLayoutMatches = std::all_of(
      bitmapExpectations.begin(), bitmapExpectations.end(),
      [&](const MsrBitmapExpectation& expected) {
        return (managedBitmap.bytes[expected.readOffset] &
                expected.readMask) == 0 &&
               (managedBitmap.bytes[expected.writeOffset] &
                expected.writeMask) != 0;
      });
  Check(state, "MSR bitmap model uses the four Intel regions",
        bitmapLayoutMatches);
  constexpr std::array<std::uint32_t, 11> hiddenMsrs = {
      0x000001C4U,  // xfd
      0x000001C5U,  // xfd err
      0x00000560U,  // rtit output base
      0x00000570U,  // rtit ctl
      0x0000058FU,  // rtit window end
      0x00000DA0U,  // xss
      0x000006A0U,  // u cet
      0x000006A7U,  // pl3 ssp
      0x000006A2U,  // s cet
      0x000006A4U,  // pl0 ssp
      0x000006A8U,  // interrupt ssp table
  };
  MsrBitmapModel hiddenBitmap;
  bool hiddenConfigured = true;
  for (const std::uint32_t msr : hiddenMsrs) {
    hiddenConfigured = hiddenBitmap.Set(msr, false) && hiddenConfigured;
    hiddenConfigured = hiddenBitmap.Set(msr, true) && hiddenConfigured;
  }
  const bool hiddenReadsTrap = std::all_of(
      hiddenMsrs.begin(), hiddenMsrs.end(), [&](const std::uint32_t msr) {
        return hiddenBitmap.IsSet(msr, false);
      });
  const bool hiddenWritesTrap = std::all_of(
      hiddenMsrs.begin(), hiddenMsrs.end(), [&](const std::uint32_t msr) {
        return hiddenBitmap.IsSet(msr, true);
      });
  Check(state, "MSR bitmap model keeps hidden MSRs bidirectionally trapped",
        hiddenConfigured && hiddenReadsTrap && hiddenWritesTrap);
  Check(state, "MSR bitmap model rejects out-of-range indices",
        !managedBitmap.Set(0x00002000U, false) &&
            !managedBitmap.Set(0xC0002000U, true));
  const std::size_t managed_array_begin = msr_bitmap_source.find(
      "constexpr u32 vmxManagedWriteMsrs[]");
  const std::size_t managed_array_end =
      managed_array_begin == std::string::npos
          ? std::string::npos
          : msr_bitmap_source.find("// XFD is not part", managed_array_begin);
  const std::string managed_policy_source =
      managed_array_begin != std::string::npos &&
              managed_array_end > managed_array_begin
          ? msr_bitmap_source.substr(managed_array_begin,
                                     managed_array_end - managed_array_begin)
          : std::string{};
  Check(state, "source keeps managed MSR reads pass-through",
        !managed_policy_source.empty() &&
            managed_policy_source.find("setBit(msr, true)") !=
                std::string::npos &&
            managed_policy_source.find("setBit(msr, false)") ==
                std::string::npos &&
            managed_policy_source.find("MSR_IA32_KERNEL_GS_BASE") ==
                std::string::npos);
  Check(state, "source encodes all four MSR bitmap regions",
        msr_bitmap_source.find("base = write ? 0x800U : 0x000U") !=
                std::string::npos &&
            msr_bitmap_source.find("base = write ? 0xC00U : 0x400U") !=
                std::string::npos &&
            msr_bitmap_source.find("msr -= 0xC0000000U") !=
                std::string::npos);
  CheckPattern(state, "guest CPUID hides unvirtualized XCR1", vmm,
               R"(leaf\s*==\s*0xD\s*&&\s*subleaf\s*==\s*1[\s\S]{0,320}CPUID_D1_XGETBV1[\s\S]{0,180}CPUID_D1_XFD)");
  CheckPattern(state, "FRED uses CPUID subleaf one", vmm,
               R"(localCpuid7MaxSubleaf\s*=\s*static_cast<u32>\(localCpuid\[0\]\)[\s\S]{0,500}__cpuidex\(localCpuid, 7, 1\)[\s\S]{0,180}CPUID_7_1_EAX_FRED)");
  const std::size_t vmexit_trace =
      exit_source.find("WriteHvTrace(vcpu, cpuId, HvTraceEventVmexitEntry");
  const std::size_t vmexit_first_vmcs_write =
      exit_source.find("VmWriteChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD");
  const std::size_t vmexit_reason_snapshot =
      exit_source.find("vcpu->LastExitReasonRaw = rawExitReason");
  Check(state, "VM-exit flight recorder captures every entry",
        vmexit_trace != std::string::npos &&
            vmexit_first_vmcs_write != std::string::npos &&
            vmexit_reason_snapshot != std::string::npos &&
            vmexit_reason_snapshot < vmexit_trace &&
            vmexit_trace < vmexit_first_vmcs_write);
  const std::array<std::string_view, 7> event_read_tokens = {
      "VmReadChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD,",
      "VmReadChecked(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE,",
      "VmReadChecked(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH,",
      "VmReadChecked(VM_EXIT_INTR_INFO,",
      "VmReadChecked(VM_EXIT_INTR_ERROR_CODE,",
      "VmReadChecked(VM_EXIT_IDT_VECTORING_INFO,",
      "VmReadChecked(VM_EXIT_IDT_VECTORING_ERROR_CODE,",
  };
  std::array<std::size_t, event_read_tokens.size()> event_read_positions{};
  bool event_reads_present = true;
  for (std::size_t i = 0; i < event_read_tokens.size(); ++i) {
    event_read_positions[i] = exit_source.find(event_read_tokens[i]);
    if (event_read_positions[i] == std::string::npos) {
      event_reads_present = false;
      break;
    }
  }
  const std::size_t event_snapshot_commit =
      exit_source.find("vcpu->LastVmExitIntrInfo");
  const std::size_t event_read_failure = FirstTokenPosition(
      exit_source,
      {"!VmReadChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD,",
       "!VmReadChecked(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE,",
       "!VmReadChecked(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH,",
       "!VmReadChecked(VM_EXIT_INTR_INFO,",
       "!VmReadChecked(VM_EXIT_INTR_ERROR_CODE,",
       "!VmReadChecked(VM_EXIT_IDT_VECTORING_INFO,",
       "!VmReadChecked(VM_EXIT_IDT_VECTORING_ERROR_CODE,"});
  const std::size_t guest_rip_read =
      exit_source.find("VmReadChecked(GUEST_RIP,");
  const std::size_t entry_info_snapshot =
      exit_source.find("LastVmEntryIntrInfo");
  const std::size_t entry_error_snapshot =
      exit_source.find("LastVmEntryIntrError");
  const std::size_t entry_length_snapshot =
      exit_source.find("LastVmEntryInstructionLength");
  const std::size_t event_reads_last =
      event_reads_present
          ? *std::max_element(event_read_positions.begin(),
                              event_read_positions.end())
          : std::string::npos;
  // The handler may accumulate VMREAD results in a boolean instead of
  // spelling one large `!VmReadChecked(...) || ...` expression. Anchor the
  // fail-stop check at that aggregate guard when present, while retaining the
  // direct-expression fallback for older implementations.
  const std::size_t event_state_guard =
      event_reads_present
          ? exit_source.find("if (!eventStateValid)", event_reads_last)
          : std::string::npos;
  const bool aggregate_event_failure =
      event_state_guard != std::string::npos &&
      std::all_of(event_read_positions.begin(), event_read_positions.end(),
                  [&](const std::size_t position) {
                    return position < event_state_guard;
                  });
  Check(state, "VM-exit retains VM-entry interruption fields before clearing",
        event_reads_present && vmexit_first_vmcs_write != std::string::npos &&
            entry_info_snapshot > event_reads_last &&
            entry_error_snapshot > event_reads_last &&
            entry_length_snapshot > event_reads_last &&
            entry_info_snapshot < vmexit_first_vmcs_write &&
            entry_error_snapshot < vmexit_first_vmcs_write &&
            entry_length_snapshot < vmexit_first_vmcs_write);
  Check(state, "VM-exit snapshots interruption fields before VMCS writes",
        event_reads_present && vmexit_first_vmcs_write != std::string::npos &&
            guest_rip_read != std::string::npos &&
            std::all_of(event_read_positions.begin(), event_read_positions.end(),
                        [&](const std::size_t position) {
                          return position < vmexit_first_vmcs_write &&
                                 position < guest_rip_read;
                        }) &&
            event_snapshot_commit > event_reads_last);
  const std::size_t vectoring_guard =
      exit_source.find("if ((idtVectoringInfo & VM_ENTRY_INTR_INFO_VALID) != 0)");
  const std::size_t vectoring_guard_end =
      vectoring_guard != std::string::npos
          ? exit_source.find("    // A VM-entry interruption field",
                             vectoring_guard)
          : std::string::npos;
  const std::string vectoring_guard_source =
      vectoring_guard != std::string::npos &&
              vectoring_guard_end > vectoring_guard
          ? exit_source.substr(vectoring_guard,
                               vectoring_guard_end - vectoring_guard)
          : std::string{};
  Check(state, "valid IDT vectoring is fail-closed before VMCS clear",
        vectoring_guard != std::string::npos &&
            vmexit_first_vmcs_write != std::string::npos &&
            vectoring_guard < vmexit_first_vmcs_write &&
            vectoring_guard_source.find("HvTraceEventFatalVmexit") !=
                std::string::npos &&
            vectoring_guard_source.find("RequestFatalStop(Ctx)") !=
                std::string::npos &&
            vectoring_guard_source.find("LastExitAction = kExitActionHalt") !=
                std::string::npos &&
            vectoring_guard_source.find(
                "FailFirstExitProbeAtFatalBoundary(vcpu, cpuId)") !=
                std::string::npos &&
            vectoring_guard_source.find("return;") != std::string::npos);
  Check(state, "IDT vectoring guard does not clear the event snapshot",
        vectoring_guard != std::string::npos &&
            vectoring_guard_source.find(
                "LastEventSnapshotValid, 0") == std::string::npos &&
            vectoring_guard_source.find("VmWriteChecked") ==
                std::string::npos);
  const std::size_t inject_exception_begin =
      vmm.find("static void InjectGuestException(GuestContext* c");
  const std::size_t inject_exception_end =
      inject_exception_begin == std::string::npos
          ? std::string::npos
          : vmm.find("// handle hypervisor unload requests",
                     inject_exception_begin);
  const std::string inject_exception_source =
      inject_exception_begin != std::string::npos &&
              inject_exception_end > inject_exception_begin
          ? vmm.substr(inject_exception_begin,
                       inject_exception_end - inject_exception_begin)
          : std::string{};
  // valid=0 leaves the vector bits undefined, so the injection guard must not
  // inspect their stale low bytes as if they described a pending event
  constexpr std::uint32_t kIntrInfoValid = 1U << 31;
  const auto eventMetadataWouldHalt = [](std::uint32_t entry,
                                         std::uint32_t exit,
                                         std::uint32_t vectoring,
                                         std::uint32_t pendingDebug) {
    constexpr std::uint32_t kIntrInfoValidMask = 1U << 31;
    return (entry & kIntrInfoValidMask) != 0 ||
           (exit & kIntrInfoValidMask) != 0 ||
           (vectoring & kIntrInfoValidMask) != 0 || pendingDebug != 0;
  };
  const bool staleVectorBytesIgnored =
      !eventMetadataWouldHalt(0x000000FFU, 0, 0, 0) &&
      !eventMetadataWouldHalt(0, 0x000000FFU, 0, 0) &&
      !eventMetadataWouldHalt(0, 0, 0x000000FFU, 0);
  Check(state, "undefined event vector bytes do not halt injection",
        !inject_exception_source.empty() &&
            inject_exception_source.find("0xFFU") == std::string::npos &&
            inject_exception_source.find("pendingVector") ==
                std::string::npos &&
            inject_exception_source.find("vectoringVector") ==
                std::string::npos && staleVectorBytesIgnored);
  Check(state, "valid event vectors still halt injection",
        eventMetadataWouldHalt(kIntrInfoValid | 0x000000FFU, 0, 0, 0) &&
            eventMetadataWouldHalt(0, kIntrInfoValid | 0x000000FFU, 0, 0) &&
            eventMetadataWouldHalt(0, 0, kIntrInfoValid | 0x000000FFU, 0));
  const std::size_t event_failure_start =
      event_state_guard != std::string::npos ? event_state_guard
                                             : event_read_failure;
  const std::string event_failure_source =
      event_failure_start != std::string::npos
          ? exit_source.substr(event_failure_start, 900)
          : std::string{};
  Check(state, "VM-exit event read failure is fail-stop",
        (aggregate_event_failure || event_read_failure != std::string::npos) &&
            !event_failure_source.empty() &&
            event_failure_source.find("AbortVm = 0") != std::string::npos &&
            event_failure_source.find("HaltVm = 1") != std::string::npos);
  CheckPattern(state, "diagnostic launch log includes VMCS state", vmm,
               R"(VMCS ready; entering VMLAUNCH[\s\S]{0,240}revision=0x%X)");
  const std::size_t exit_intr_snapshot =
      exit_source.find("LastVmExitIntrInfo = static_cast<u32>(exitIntrInfo)");
  const std::size_t guest_cr0_snapshot =
      exit_source.find("LastGuestCr0 = Ctx->GuestCr0");
  const std::size_t guest_tr_snapshot =
      exit_source.find("LastGuestTr = guestTr");
  Check(state, "diagnostic trace captures guest transition state",
        exit_intr_snapshot != std::string::npos &&
            guest_cr0_snapshot > exit_intr_snapshot &&
            guest_tr_snapshot > guest_cr0_snapshot);
  const std::string launch_marker_source = SliceSource(
      vmm, "extern \"C\" bool MarkCurrentVcpuLaunched()",
      "extern \"C\" void MarkCurrentVcpuParked()");
  Check(state, "launch state is published by the pre-entry marker",
        !launch_marker_source.empty() &&
            launch_marker_source.find("return false") != std::string::npos &&
            launch_marker_source.find("return true") != std::string::npos &&
            launch_marker_source.find("VcpuLaunched") != std::string::npos);
  Check(state, "launch marker uses VMX stage and atomic VmxOn publication",
        !launch_marker_source.empty() &&
            launch_marker_source.find(
                "InterlockedCompareExchange(&vcpu->LaunchStage, 5, 4)") !=
                std::string::npos &&
            launch_marker_source.find("InterlockedCompareExchange(&vcpu->State") !=
                std::string::npos &&
            launch_marker_source.find("VcpuLaunched") != std::string::npos &&
            launch_marker_source.find("VcpuVmxOn") != std::string::npos);
  Check(state, "launch marker does not inspect guest CR4.VMXE",
        !launch_marker_source.empty() &&
            launch_marker_source.find("__readcr4()") == std::string::npos);
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
  const std::string thunk_source =
      thunk_begin != std::string::npos && thunk_end > thunk_begin
          ? asm_source.substr(thunk_begin, thunk_end - thunk_begin)
          : std::string{};
  Check(state, "guest launch returns without leaving VMX",
        !thunk_source.empty() && thunk_source.find("ret") != std::string::npos &&
            thunk_source.find("vmcall") == std::string::npos &&
            thunk_source.find("call ") == std::string::npos &&
            thunk_source.find("g_HvLaunchGuestStarted") == std::string::npos);
  const std::size_t first_exit_counter = exit_source.find("if (exitCount == 1)");
  const std::size_t first_exit_started =
      exit_source.find("InterlockedIncrement(&g_HvLaunchGuestStarted)",
                        first_exit_counter);
  const std::size_t first_exit_proof =
      exit_source.find("InterlockedIncrement(&g_HvLaunchFirstVmExitEntered)",
                        first_exit_started);
  Check(state, "first guest exit publishes launch telemetry",
        first_exit_counter != std::string::npos &&
            first_exit_started > first_exit_counter &&
            first_exit_proof > first_exit_started);
  Check(state, "guest start restores the complete launch frame",
        thunk_begin != std::string::npos && thunk_end > thunk_begin &&
            asm_source.substr(thunk_begin, thunk_end - thunk_begin).find(
                "movdqu xmm15, xmmword ptr [rsp + 0B0h]") !=
                std::string::npos &&
            asm_source.substr(thunk_begin, thunk_end - thunk_begin).find(
                "ldmxcsr [rsp + 0C0h]") != std::string::npos &&
            asm_source.substr(thunk_begin, thunk_end - thunk_begin).find(
                "pop r15") != std::string::npos &&
            asm_source.substr(thunk_begin, thunk_end - thunk_begin).find(
                "popfq") != std::string::npos &&
            asm_source.substr(thunk_begin, thunk_end - thunk_begin).find(
                "add rsp, 08h") != std::string::npos &&
            asm_source.substr(thunk_begin, thunk_end - thunk_begin).find(
                "bt qword ptr [rsp], 9") != std::string::npos &&
            asm_source.substr(thunk_begin, thunk_end - thunk_begin).find(
                "btr qword ptr [rsp], 9") != std::string::npos &&
            asm_source.substr(thunk_begin, thunk_end - thunk_begin).find(
                "sti") != std::string::npos);
  Check(state, "launch recorder covers the hardware transition",
        asm_source.find("g_HvLaunchGuestEntered") != std::string::npos &&
            asm_source.find("g_HvLaunchVmlaunchIssued") != std::string::npos &&
            asm_source.find("g_HvLaunchVmlaunchReturned") != std::string::npos &&
            asm_source.find("g_HvLaunchVmExitAsmReached") != std::string::npos);
  const std::size_t wrapper_begin = asm_source.find("EnableHvCallback proc");
  const std::size_t wrapper_end = asm_source.find("EnableHvCallback endp", wrapper_begin);
  Check(state, "IPI wrapper preserves nonvolatile XMM registers",
        wrapper_begin != std::string::npos && wrapper_end > wrapper_begin &&
            asm_source.substr(wrapper_begin, wrapper_end - wrapper_begin).find(
                "movdqu xmmword ptr [rsp + 020h], xmm6") != std::string::npos &&
            asm_source.substr(wrapper_begin, wrapper_end - wrapper_begin).find(
                "movdqu xmm6, xmmword ptr [rsp + 020h]") != std::string::npos);
  const std::string wrapper_source =
      wrapper_begin != std::string::npos && wrapper_end > wrapper_begin
          ? asm_source.substr(wrapper_begin, wrapper_end - wrapper_begin)
          : std::string{};
  const std::size_t launch_marker_call =
      wrapper_source.find("call MarkCurrentVcpuLaunched");
  const std::size_t launch_guest_call =
      wrapper_source.find("call HvLaunchGuest");
  const std::size_t launch_begin = asm_source.find("HvLaunchGuest proc frame");
  const std::size_t launch_end = asm_source.find("HvLaunchGuest endp", launch_begin);
  Check(state, "IPI wrapper publishes state before VMLAUNCH",
        launch_marker_call != std::string::npos &&
            launch_guest_call != std::string::npos &&
            launch_marker_call < launch_guest_call &&
            wrapper_source.find("pushfq") != std::string::npos &&
            wrapper_source.find("push rax") != std::string::npos &&
            wrapper_source.find("push r15") != std::string::npos);
  CheckPattern(state, "launch reserves teardown stack space", asm_source,
               R"(HvLaunchGuest proc[\s\S]{0,700}sub rsp, 200h[\s\S]{0,500}vmlaunch[\s\S]{0,300}add rsp, 200h)");
  Check(state, "guest launch RSP uses the complete save frame",
        wrapper_source.find("lea rdx, [rsp]") != std::string::npos &&
            asm_source.substr(launch_begin == std::string::npos ? 0 : launch_begin,
                              launch_end > launch_begin ? launch_end - launch_begin : 0)
                    .find("VMCS_GUEST_RSP") == std::string::npos);
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
  Check(state, "launch uses the HyperDbg full-register frame",
        wrapper_source.find("push 0") != std::string::npos &&
            wrapper_source.find("pushfq") != std::string::npos &&
            wrapper_source.find("push r15") != std::string::npos &&
            wrapper_source.find("sub rsp, 100h") != std::string::npos);
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
  const std::size_t staged_target_failure = launch_start_source.find(
      "if (!NT_SUCCESS(targetStatus))",
      launch_start_source.find(
          "launching processors through staged target DPCs"));
  const std::size_t staged_failure_diagnostics =
      launch_start_source.find("PrintLaunchResult(i, g_VcpuData[i])",
                               staged_target_failure);
  const std::size_t staged_failure_stop = launch_start_source.find(
      "StopHypervisorInternal(true)", staged_target_failure);
  Check(state, "staged failure prints diagnostics before VMX rollback",
        staged_target_failure != std::string::npos &&
            staged_failure_diagnostics > staged_target_failure &&
            staged_failure_stop > staged_failure_diagnostics);
  const std::size_t staged_launch_loop = launch_start_source.find(
      "for (u32 i = 0; i < g_ProcessorCount; ++i)",
      launch_start_source.find("launching processors through staged target DPCs"));
  const std::size_t staged_detail_gate = launch_start_source.find(
      "LaunchResultNeedsDetail(i, g_VcpuData[i])", staged_launch_loop);
  const std::size_t staged_aggregate = launch_start_source.find(
      "[HV] staged launch completed:", staged_launch_loop);
  Check(state, "staged launch filters successful per CPU output",
        staged_launch_loop != std::string::npos &&
            staged_detail_gate > staged_launch_loop &&
            staged_aggregate > staged_detail_gate);
  const std::size_t probe_broadcast = launch_start_source.find(
      "QueueTargetOperation(i, TargetOperationProbe)");
  const std::size_t launch_orchestration = launch_start_source.find(
      "const u32 expected = ExpectedLaunchProcessorCount()");
  Check(state, "startup completes the no-VMX probe before launch orchestration",
        probe_broadcast != std::string::npos &&
            launch_orchestration != std::string::npos &&
            probe_broadcast < launch_orchestration);
  Check(state, "startup releases the coordinator after staged launch",
        launch_orchestration != std::string::npos &&
            launch_start_source.find("reservedProcessor") !=
                std::string::npos &&
            launch_start_source.find("BindCoordinatorToProcessor") !=
                std::string::npos &&
            launch_start_source.find("InterlockedExchange(&g_HvLifecycle, kHvLifecycleRunning)") !=
                std::string::npos &&
            launch_start_source.find("ReleaseCoordinatorAffinity(&coordinatorAffinity") !=
                std::string::npos &&
            launch_start_source.find("coordinator CPU %u remains native for KD") ==
                std::string::npos);
  const std::size_t startup_running_publish = launch_start_source.find(
      "InterlockedExchange(&g_HvLifecycle, kHvLifecycleRunning)");
  const std::size_t startup_coordinator_release = launch_start_source.find(
      "ReleaseCoordinatorAffinity(&coordinatorAffinity", startup_running_publish);
  const std::size_t startup_success_return =
      launch_start_source.rfind("return STATUS_SUCCESS");
  Check(state, "startup orders coordinator release after lifecycle publication",
        startup_running_publish != std::string::npos &&
            startup_coordinator_release > startup_running_publish &&
            startup_success_return > startup_coordinator_release);
  const std::size_t launch_callbacks_begin = vmm.find(
      "extern \"C\" ULONG_PTR ProbeIpiRendezvousCallback");
  const std::size_t launch_callbacks_end = vmm.find(
      "extern \"C\" ULONG PrepareHvCallback", launch_callbacks_begin);
  const std::string launch_callbacks_source =
      launch_callbacks_begin != std::string::npos &&
              launch_callbacks_end != std::string::npos
          ? vmm.substr(launch_callbacks_begin,
                       launch_callbacks_end - launch_callbacks_begin)
          : std::string{};
  Check(state, "launch boundary callbacks avoid unsafe target-level services",
        !launch_callbacks_source.empty() &&
            launch_callbacks_source.find("DbgPrint") == std::string::npos &&
            launch_callbacks_source.find("ExAllocate") == std::string::npos &&
            launch_callbacks_source.find("KeAcquire") == std::string::npos);
  Check(state, "startup collapses per-CPU allocation debugger output",
        vmm.find("[HV] CPU %u allocations:") == std::string::npos &&
            vmm.find("[HV] allocations complete: processors=%u") !=
                std::string::npos);
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
  const std::size_t teardown_vmxoff = normal_teardown_source.find("vmxoff");
  const std::size_t teardown_guest_xrstors =
      normal_teardown_source.find("xrstors64 [r10]");
  const std::size_t teardown_guest_xss =
      normal_teardown_source.find("CTX_GUEST_XSS", teardown_guest_xrstors);
  const std::size_t teardown_guest_xcr0 =
      normal_teardown_source.find("CTX_GUEST_XCR0", teardown_guest_xss);
  const std::size_t teardown_guest_done =
      normal_teardown_source.find("restoreGuestStateDone:");
  const std::size_t teardown_guest_cr3 =
      normal_teardown_source.find("mov cr3");
  Check(state, "native teardown restores guest XSTATE before CR3 handoff",
        teardown_vmxoff != std::string::npos &&
            teardown_guest_xrstors > teardown_vmxoff &&
            teardown_guest_xss > teardown_guest_xrstors &&
            teardown_guest_xcr0 > teardown_guest_xss &&
            teardown_guest_done > teardown_guest_xcr0 &&
            teardown_guest_cr3 > teardown_guest_done);
  Check(state, "native teardown restores host state before guest mask",
        host_xcr0_xsetbv != std::string::npos &&
            teardown_guest_xrstors != std::string::npos &&
            host_xcr0_xsetbv < teardown_guest_xrstors &&
            teardown_marker != std::string::npos &&
            host_xcr0_xsetbv < teardown_marker);
  Check(state, "native teardown keeps guest XSS after guest state",
        teardown_guest_xss != std::string::npos &&
            teardown_guest_xcr0 != std::string::npos &&
            teardown_guest_done != std::string::npos &&
            teardown_guest_xss < teardown_guest_xcr0 &&
            teardown_guest_xcr0 < teardown_guest_done);
  const std::size_t teardown_cr3_call =
      normal_teardown_source.find("call ", teardown_guest_cr3);
  Check(state, "native teardown makes no C++ call after guest CR3",
        teardown_guest_cr3 != std::string::npos &&
            (teardown_cr3_call == std::string::npos ||
             normal_teardown_source.find("iretq", teardown_guest_cr3) <
                 teardown_cr3_call));
  const std::string launch_abort_source = SliceSource(
      vmm, "extern \"C\" void AbortHvLaunch(u64 Rflags)",
      "// ==============================================================================\n// Stop Logic");
  const std::size_t abort_vmxon_state =
      launch_abort_source.find("state == VcpuVmxOn");
  const std::size_t abort_vmxoff = launch_abort_source.find("HvVmxOff(");
  const std::size_t abort_host_xss = launch_abort_source.find(
      "WriteMsrSafe(MSR_IA32_XSS, vcpu->HostXss)");
  Check(state, "VmxOn rollback restores host XSS after VMXOFF",
        !launch_abort_source.empty() &&
            abort_vmxon_state != std::string::npos &&
            abort_vmxoff > abort_vmxon_state &&
            abort_host_xss > abort_vmxoff);
  CheckPattern(state, "stop claims ownership with a lifecycle CAS", vmm,
               R"(StopHypervisorInternal\([\s\S]{0,500}InterlockedCompareExchange\(&g_HvLifecycle[\s\S]{0,220}kHvLifecycleStopping)");
  CheckPattern(state, "stop uses targeted workers with deadlines", vmm,
               R"(StopHypervisorInternal\([\s\S]{0,5000}QueueTargetOperation\(i, TargetOperationStop\)[\s\S]{0,2500}WaitTargetOperation)");
  CheckPattern(state, "unresolved target work enters quarantine", vmm,
               R"(HasUnresolvedTargetWork\(\)[\s\S]{0,600}PinImageForParkedCpu\(\)[\s\S]{0,300}kHvLifecycleQuarantined)");
  CheckPattern(state, "invalid target worker publishes terminal failure", vmm,
               R"(if \(!g_VcpuData \|\| work->ProcessorIndex >= g_ProcessorCount\)[\s\S]{0,260}STATUS_INVALID_DEVICE_STATE[\s\S]{0,220}TargetWorkFailed)");
  CheckPattern(state, "completed target work ignores stale timeout", vmm,
               R"(HasUnresolvedTargetWork\(\)[\s\S]{0,500}ThreadHandle != nullptr[\s\S]{0,120}return true)");
  CheckPattern(state, "quarantined DriverEntry remains resident", main,
               R"(IsHypervisorQuarantined\(\)[\s\S]{0,260}DriverUnload\s*=\s*nullptr[\s\S]{0,260}return STATUS_SUCCESS)");
  const std::size_t driver_unload_begin = main.find("void DriverUnload(");
  const std::size_t driver_unload_end = main.find(
      "extern \"C\" NTSTATUS DriverEntry", driver_unload_begin);
  const std::string driver_unload_source =
      driver_unload_begin != std::string::npos &&
              driver_unload_end > driver_unload_begin
          ? main.substr(driver_unload_begin,
                        driver_unload_end - driver_unload_begin)
          : std::string{};
  const std::size_t unload_callback =
      driver_unload_source.find("UnregisterSecondaryDumpCallback();");
  Check(state, "DriverUnload requires a complete non-quarantined stop",
        driver_unload_source.find("StopHypervisor();") != std::string::npos &&
            driver_unload_source.find(
                "if (!IsHypervisorStopComplete() || IsHypervisorQuarantined())") !=
                std::string::npos &&
            unload_callback != std::string::npos &&
            driver_unload_source.find("return STATUS") == std::string::npos &&
            driver_unload_source.find("return;") == std::string::npos);
  CheckPattern(state, "DriverUnload rechecks after callback removal", main,
               R"(UnregisterSecondaryDumpCallback\(\);[\s\S]{0,500}if\s*\(\s*!IsHypervisorStopComplete\(\)\s*\|\|\s*IsHypervisorQuarantined\(\)\s*\)[\s\S]{0,300}KeBugCheckEx)");
  CheckPattern(state, "start rollback gates callback and return", main,
               R"(StopHypervisor\(\);[\s\S]{0,320}if\s*\(IsHypervisorQuarantined\(\)\)[\s\S]{0,300}if\s*\(!IsHypervisorStopComplete\(\)\)[\s\S]{0,300}KeBugCheckEx[\s\S]{0,260}UnregisterSecondaryDumpCallback\(\))");
  Check(state, "unload callback state has a private fatal marker",
        main.find("kHvFatalUnloadCallbackState = 0x43425354ULL") !=
            std::string::npos);
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
  const std::string vmx_gate_source =
      SliceSource(main, "bool IsVmxSupported()", "void DriverUnload(");
  const std::size_t vendor_token =
      vmx_gate_source.find("GenuineIntel");
  const std::size_t vendor_reject =
      vendor_token == std::string::npos
          ? std::string::npos
          : vmx_gate_source.find("RejectVmx", vendor_token);
  const std::size_t vmx_basic_read =
      vmx_gate_source.find("MSR_IA32_VMX_BASIC");
  Check(state, "VMX gate rejects non-Intel vendors before VMX MSR access",
        !vmx_gate_source.empty() && vendor_token != std::string::npos &&
            vendor_reject != std::string::npos && vmx_basic_read != std::string::npos &&
            vendor_reject < vmx_basic_read &&
            (vmx_gate_source.find("0x756E6547") != std::string::npos ||
             vmx_gate_source.find("0x49656E69") != std::string::npos ||
             vmx_gate_source.find("0x6C65746E") != std::string::npos));
  CheckPattern(state, "XCR0 must be a CPUID-supported subset", vmm,
               R"(hostXcr0\s*&\s*~supportedXcr0)");
  CheckPattern(state, "active unsupported XSS fails before VMXON", vmm,
               R"(hostXss\s*&\s*~IA32_XSS_PRESERVABLE_MASK)");
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
  const std::string contract_tag = ExtractDriverContractTag(main);
  const bool tag_found = !contract_tag.empty();
  unsigned contract_version = 0;
  if (!contract_tag.empty()) {
    std::smatch version_match;
    if (std::regex_search(contract_tag, version_match,
                          std::regex(R"(XSTATE-V([0-9]+)-)"))) {
      try {
        contract_version = static_cast<unsigned>(
            std::stoul(version_match[1].str()));
      } catch (...) {
        contract_version = 0;
      }
    }
  }
  const std::array<std::string_view, 8> required_contract_tokens = {
      "TRIPLEFAULT", "FAILSTOP", "VMEXIT", "FLIGHTREC", "XSS-PRESERVE",
      "FRED-SUBLEAF1", "CET-HIDDEN", "CR3-FLIGHTREC",
  };
  bool contract_tokens_present = tag_found;
  for (const std::string_view token : required_contract_tokens) {
    contract_tokens_present =
        contract_tokens_present && contract_tag.find(token) != std::string::npos;
  }
  Check(state, "driver contract tag identifies a current capability revision",
        tag_found && contract_version >= 30 && contract_tokens_present &&
            contract_tag.find("VMWRITE-FIELD-VALUE") != std::string::npos &&
            contract_tag.find("RAW-VALUE-FIELD") != std::string::npos &&
            contract_tag.find("CR4-SHADOW") != std::string::npos &&
            contract_tag.find("FIRSTEXIT-CPUID-PROBE") !=
                std::string::npos);
  CheckPattern(state, "CR3 PCID no-flush is accepted", vmm,
               R"(noFlushMask\s*=\s*pcide\s*\?\s*\(1ULL\s*<<\s*63\))");
  CheckPattern(state, "NormalizeCr3 clears the no-flush hint", vmm,
               R"(static __forceinline u64 NormalizeCr3[\s\S]{0,260}value\s*&\s*~\(1ULL\s*<<\s*63\))");
  CheckPattern(state, "CR3 no-flush is normalized before VMCS write", vmm,
               R"(const u64 normalizedCr3\s*=\s*NormalizeCr3\(value,\s*guestCr4\)[\s\S]{0,180}VmWriteChecked\(GUEST_CR3,\s*normalizedCr3\))");
  Check(state, "initial VMCS CR3 is normalized",
        (vmm.find("const u64 guestCr3 = NormalizeCr3(__readcr3(), guestCr4);") !=
                 std::string::npos ||
         vmm.find("const u64 rawGuestCr3 = __readcr3();") !=
                 std::string::npos) &&
            vmm.find("IsValidArchitecturalCr3(guestCr3, guestCr4)") !=
                std::string::npos &&
            vmm.find("VmWriteChecked(GUEST_CR3, guestCr3)") !=
                std::string::npos);
  const std::string setup_vmcs_source =
      SliceSource(vmm, "bool SetupVmcs(", "static bool LaunchResultNeedsDetail");
  Check(state, "launch CR3 values are recorded before VMCS writes",
        !setup_vmcs_source.empty() &&
            setup_vmcs_source.find("const u64 rawHostCr3 = Vcpu->HostCr3") !=
                std::string::npos &&
            setup_vmcs_source.find("const u64 rawGuestCr3 = __readcr3()") !=
                std::string::npos &&
            setup_vmcs_source.find("LaunchRawGuestCr3") != std::string::npos &&
            setup_vmcs_source.find("HvTraceEventCr3LaunchContract") !=
                std::string::npos &&
            setup_vmcs_source.find("HvTraceEventCr3LaunchContract") <
                setup_vmcs_source.find("VmWriteChecked(GUEST_CR3"));
  Check(state, "launch CR3 metadata preserves PCID and no-flush state",
        vmm.find("PackLaunchCr3Metadata") != std::string::npos &&
            vmm.find("kGuestPcideShift = 32") != std::string::npos &&
            vmm.find("kHostPcideShift = 33") != std::string::npos &&
            vmm.find("kGuestNoFlushShift = 34") != std::string::npos &&
            vmm.find("kHostNoFlushShift = 35") != std::string::npos);
  Check(state, "crash snapshot exports launch CR3 values",
        !fatal_snapshot_layout.empty() &&
            TokensInOrder(fatal_snapshot_layout,
                          {"LaunchRawGuestCr3", "LaunchGuestCr3",
                           "LaunchRawHostCr3", "LaunchHostCr3",
                           "LaunchCr3Metadata"}) &&
            !crash_blob_copy.empty() &&
            TokensInOrder(crash_blob_copy,
                          {"out.LaunchRawGuestCr3", "out.LaunchGuestCr3",
                           "out.LaunchRawHostCr3", "out.LaunchHostCr3",
                           "out.LaunchCr3Metadata"}));
  Check(state, "VMCS CET requires CR0 write protection",
        vmm.find("kCr0WriteProtect = 1ULL << 16") != std::string::npos &&
            vmm.find("hostCetWriteProtectValid") != std::string::npos &&
            vmm.find("guestCetWriteProtectValid") != std::string::npos &&
            vmm.find("VMCS setup rejected CET without CR0.WP") !=
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
  Check(state, "VMCS CR4 mask traps unsupported FRED",
        vmm.find("GetCr4GuestHostMask") != std::string::npos &&
            vmm.find("CR4_OSXSAVE") != std::string::npos &&
            vmm.find("CR4_FRED") != std::string::npos);
  Check(state, "VMCS CR4 mask traps unsaved PKRU",
        vmm.find("g_XstateMode == XstateSaveFxsave") != std::string::npos &&
            vmm.find("g_HostXcr0Mask & XCR0_PKRU") != std::string::npos &&
            vmm.find("? CR4_PKE") != std::string::npos);
  const std::size_t cr4_shadow_setup =
      vmm.find("const u64 cr4GuestHostMask = GetCr4GuestHostMask()");
  const std::size_t cr4_shadow_value =
      vmm.find("const u64 cr4ReadShadow = guestCr4 & cr4GuestHostMask",
               cr4_shadow_setup);
  Check(state, "CR4 read shadow stores masked guest bits",
        cr4_shadow_setup != std::string::npos &&
            cr4_shadow_value > cr4_shadow_setup);
  const std::size_t cr4_read_guest =
      vmm.find("VmReadChecked(GUEST_CR4", 0);
  const std::size_t cr4_read_mask =
      vmm.find("CONTROL_CR4_GUEST_HOST_MASK", cr4_read_guest);
  const std::size_t cr4_read_shadow =
      vmm.find("CONTROL_CR4_READ_SHADOW", cr4_read_mask);
  const std::size_t cr4_read_combine =
      vmm.find("const u64 value = (guestCr4 & ~cr4GuestHostMask) |",
               cr4_read_shadow);
  Check(state, "MOV from CR4 combines guest and shadow views",
        cr4_read_guest != std::string::npos &&
            cr4_read_mask > cr4_read_guest &&
            cr4_read_shadow > cr4_read_mask &&
            cr4_read_combine > cr4_read_shadow &&
            vmm.find("(cr4ReadShadow & cr4GuestHostMask)",
                     cr4_read_combine) != std::string::npos);
  const std::size_t cr4_write_actual =
      vmm.find("const u64 actualCr4 = requestedCr4");
  const std::size_t cr4_write_shadow =
      vmm.find("value & cr4GuestHostMask", cr4_write_actual);
  Check(state, "MOV to CR4 updates the masked shadow",
        cr4_write_actual != std::string::npos &&
            cr4_write_shadow > cr4_write_actual);
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
        vmm.find("static constexpr bool kGuestCetStateVirtualized = false") !=
                std::string::npos &&
            vmm.find("guestXssCapabilityMask") != std::string::npos &&
            vmm.find("g_SupportedXssMask") != std::string::npos &&
            vmm.find("CPUID_7_ECX_CET_SHSTK") != std::string::npos);
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
  const std::size_t d1_end =
      d1_begin == std::string::npos
          ? std::string::npos
          : vmm.find("} else if (subleafSupported && leaf == 0xD &&", d1_begin + 1);
  const std::string d1_source =
      d1_begin != std::string::npos && d1_end > d1_begin
          ? vmm.substr(d1_begin, d1_end - d1_begin)
          : std::string{};
  Check(state, "D.1 reports compacted area only when supported",
        !d1_source.empty() &&
            d1_source.find("const bool hostXsavec") != std::string::npos &&
            d1_source.find("const bool compactedSupported") !=
                std::string::npos &&
            d1_source.find("g_XsavesEnabled != 0 || hostXsavec") !=
                std::string::npos &&
            d1_source.find("guestXssCapabilityMask") != std::string::npos &&
            d1_source.find("guestXssSelection") >
                d1_source.find("guestXssCapabilityMask") &&
            d1_source.find("if (compactedSupported &&") !=
                std::string::npos &&
            d1_source.find("regs[1] = static_cast<int>(guestXsaveSize)") !=
                std::string::npos &&
            d1_source.find("regs[1] = 0") != std::string::npos &&
            d1_source.find("regs[2]") != std::string::npos &&
            d1_source.find("regs[3]") != std::string::npos);
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
  CheckPattern(state, "hidden CET_U MSRs are always intercepted", vmm,
               R"(constexpr u32 hiddenCetUserMsrs\[\]\s*=\s*\{\s*MSR_IA32_U_CET\s*,\s*MSR_IA32_PL3_SSP[\s\S]{0,220}for\s*\(u32 msr\s*:\s*hiddenCetUserMsrs\)[\s\S]{0,140}setBit\(msr\s*,\s*false\)[\s\S]{0,100}setBit\(msr\s*,\s*true\))");
  CheckPattern(state, "hidden CET_U reads return the reset view", vmm,
               R"(HandleMsrRead[\s\S]{0,9000}msrIndex\s*==\s*MSR_IA32_U_CET\s*\|\|\s*msrIndex\s*==\s*MSR_IA32_PL3_SSP[\s\S]{0,320}Ctx->Rax\s*=\s*0[\s\S]{0,80}Ctx->Rdx\s*=\s*0)");
  CheckPattern(state, "hidden CET_U writes inject general protection", vmm,
               R"(HandleMsrWrite[\s\S]{0,9000}msrIndex\s*==\s*MSR_IA32_U_CET\s*\|\|\s*msrIndex\s*==\s*MSR_IA32_PL3_SSP[\s\S]{0,320}InjectGuestException\(Ctx,\s*13,\s*true,\s*0\))");
  CheckPattern(state, "driver fatal bugcheck code is private", vmm,
               R"(kHvFatalBugCheck\s*=\s*0x48564D58UL)");
  Check(state, "driver logs avoid the DEFAULT debug component",
        main.find("DbgPrint(") == std::string::npos &&
            vmm.find("DbgPrint(") == std::string::npos &&
            main.find("DPFLTR_IHVDRIVER_ID") != std::string::npos &&
            vmm.find("DPFLTR_IHVDRIVER_ID") != std::string::npos);
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
        vmm.find("primaryMandatoryOn & ~knownPrimaryMandatoryOn") !=
                std::string::npos &&
            vmm.find("pinMandatoryOn & ~VMX_PINBASED_MANDATORY_ON") !=
                std::string::npos &&
            vmm.find("exitMandatoryOn & ~VMX_EXIT_MANDATORY_ON") !=
                std::string::npos &&
            vmm.find("entryMandatoryOn & ~VMX_ENTRY_MANDATORY_ON") !=
                std::string::npos);
  const std::size_t supported_primary =
      vmm.find("constexpr u32 supportedPrimary");
  const std::size_t unsupported_primary =
      vmm.find("constexpr u32 unsupportedPrimary", supported_primary);
  const std::size_t unsupported_path =
      vmm.find("unsupported exit path", unsupported_primary);
  const std::string supported_primary_source =
      supported_primary != std::string::npos &&
              unsupported_primary > supported_primary
          ? vmm.substr(supported_primary,
                       unsupported_primary - supported_primary)
          : std::string{};
  const std::string unsupported_primary_source =
      unsupported_primary != std::string::npos &&
              unsupported_path > unsupported_primary
          ? vmm.substr(unsupported_primary,
                       unsupported_path - unsupported_primary)
          : std::string{};
  Check(state, "CR3 load/store exits use the CR access handler",
        supported_primary != std::string::npos &&
            unsupported_primary > supported_primary &&
            supported_primary_source.find("CPU_BASED_CR3_LOAD_EXITING") !=
                std::string::npos &&
            supported_primary_source.find("CPU_BASED_CR3_STORE_EXITING") !=
                std::string::npos &&
            unsupported_path > unsupported_primary &&
            unsupported_primary_source.find("CPU_BASED_CR3_LOAD_EXITING") ==
                std::string::npos &&
            unsupported_primary_source.find("CPU_BASED_CR3_STORE_EXITING") ==
                std::string::npos &&
            vmm.find("HandleCrAccess") != std::string::npos &&
            vmm.find("accessType == 0") != std::string::npos &&
            vmm.find("case VM_EXIT_REASON_RDPMC") != std::string::npos &&
            vmm.find("case VM_EXIT_REASON_RDTSC") != std::string::npos &&
            vmm.find("VM_EXIT_REASON_CR3_LOAD") == std::string::npos &&
            vmm.find("VM_EXIT_REASON_CR3_STORE") == std::string::npos &&
            vmx.find("VM_EXIT_REASON_RDPMC                   15") !=
                std::string::npos &&
            vmx.find("VM_EXIT_REASON_RDTSC                   16") !=
                std::string::npos &&
            vmx.find("VM_EXIT_REASON_CR_ACCESS                28") !=
                std::string::npos);
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

void TestArtifact(const fs::path& root, const fs::path& driver,
                  TestState& state) {
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

  bool image_read = false;
  bool image_has_contract_tag = false;
  bool image_has_hyperdbg_vmwrite = false;
  bool image_has_reversed_vmwrite = false;
  if (file_size <= static_cast<std::uintmax_t>(
                       (std::numeric_limits<std::size_t>::max)())) {
    std::string image_bytes(static_cast<std::size_t>(file_size), '\0');
    file.clear();
    file.seekg(0, std::ios::beg);
    image_read = static_cast<bool>(file.read(
        image_bytes.data(), static_cast<std::streamsize>(image_bytes.size())));
    if (image_read) {
      std::ifstream source_file(root / "src/main.cpp", std::ios::binary);
      std::string source_text;
      if (source_file) {
        source_text.assign(std::istreambuf_iterator<char>(source_file),
                           std::istreambuf_iterator<char>());
      }
      const std::string expected_contract_tag =
          ExtractDriverContractTag(source_text);
      image_has_contract_tag =
          !expected_contract_tag.empty() &&
          (image_bytes.find(expected_contract_tag) != std::string::npos ||
           ContainsUtf16Le(image_bytes, expected_contract_tag));
       image_has_hyperdbg_vmwrite =
           ContainsBytes(image_bytes, {0x0F, 0x79, 0xD1, 0x9C, 0x58, 0xC3});
       image_has_reversed_vmwrite =
           ContainsBytes(image_bytes, {0x0F, 0x79, 0xCA, 0x9C, 0x58, 0xC3});
    }
  }
  Check(state, "SYS embeds the current VMX contract tag",
        image_read && image_has_contract_tag, driver.string());
  Check(state, "SYS embeds the HyperDbg VMWRITE wrapper",
        image_read && image_has_hyperdbg_vmwrite &&
            !image_has_reversed_vmwrite, driver.string());
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
    TestArtifact(options.root, options.driver, state);
  }
  if (options.signature) TestSignature(options.driver, options.allow_test_root, state);
  if (options.runtime) {
    TestService(options.service, options.start, options.stop, state);
  }

  std::cout << "\nDriver tests: " << state.passed << " passed, " << state.failed
            << " failed\n";
  return state.failed == 0 ? 0 : 1;
}
