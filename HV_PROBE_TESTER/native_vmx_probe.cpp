#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

constexpr std::uint32_t kProbeLeaf = 0x13371337U;
constexpr std::uint32_t kProbeSubleaf = 0x56455249U;
constexpr std::uint32_t kProbeSignatureEax = 0x48565031U;
constexpr std::uint32_t kProbeSignatureEdx = 0x564D5831U;
constexpr unsigned kProbeRounds = 4;

struct LogicalProcessor {
    WORD group;
    BYTE number;
    std::uint32_t index;
};

struct ProbeResult {
    bool ok = false;
    std::uint32_t firstVmexits = 0;
    std::uint32_t lastVmexits = 0;
    std::uint32_t eax = 0;
    std::uint32_t ebx = 0;
    std::uint32_t ecx = 0;
    std::uint32_t edx = 0;
};

std::vector<LogicalProcessor> enumerateProcessors() {
    std::vector<LogicalProcessor> processors;
    const WORD groups = GetActiveProcessorGroupCount();
    std::uint32_t globalIndex = 0;

    for (WORD group = 0; group < groups; ++group) {
        const DWORD count = GetActiveProcessorCount(group);
        for (DWORD number = 0; number < count; ++number) {
            processors.push_back(LogicalProcessor{
                group,
                static_cast<BYTE>(number),
                globalIndex++,
            });
        }
    }
    return processors;
}

bool pinCurrentThread(const LogicalProcessor& cpu) {
    if (cpu.number >= sizeof(KAFFINITY) * 8) {
        return false;
    }

    GROUP_AFFINITY affinity{};
    affinity.Group = cpu.group;
    affinity.Mask = static_cast<KAFFINITY>(1) << cpu.number;
    if (!SetThreadGroupAffinity(GetCurrentThread(), &affinity, nullptr)) {
        return false;
    }

    PROCESSOR_NUMBER current{};
    GetCurrentProcessorNumberEx(&current);
    return current.Group == cpu.group && current.Number == cpu.number;
}

ProbeResult probeCurrentProcessor(std::uint32_t expectedIndex) {
    ProbeResult result{};
    std::uint32_t previousCount = 0;

    for (unsigned round = 0; round < kProbeRounds; ++round) {
        int regs[4]{};
        __cpuidex(regs,
                  static_cast<int>(kProbeLeaf),
                  static_cast<int>(kProbeSubleaf));

        const auto eax = static_cast<std::uint32_t>(regs[0]);
        const auto ebx = static_cast<std::uint32_t>(regs[1]);
        const auto ecx = static_cast<std::uint32_t>(regs[2]);
        const auto edx = static_cast<std::uint32_t>(regs[3]);

        result.eax = eax;
        result.ebx = ebx;
        result.ecx = ecx;
        result.edx = edx;

        if (eax != kProbeSignatureEax || edx != kProbeSignatureEdx ||
            ebx != expectedIndex) {
            return result;
        }

        if (round == 0) {
            result.firstVmexits = ecx;
        } else if (ecx <= previousCount) {
            return result;
        }

        previousCount = ecx;
        result.lastVmexits = ecx;
    }

    result.ok = true;
    return result;
}

} // namespace

int main() {
    std::puts("KNHV VMX non-root self-test");
    std::puts("probe: private CPUID leaf -> VM-exit handler -> signed response");

    int featureRegs[4]{};
    __cpuid(featureRegs, 1);
    const bool hypervisorBit =
        (static_cast<std::uint32_t>(featureRegs[2]) & (1U << 31)) != 0;
    std::printf("CPUID.1 hypervisor-present bit: %u (not used for verdict)\n\n",
                hypervisorBit ? 1U : 0U);

    const auto processors = enumerateProcessors();
    if (processors.empty()) {
        std::fputs("No active logical processors found.\n", stderr);
        return 2;
    }

    GROUP_AFFINITY originalAffinity{};
    const bool haveOriginalAffinity =
        GetThreadGroupAffinity(GetCurrentThread(), &originalAffinity) != FALSE;

    unsigned passed = 0;
    for (const auto& cpu : processors) {
        if (!pinCurrentThread(cpu)) {
            std::printf("CPU %02u (group %u:%u): FAIL affinity error=%lu\n",
                        cpu.index,
                        static_cast<unsigned>(cpu.group),
                        static_cast<unsigned>(cpu.number),
                        GetLastError());
            continue;
        }

        const auto result = probeCurrentProcessor(cpu.index);
        if (result.ok) {
            ++passed;
            std::printf(
                "CPU %02u (group %u:%u): PASS vmexits=%u->%u\n",
                cpu.index,
                static_cast<unsigned>(cpu.group),
                static_cast<unsigned>(cpu.number),
                result.firstVmexits,
                result.lastVmexits);
        } else {
            std::printf(
                "CPU %02u (group %u:%u): FAIL eax=%08X ebx=%08X ecx=%08X edx=%08X\n",
                cpu.index,
                static_cast<unsigned>(cpu.group),
                static_cast<unsigned>(cpu.number),
                result.eax,
                result.ebx,
                result.ecx,
                result.edx);
        }
    }

    if (haveOriginalAffinity) {
        SetThreadGroupAffinity(GetCurrentThread(), &originalAffinity, nullptr);
    }

    std::printf("\nSummary: %u/%zu logical processors PASS\n",
                passed,
                processors.size());

    if (passed == processors.size()) {
        std::puts("VERDICT: every active logical processor answered from KNHV's VM-exit path.");
        return 0;
    }

    std::puts("VERDICT: full-core VMX probe failed.");
    return 1;
}
