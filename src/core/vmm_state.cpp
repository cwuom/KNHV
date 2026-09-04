#include "vmm_internal.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject;

VcpuContext* g_VcpuData = nullptr;
u32 g_ProcessorCount = 0;
volatile LONG g_HvLifecycle = kHvLifecycleIdle;
volatile LONG g_HvImagePinned = 0;

TargetCpuWork* g_HvTargetCpuWork = nullptr;
TargetLaunchDpcWork* g_HvTargetLaunchDpcWork = nullptr;
volatile LONG g_HvTargetWorkGeneration = 0;
volatile LONG g_HvTargetActiveProcessor = -1;

HANDLE g_HvRuntimeWatchdogThread = nullptr;
volatile LONG g_HvRuntimeWatchdogStop = 0;
volatile LONG g_HvRuntimeWatchdogTicks = 0;
volatile LONG g_HvRuntimeWatchdogBreakFired = 0;
volatile LONG g_HvWaitpkgVmcsEnabled = 0;

u64 g_VmxBasic = 0;
u64 g_HostCr3 = 0;
bool g_VmxRequires32BitPhysicalAddress = false;
bool g_VmxFeatureContractInitialized = false;
bool g_VmxFeatureContractValid = false;
u64 g_EnumeratedXssMask = 0;
u64 g_SupportedXssMask = 0;
u64 g_GuestXssWriteMask = 0;
u64 g_HostXssMask = 0;
u64 g_HostXcr0Mask = 0;
u64 g_DebugctlMask = kDebugctlArchitecturalMask;
u32 g_XsaveStateSize = 0;
u32 g_VmxCapabilityProfile = 0;
volatile LONG g_VmxGuestOptionalProfile = 0;
volatile LONG g_VmxGuestOptionalProfileCandidate = 0;

extern "C" {
__declspec(align(64)) HvHostFaultRecord g_HvHostFaultRecord = {};
__declspec(align(64)) volatile LONG64 g_HvRootNmiCount = 0;
volatile u8 g_LinearAddressBits = 48;
volatile u8 g_CetVmcsEnabled = 0;
volatile u8 g_XsavesEnabled = 0;
volatile u8 g_XstateMode = XstateSaveFxsave;
volatile u64 g_XsavesMask = 0;
volatile LONG g_HvVerboseLogging = 1;

__declspec(align(64)) volatile LONG g_HvLaunchTelemetrySignature = 0;
volatile LONG g_HvLaunchExpectedProcessors = 0;
volatile LONG g_HvLaunchProbeEntered = 0;
volatile LONG g_HvLaunchProbeCompleted = 0;
volatile LONG g_HvLaunchDispatchEntered = 0;
volatile LONG g_HvLaunchAssemblyEntered = 0;
volatile LONG g_HvLaunchPrepareEntered = 0;
volatile LONG g_HvLaunchPrepareSucceeded = 0;
volatile LONG g_HvLaunchGuestEntered = 0;
volatile LONG g_HvLaunchVmlaunchIssued = 0;
volatile LONG g_HvLaunchVmlaunchReturned = 0;
volatile LONG g_HvLaunchGuestStarted = 0;
volatile LONG g_HvLaunchMarkedLaunched = 0;
volatile LONG g_HvLaunchVmExitAsmReached = 0;
volatile LONG g_HvVmExitDebugHold = 0;
volatile LONG g_HvLaunchFirstVmExitEntered = 0;
volatile LONG g_HvLaunchDispatchReturned = 0;
volatile LONG g_HvLaunchLastProbeProcessor = -1;
volatile LONG g_HvLaunchLastDispatchProcessor = -1;
volatile LONG g_HvLaunchLastPrepareProcessor = -1;
volatile LONG g_HvLaunchLastReturnProcessor = -1;
}

bool ShouldLaunchOnThisProcessor(u32 id) {
    return kDebugSingleCpu ? id == kDebugCpuIndex : true;
}

bool ShouldReportLaunchResult(u32 processor_index) {
    return ShouldLaunchOnThisProcessor(processor_index);
}

u32 ExpectedLaunchProcessorCount() {
    return kDebugSingleCpu ? 1U : g_ProcessorCount;
}

VmxControlGeneration SelectVmxControlGeneration(u32 profile) {
    if ((profile & VmxProfileTrueControls) == 0) {
        return VmxGenerationLegacy;
    }
    if ((profile & VmxProfileTertiaryControls) != 0) {
        return VmxGenerationTrueTertiary;
    }
    if ((profile & VmxProfileSecondaryControls) != 0) {
        return VmxGenerationTrueSecondary;
    }
    return VmxGenerationTrue;
}

bool ShouldInjectFault(u32 cpu, u32 stage) {
#if defined(KNHV_TEST_FAIL_CPU) && defined(KNHV_TEST_FAIL_STAGE)
    return static_cast<u32>(KNHV_TEST_FAIL_CPU) == cpu &&
           static_cast<u32>(KNHV_TEST_FAIL_STAGE) == stage;
#else
    UNREFERENCED_PARAMETER(cpu);
    UNREFERENCED_PARAMETER(stage);
    return false;
#endif
}

void WriteHvTrace(VcpuContext* vcpu, u32 cpu, HvTraceEvent event, u64 arg0,
                  u64 arg1, u64 arg2, u64 arg3) {
    if (!vcpu || !vcpu->TraceRing || vcpu->TraceCapacity == 0) return;
    const u64 sequence = static_cast<u64>(
        InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(
                                    &vcpu->TraceWriteIndex)) -
        1);
    const u32 slot = static_cast<u32>(sequence % vcpu->TraceCapacity);
    HvTraceRecord* record = &vcpu->TraceRing[slot];
    record->Tsc = __rdtsc();
    record->Cpu = cpu;
    record->Lifecycle = static_cast<u16>(
        InterlockedCompareExchange(&g_HvLifecycle, 0, 0));
    record->Stage = static_cast<u16>(
        InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0));
    record->Event = static_cast<u32>(event);
    record->Arg0 = arg0;
    record->Arg1 = arg1;
    record->Arg2 = arg2;
    record->Arg3 = arg3;
    MemoryBarrier();
    record->Sequence = sequence;
}

extern "C" void HvTraceCurrentVcpuEvent(u32 event) {
    if (!g_VcpuData) return;
    const u32 cpu = CurrentProcessorIndex();
    if (cpu < g_ProcessorCount) {
        WriteHvTrace(&g_VcpuData[cpu], cpu,
                     static_cast<HvTraceEvent>(event));
    }
}

extern "C" bool HvFaultInjectedCurrent(u32 stage) {
    return ShouldInjectFault(CurrentProcessorIndex(), stage);
}
