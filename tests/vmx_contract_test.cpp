#include "test_support.h"

using namespace knhv_tests;

int wmain(int argc, wchar_t** argv) {
    Options options;
    if (!ParseOptions(argc, argv, options)) {
        PrintUsage();
        return 2;
    }
    if (options.help) {
        PrintUsage();
        return 0;
    }

    TestState state;
    RunSourceContract(options.root, state);
    RunProviderV2Contract(state);
    RunEptTimeModelContract(state);
    RunVmcs02ModelContract(state);
    RunIommuModelContract(state);
    RunExitModelContract(state);
    RunCpuPolicyModelContract(state);
    if (options.hardware) RunHardwareContract(state);
    if (options.signature || options.runtime || options.driver_explicit) {
        RunArtifactContract(options.root, options.driver, state);
    }
    if (options.signature) {
        RunSignatureContract(options.driver, options.allow_test_root, state);
    }
    if (options.runtime) {
        RunServiceContract(options.service, options.start, options.stop, state);
    }

    std::cout << "\nDriver tests: " << state.passed << " passed, "
              << state.failed << " failed\n";
    return state.failed == 0 ? 0 : 1;
}
