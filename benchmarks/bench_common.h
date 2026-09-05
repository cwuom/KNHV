#pragma once

#include <cstdint>

namespace knhv_bench {

enum class BenchKind : std::uint32_t {
    NativeLike = 1,
    VmxExit = 2,
    TscQpc = 3,
    EptHook = 4,
    DeviceIo = 5,
};

int Run(BenchKind kind, const wchar_t* name, int argc, wchar_t** argv);

}  // namespace knhv_bench
