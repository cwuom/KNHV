#include "bench_common.h"

int wmain(int argc, wchar_t** argv) {
    return knhv_bench::Run(knhv_bench::BenchKind::VmxExit,
                           L"KNHV_VmxExitBench", argc, argv);
}
