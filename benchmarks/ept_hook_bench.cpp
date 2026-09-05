#include "bench_common.h"

int wmain(int argc, wchar_t** argv) {
    return knhv_bench::Run(knhv_bench::BenchKind::EptHook,
                           L"KNHV_EptHookBench", argc, argv);
}
