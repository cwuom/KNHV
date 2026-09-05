#include "bench_common.h"

int wmain(int argc, wchar_t** argv) {
    return knhv_bench::Run(knhv_bench::BenchKind::DeviceIo,
                           L"KNHV_DeviceIoBench", argc, argv);
}
