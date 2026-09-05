#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "preflight.h"

int wmain(int argc, wchar_t** argv) {
    return knhv_preflight::Run(argc, argv);
}
