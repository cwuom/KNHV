#pragma once

#include <string>
#include <vector>

namespace knhv_preflight {

enum class GateState {
    Pass,
    Fail,
    Unknown,
};

struct GateResult {
    std::string name;
    GateState state = GateState::Unknown;
    std::string reason;
};

struct Options {
    std::wstring output_path;
    std::wstring profile = L"native-l0";
    bool help = false;
};

int Run(int argc, wchar_t** argv);

}  // namespace knhv_preflight
