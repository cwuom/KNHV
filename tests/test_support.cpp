#include "test_support.h"

#include <algorithm>
#include <iterator>

namespace knhv_tests {

void Check(TestState& state, std::string_view name, bool condition,
           std::string_view detail) {
    if (condition) {
        ++state.passed;
        std::cout << "PASS  " << name << "\n";
        return;
    }

    ++state.failed;
    std::cerr << "FAIL  " << name;
    if (!detail.empty()) std::cerr << ": " << detail;
    std::cerr << "\n";
}

std::string ReadText(const fs::path& path, TestState& state) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        Check(state, "read " + path.generic_string(), false,
              "file not found");
        return {};
    }

    std::string text{std::istreambuf_iterator<char>(file),
                     std::istreambuf_iterator<char>()};
    if (file.bad()) {
        Check(state, "read " + path.generic_string(), false, "read error");
        return {};
    }
    text.erase(std::remove(text.begin(), text.end(), '\r'), text.end());
    return text;
}

bool Contains(const std::string& text, std::string_view token) {
    return text.find(token) != std::string::npos;
}

bool ContainsInOrder(const std::string& text,
                     std::initializer_list<std::string_view> tokens) {
    std::size_t cursor = 0;
    for (const std::string_view token : tokens) {
        const std::size_t position = text.find(token, cursor);
        if (position == std::string::npos) return false;
        cursor = position + token.size();
    }
    return true;
}

bool Matches(const std::string& text, std::string_view expression) {
    try {
        return std::regex_search(text, std::regex(std::string(expression)));
    } catch (const std::regex_error&) {
        return false;
    }
}

void PrintUsage() {
    std::wcout
        << L"KNHV_ContractTests [--root path] [--driver path] "
           L"[--hardware] [--signature] [--runtime] [--start] [--stop] "
           L"[--service name] [--allow-test-root]\n";
}

bool ParseOptions(int argc, wchar_t** argv, Options& options) {
#ifdef KNHV_SOURCE_ROOT
    options.root = fs::path(KNHV_SOURCE_ROOT);
#else
    options.root = fs::current_path();
#endif

    auto read_path = [&](int& index, fs::path& output) {
        if (index + 1 >= argc) return false;
        output = argv[++index];
        return true;
    };

    for (int index = 1; index < argc; ++index) {
        const std::wstring argument = argv[index];
        if (argument == L"--root") {
            if (!read_path(index, options.root)) return false;
        } else if (argument == L"--driver") {
            if (!read_path(index, options.driver)) return false;
            options.driver_explicit = true;
        } else if (argument == L"--service") {
            if (index + 1 >= argc) return false;
            options.service = argv[++index];
        } else if (argument == L"--hardware") {
            options.hardware = true;
        } else if (argument == L"--runtime") {
            options.runtime = true;
        } else if (argument == L"--start") {
            options.runtime = true;
            options.start = true;
        } else if (argument == L"--stop") {
            options.runtime = true;
            options.stop = true;
        } else if (argument == L"--signature") {
            options.signature = true;
        } else if (argument == L"--allow-test-root") {
            options.allow_test_root = true;
        } else if (argument == L"--help" || argument == L"-h") {
            options.help = true;
            return true;
        } else {
            std::wcerr << L"Unknown option: " << argument << L"\n";
            return false;
        }
    }

    if (options.driver.empty()) {
        options.driver = options.root / L"build/vscode/Debug/KNHV.sys";
    }
    return true;
}

}  // namespace knhv_tests
