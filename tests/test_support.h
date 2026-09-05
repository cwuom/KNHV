#pragma once

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <regex>
#include <string>
#include <string_view>

namespace knhv_tests {

namespace fs = std::filesystem;

struct TestState {
    int passed = 0;
    int failed = 0;
};

void Check(TestState& state, std::string_view name, bool condition,
           std::string_view detail = {});
std::string ReadText(const fs::path& path, TestState& state);
bool Contains(const std::string& text, std::string_view token);
bool ContainsInOrder(const std::string& text,
                     std::initializer_list<std::string_view> tokens);
bool Matches(const std::string& text, std::string_view expression);

struct Options {
    fs::path root;
    fs::path driver;
    bool driver_explicit = false;
    std::wstring service = L"KNHV";
    bool hardware = false;
    bool runtime = false;
    bool start = false;
    bool stop = false;
    bool signature = false;
    bool allow_test_root = false;
    bool help = false;
};

bool ParseOptions(int argc, wchar_t** argv, Options& options);
void PrintUsage();

void RunSourceContract(const fs::path& root, TestState& state);
void RunNestedModelContract(const fs::path& root, TestState& state);
void RunArtifactContract(const fs::path& root, const fs::path& driver,
                         TestState& state);
void RunSignatureContract(const fs::path& driver, bool allow_test_root,
                          TestState& state);
void RunHardwareContract(TestState& state);
void RunServiceContract(const std::wstring& name, bool start, bool stop,
                        TestState& state);

}  // namespace knhv_tests
