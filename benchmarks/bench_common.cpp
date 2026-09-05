#include "bench_common.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "knhv_control_ioctl.h"

namespace knhv_bench {
namespace {

namespace fs = std::filesystem;

#ifndef KNHV_BENCH_GIT
#define KNHV_BENCH_GIT "unknown"
#endif

#ifndef KNHV_BENCH_CONFIGURATION
#define KNHV_BENCH_CONFIGURATION "unknown"
#endif

#ifndef KNHV_BENCH_SOURCE_DIRTY
#define KNHV_BENCH_SOURCE_DIRTY "unknown"
#endif

constexpr int kExitOk = 0;
constexpr int kExitMeasurementFailure = 1;
constexpr int kExitUsage = 2;
constexpr int kExitBlocked = 10;
constexpr int kExitUnsupported = 11;
constexpr int kExitNotComparable = 12;
constexpr std::uint64_t kDefaultSeed = 0x4B4E4856ULL;
constexpr std::uint64_t kMaxDurationMs = 3'600'000ULL;
constexpr std::uint32_t kMaxRepeats = 1000U;
constexpr std::uint64_t kMaxIterations = 1'000'000'000ULL;

struct Options {
    std::wstring mode = L"baseline";
    std::wstring workload = L"cpu,mem";
    std::wstring events = L"cpuid,rdtsc,rdmsr,ept,vmx";
    std::wstring profile = L"no-hook";
    std::wstring cpus = L"all";
    std::wstring affinity = L"all-online";
    std::wstring require_owner;
    std::wstring device_profile;
    std::wstring output;
    std::wstring baseline;
    std::wstring candidate;
    std::uint64_t duration_ms = 1000U;
    std::uint32_t repeat = 3U;
    std::uint64_t iterations = 0U;
    std::uint64_t seed = kDefaultSeed;
    std::uint32_t pages = 1U;
    bool compare = false;
    bool allow_dma = false;
    bool suspend_resume = false;
};

struct ProviderState {
    bool queried = false;
    bool available = false;
    std::string owner = "unknown";
    std::string reason = "not queried";
    std::uint32_t status = 0U;
    std::uint32_t flags = 0U;
    std::uint64_t features = 0U;
};

struct Sample {
    std::uint64_t elapsed_ns = 0U;
    std::uint64_t operations = 0U;
    std::uint64_t tsc_delta = 0U;
    double rate = 0.0;
};

struct Measurement {
    std::vector<Sample> samples;
    bool clock_backwards = false;
    std::uint64_t qpc_frequency = 0U;
};

struct RunInfo {
    std::string status = "pass";
    std::string verdict = "pass";
    std::string reason;
    ProviderState provider;
    Measurement measurement;
    std::string executable_hash = "unknown";
    std::string executable_path = "unknown";
    bool has_comparison = false;
    double comparison_delta_percent = 0.0;
};

std::string Narrow(std::wstring_view value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return "<invalid-utf16>";
    std::string result(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), required, nullptr,
        nullptr);
    if (written != required) return "<invalid-utf16>";
    return result;
}

std::string JsonEscape(std::string_view value) {
    std::string result;
    result.reserve(value.size() + 8U);
    for (const unsigned char character : value) {
        switch (character) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (character < 0x20U) {
                std::ostringstream escaped;
                escaped << "\\u" << std::hex << std::setw(4)
                        << std::setfill('0') << static_cast<unsigned>(character);
                result += escaped.str();
            } else {
                result.push_back(static_cast<char>(character));
            }
            break;
        }
    }
    return result;
}

bool ParseUnsigned(std::wstring_view text, std::uint64_t& value) {
    if (text.empty()) return false;
    std::wstring copy(text);
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::wcstoull(copy.c_str(), &end, 0);
    if (errno == ERANGE || end == copy.c_str() || *end != L'\0') {
        return false;
    }
    value = static_cast<std::uint64_t>(parsed);
    return true;
}

bool TakeValue(int& index, int argc, wchar_t** argv, std::wstring& value) {
    if (index + 1 >= argc) return false;
    value = argv[++index];
    return !value.empty();
}

bool ParseOptions(int argc, wchar_t** argv, Options& options,
                  std::string& error) {
    for (int index = 1; index < argc; ++index) {
        const std::wstring_view argument(argv[index]);
        if (argument == L"--help" || argument == L"-h") {
            error = "help";
            return true;
        }
        if (argument == L"--compare") {
            options.compare = true;
            continue;
        }
        if (argument == L"--allow-dma") {
            options.allow_dma = true;
            continue;
        }
        if (argument == L"--suspend-resume") {
            options.suspend_resume = true;
            continue;
        }

        std::wstring* destination = nullptr;
        if (argument == L"--mode") destination = &options.mode;
        else if (argument == L"--workload") destination = &options.workload;
        else if (argument == L"--events") destination = &options.events;
        else if (argument == L"--profile") destination = &options.profile;
        else if (argument == L"--cpus") destination = &options.cpus;
        else if (argument == L"--affinity") destination = &options.affinity;
        else if (argument == L"--require-owner") destination = &options.require_owner;
        else if (argument == L"--device-profile") destination = &options.device_profile;
        else if (argument == L"--out") destination = &options.output;
        else if (argument == L"--baseline") destination = &options.baseline;
        else if (argument == L"--candidate") destination = &options.candidate;

        if (destination != nullptr) {
            if (!TakeValue(index, argc, argv, *destination)) {
                error = "missing value for " + Narrow(argument);
                return false;
            }
            continue;
        }

        if (argument == L"--duration" || argument == L"--duration-ms" ||
            argument == L"--repeat" || argument == L"--iterations" ||
            argument == L"--seed" || argument == L"--pages") {
            std::wstring value;
            if (!TakeValue(index, argc, argv, value)) {
                error = "missing value for " + Narrow(argument);
                return false;
            }
            std::uint64_t parsed = 0U;
            if (!ParseUnsigned(value, parsed)) {
                error = "invalid numeric value for " + Narrow(argument);
                return false;
            }
            if (argument == L"--duration") {
                if (parsed == 0U || parsed > kMaxDurationMs / 1000U) {
                    error = "duration seconds out of range";
                    return false;
                }
                options.duration_ms = parsed * 1000U;
            } else if (argument == L"--duration-ms") {
                if (parsed == 0U || parsed > kMaxDurationMs) {
                    error = "duration milliseconds out of range";
                    return false;
                }
                options.duration_ms = parsed;
            } else if (argument == L"--repeat") {
                if (parsed == 0U || parsed > kMaxRepeats) {
                    error = "repeat out of range";
                    return false;
                }
                options.repeat = static_cast<std::uint32_t>(parsed);
            } else if (argument == L"--iterations") {
                if (parsed == 0U || parsed > kMaxIterations) {
                    error = "iterations out of range";
                    return false;
                }
                options.iterations = parsed;
            } else if (argument == L"--seed") {
                options.seed = parsed;
            } else {
                if (parsed == 0U || parsed > 1'000'000U) {
                    error = "pages out of range";
                    return false;
                }
                options.pages = static_cast<std::uint32_t>(parsed);
            }
            continue;
        }

        error = "unknown option " + Narrow(argument);
        return false;
    }
    return true;
}

void PrintUsage(const wchar_t* name) {
    std::wcout << name << L" [options]\n"
               << L"  --mode baseline|native-l0|nested-l1|synthetic|ept-hook\n"
               << L"  --duration <seconds> or --duration-ms <milliseconds>\n"
               << L"  --repeat <count> --iterations <count> --seed <number>\n"
               << L"  --workload <csv> --events <csv> --profile <csv>\n"
               << L"  --affinity <name> --out <json-or-csv-path>\n"
               << L"  --compare --baseline <json> --candidate <json>\n";
}

std::string RegistryString(HKEY root, const wchar_t* path,
                            const wchar_t* name) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, path, 0U, KEY_READ, &key) != ERROR_SUCCESS) {
        return "unknown";
    }
    DWORD type = 0U;
    DWORD bytes = 0U;
    LONG result = RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes);
    if (result != ERROR_SUCCESS || type != REG_SZ || bytes < sizeof(wchar_t)) {
        RegCloseKey(key);
        return "unknown";
    }
    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1U, L'\0');
    result = RegQueryValueExW(key, name, nullptr, &type,
                              reinterpret_cast<BYTE*>(buffer.data()), &bytes);
    RegCloseKey(key);
    if (result != ERROR_SUCCESS) return "unknown";
    return Narrow(std::wstring_view(buffer.data()));
}

std::string CurrentExecutablePath() {
    std::vector<wchar_t> buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                                                 static_cast<DWORD>(buffer.size()));
        if (length == 0U) return "unknown";
        if (length + 1U < buffer.size()) {
            return Narrow(std::wstring_view(buffer.data(), length));
        }
        if (buffer.size() >= 32768U) return "unknown";
        buffer.resize(buffer.size() * 2U, L'\0');
    }
}

std::string Sha256File(const std::string& path) {
    const fs::path file_path = fs::u8path(path);
    HANDLE file = CreateFileW(file_path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) return "unknown";

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0U;
    DWORD result_size = 0U;
    std::string result = "unknown";
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U)) ||
        !BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                                           reinterpret_cast<PUCHAR>(&object_size),
                                           sizeof(object_size), &result_size, 0U))) {
        CloseHandle(file);
        if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0U);
        return result;
    }
    std::vector<UCHAR> object(object_size);
    std::array<UCHAR, 32> digest{};
    if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, object.data(),
                                         object_size, nullptr, 0U, 0U))) {
        CloseHandle(file);
        BCryptCloseAlgorithmProvider(algorithm, 0U);
        return result;
    }

    std::array<UCHAR, 64U * 1024U> chunk{};
    bool okay = true;
    for (;;) {
        DWORD read = 0U;
        if (!ReadFile(file, chunk.data(), static_cast<DWORD>(chunk.size()),
                      &read, nullptr)) {
            okay = false;
            break;
        }
        if (read == 0U) break;
        if (!BCRYPT_SUCCESS(BCryptHashData(hash, chunk.data(), read, 0U))) {
            okay = false;
            break;
        }
    }
    if (okay && BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(),
                                                static_cast<ULONG>(digest.size()),
                                                0U))) {
        std::ostringstream text;
        text << std::hex << std::setfill('0');
        for (const UCHAR byte : digest) {
            text << std::setw(2) << static_cast<unsigned>(byte);
        }
        result = text.str();
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0U);
    CloseHandle(file);
    return result;
}

ProviderState QueryProvider() {
    ProviderState result;
    result.queried = true;
    HANDLE device = CreateFileW(L"\\\\.\\KNHVControl", GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        result.reason = "KNHVControl unavailable win32=" +
                        std::to_string(error);
        return result;
    }
    knhv::HvQueryCapsIn request{};
    request.version = knhv::kAbiVersion;
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.request_id = 1U;
    knhv::HvQueryCapsOut response{};
    DWORD returned = 0U;
    const BOOL okay = DeviceIoControl(
        device, IOCTL_KNHV_QUERY_CAPS, &request, sizeof(request), &response,
        sizeof(response), &returned, nullptr);
    const DWORD error = okay ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    if (!okay || returned != sizeof(response) ||
        response.version != knhv::kAbiVersion ||
        response.size != sizeof(response)) {
        result.reason = "capability IOCTL failed win32=" +
                        std::to_string(error);
        return result;
    }
    result.status = static_cast<std::uint32_t>(response.status);
    result.flags = response.snapshot.status_flags;
    result.features = response.snapshot.feature_bits;
    if (result.status != static_cast<std::uint32_t>(knhv::HvStatus::Success)) {
        result.reason = "provider returned status=" +
                        std::to_string(result.status);
        return result;
    }
    result.available = true;
    const bool knhv_owner =
        (result.flags & knhv::kFlagKnhvBootL0Active) != 0U;
    const bool external_owner =
        (result.flags & knhv::kFlagOuterL0Active) != 0U;
    if (knhv_owner && external_owner) {
        result.owner = "conflict";
        result.reason = "provider reported multiple active VMX owners";
    } else if (knhv_owner) {
        result.owner = "knhv";
    } else if (external_owner) {
        result.owner = "external";
    } else {
        result.owner = "none";
        result.reason = "capability snapshot has no active owner";
    }
    if (result.reason == "capability snapshot received" ||
        result.reason == "not queried") {
        result.reason = "capability snapshot received";
    }
    return result;
}

bool HasToken(std::wstring_view csv, std::wstring_view token) {
    std::size_t begin = 0U;
    while (begin <= csv.size()) {
        const std::size_t end = csv.find(L',', begin);
        const std::wstring_view part = csv.substr(
            begin, end == std::wstring_view::npos ? csv.size() - begin
                                                   : end - begin);
        if (part == token) return true;
        if (end == std::wstring_view::npos) break;
        begin = end + 1U;
    }
    return false;
}

std::string WorkloadSupport(const Options& options, BenchKind kind) {
    if (options.affinity != L"all-online") {
        return "only --affinity all-online is implemented by this host-only EXE";
    }
    if (options.cpus != L"all") {
        return "only --cpus all is implemented by this host-only EXE";
    }
    if (kind == BenchKind::NativeLike &&
        (HasToken(options.workload, L"storage") ||
         HasToken(options.workload, L"network"))) {
        return "storage/network require an explicit isolated workload adapter";
    }
    if (kind == BenchKind::TscQpc && options.suspend_resume) {
        return "suspend-resume requires a physical test harness";
    }
    if (kind == BenchKind::DeviceIo &&
        (options.device_profile != L"virtual" || !options.allow_dma)) {
        return "device benchmark requires --device-profile virtual and --allow-dma; physical DMA is not enabled by this EXE";
    }
    return {};
}

bool ProviderSupportsNested(const ProviderState& provider) {
    if (!provider.available ||
        provider.status != static_cast<std::uint32_t>(knhv::HvStatus::Success) ||
        provider.owner == "unknown" || provider.owner == "none" ||
        provider.owner == "conflict") {
        return false;
    }
    if ((provider.flags & knhv::kFlagSyntheticSnapshot) != 0U) {
        return false;
    }
    return (provider.flags & knhv::kFlagNestedVmx) != 0U &&
           (provider.features & knhv::kCapNestedVmx) != 0U;
}

std::uint64_t DoBatch(BenchKind kind, const Options& options,
                      std::uint64_t count, std::uint64_t& state,
                      bool& clock_backwards, std::uint64_t& previous_qpc,
                      std::uint64_t& previous_tsc) {
    std::array<std::uint8_t, 4096> source{};
    std::array<std::uint8_t, 4096> destination{};
    std::uint64_t operations = 0U;
    for (std::uint64_t index = 0U; index < count; ++index) {
        switch (kind) {
        case BenchKind::NativeLike:
            state ^= state << 13U;
            state ^= state >> 7U;
            state ^= state << 17U;
            if (HasToken(options.workload, L"mem")) {
                std::memcpy(destination.data(), source.data(), source.size());
                state += destination[(index + state) % destination.size()];
            }
            break;
        case BenchKind::VmxExit:
            switch ((index + state) % 5U) {
            case 0U: state += 0x1337U; break;
            case 1U: state ^= 0xC0FFEEU; break;
            case 2U: state = (state << 3U) | (state >> 61U); break;
            case 3U: state += state >> 11U; break;
            default: state ^= state << 9U; break;
            }
            break;
        case BenchKind::TscQpc: {
            LARGE_INTEGER counter{};
            QueryPerformanceCounter(&counter);
            const std::uint64_t qpc = static_cast<std::uint64_t>(counter.QuadPart);
            unsigned int auxiliary = 0U;
            const std::uint64_t tsc = __rdtscp(&auxiliary);
            if (qpc < previous_qpc || tsc < previous_tsc) clock_backwards = true;
            previous_qpc = qpc;
            previous_tsc = tsc;
            state ^= qpc ^ tsc ^ auxiliary;
            break;
        }
        case BenchKind::EptHook: {
            const std::uint64_t page = (index + state) %
                                        (static_cast<std::uint64_t>(options.pages) * 64U);
            const bool execute_hook = options.profile.find(L"exec") !=
                                      std::wstring::npos;
            const bool write_hook = options.profile.find(L"write") !=
                                     std::wstring::npos;
            state += page ^ (execute_hook ? 0xE1U : 0U) ^
                     (write_hook ? 0xB1U : 0U);
            break;
        }
        case BenchKind::DeviceIo:
            state = (state * 6364136223846793005ULL) + 1442695040888963407ULL;
            break;
        }
        ++operations;
    }
    volatile std::uint64_t sink = state;
    (void)sink;
    return operations;
}

bool Measure(BenchKind kind, const Options& options, Measurement& measurement) {
    LARGE_INTEGER frequency{};
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) {
        return false;
    }
    measurement.qpc_frequency = static_cast<std::uint64_t>(frequency.QuadPart);
    measurement.samples.reserve(options.repeat);
    for (std::uint32_t repeat = 0U; repeat < options.repeat; ++repeat) {
        LARGE_INTEGER start{};
        LARGE_INTEGER now{};
        if (!QueryPerformanceCounter(&start)) return false;
        std::uint64_t state = options.seed + repeat + 1U;
        std::uint64_t previous_qpc = static_cast<std::uint64_t>(start.QuadPart);
        const std::uint64_t tsc_start = __rdtsc();
        std::uint64_t previous_tsc = tsc_start;
        std::uint64_t operations = 0U;
        do {
            const std::uint64_t batch = options.iterations == 0U
                                            ? 1024U
                                            : std::min<std::uint64_t>(
                                                  1024U, options.iterations - operations);
            if (batch == 0U) break;
            operations += DoBatch(kind, options, batch, state,
                                  measurement.clock_backwards, previous_qpc,
                                  previous_tsc);
            if (!QueryPerformanceCounter(&now)) return false;
            if (now.QuadPart < start.QuadPart ||
                static_cast<std::uint64_t>(now.QuadPart) < previous_qpc) {
                measurement.clock_backwards = true;
            }
            previous_qpc = static_cast<std::uint64_t>(now.QuadPart);
        } while (options.iterations == 0U
                     ? (now.QuadPart >= start.QuadPart &&
                        static_cast<std::uint64_t>(now.QuadPart -
                                                   start.QuadPart) *
                                1000U / measurement.qpc_frequency <
                            options.duration_ms)
                     : operations < options.iterations);
        if (!QueryPerformanceCounter(&now)) return false;
        if (now.QuadPart < start.QuadPart ||
            static_cast<std::uint64_t>(now.QuadPart) < previous_qpc) {
            measurement.clock_backwards = true;
        }
        const auto ticks = static_cast<std::uint64_t>(
            now.QuadPart >= start.QuadPart ? now.QuadPart - start.QuadPart : 0U);
        const std::uint64_t elapsed_ns =
            static_cast<std::uint64_t>((static_cast<long double>(ticks) *
                                        1'000'000'000.0L) /
                                       static_cast<long double>(measurement.qpc_frequency));
        const std::uint64_t tsc_end = __rdtsc();
        if (tsc_end < tsc_start) measurement.clock_backwards = true;
        const double rate = elapsed_ns == 0U
                                ? 0.0
                                : static_cast<double>(operations) * 1'000'000'000.0 /
                                      static_cast<double>(elapsed_ns);
        measurement.samples.push_back(
            Sample{elapsed_ns, operations,
                   tsc_end >= tsc_start ? tsc_end - tsc_start : 0U, rate});
    }
    return !measurement.samples.empty();
}

double Percentile(const std::vector<Sample>& samples, double fraction) {
    if (samples.empty()) return 0.0;
    std::vector<double> values;
    values.reserve(samples.size());
    for (const Sample& sample : samples) values.push_back(sample.rate);
    std::sort(values.begin(), values.end());
    const double position = fraction * static_cast<double>(values.size() - 1U);
    const auto lower = static_cast<std::size_t>(position);
    const auto upper = std::min<std::size_t>(lower + 1U, values.size() - 1U);
    const double weight = position - static_cast<double>(lower);
    return values[lower] + (values[upper] - values[lower]) * weight;
}

std::string JsonNumber(double value) {
    std::ostringstream text;
    text << std::setprecision(17) << value;
    return text.str();
}

std::string ExtractString(const std::string& json, std::string_view key) {
    const std::regex expression("\\\"" + std::string(key) +
                               "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
    std::smatch match;
    if (!std::regex_search(json, match, expression) || match.size() != 2U) {
        return {};
    }
    return match[1].str();
}

std::string ExtractNumber(const std::string& json, std::string_view key) {
    const std::regex expression("\\\"" + std::string(key) +
                               "\\\"\\s*:\\s*(-?[0-9]+(\\.[0-9]+)?)");
    std::smatch match;
    if (!std::regex_search(json, match, expression) || match.size() < 2U) {
        return {};
    }
    return match[1].str();
}

bool ReadText(const std::wstring& path, std::string& text) {
    std::ifstream input(fs::path(path), std::ios::binary);
    if (!input) return false;
    std::ostringstream buffer;
    buffer << input.rdbuf();
    text = buffer.str();
    return input.good() || input.eof();
}

bool WriteText(const std::wstring& path, const std::string& text) {
    if (path.empty()) {
        std::cout << text << '\n';
        return true;
    }
    const fs::path output(path);
    std::error_code error;
    if (!output.parent_path().empty()) {
        fs::create_directories(output.parent_path(), error);
        if (error) return false;
    }
    std::ofstream file(output, std::ios::binary | std::ios::trunc);
    if (!file) return false;
    file << text << '\n';
    return file.good();
}

std::string BuildJson(BenchKind kind, const wchar_t* name,
                      const Options& options, const RunInfo& info) {
    const std::string executable = JsonEscape(info.executable_path);
    const double p50 = Percentile(info.measurement.samples, 0.50);
    const double p95 = Percentile(info.measurement.samples, 0.95);
    const double p99 = Percentile(info.measurement.samples, 0.99);
    double maximum = 0.0;
    for (const Sample& sample : info.measurement.samples) {
        maximum = (std::max)(maximum, sample.rate);
    }
    const char* measurement_source =
        options.mode == L"baseline"
            ? "host-user-mode"
            : (options.mode == L"synthetic" || options.mode == L"ept-hook"
                   ? "synthetic-loop"
                   : "provider-gated-host-loop");
    const std::string capability_hash =
        info.provider.queried && info.provider.available
            ? [&info] {
                  std::ostringstream value;
                  value << "0x" << std::hex << info.provider.features;
                  return value.str();
              }()
            : "unknown";
    std::ostringstream output;
    output << "{\n"
           << "  \"schema\":\"knhv-bench-1\",\n"
           << "  \"benchmark\":\"" << JsonEscape(Narrow(name)) << "\",\n"
           << "  \"kind\":" << static_cast<unsigned>(kind) << ",\n"
           << "  \"status\":\"" << JsonEscape(info.status) << "\",\n"
           << "  \"verdict\":\"" << JsonEscape(info.verdict) << "\",\n"
           << "  \"reason\":\"" << JsonEscape(info.reason) << "\",\n"
           << "  \"build\":{\"git\":\"" << KNHV_BENCH_GIT
           << "\",\"configuration\":\"" << KNHV_BENCH_CONFIGURATION
           << "\",\"source_dirty\":\"" << KNHV_BENCH_SOURCE_DIRTY
           << "\",\"executable\":\"" << executable
           << "\",\"sha256\":\"" << info.executable_hash << "\"},\n"
           << "  \"host\":{\"os_build\":\""
           << JsonEscape(RegistryString(HKEY_LOCAL_MACHINE,
                                         L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                         L"CurrentBuildNumber"))
           << "\",\"bios\":\"unknown\",\"microcode\":\"unknown\"},\n"
           << "  \"cpu\":{\"model\":\""
           << JsonEscape(RegistryString(
                  HKEY_LOCAL_MACHINE,
                  L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                  L"ProcessorNameString"))
           << "\",\"logical_processors\":"
           << GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)
           << ",\"topology_hash\":\"unknown\",\"capability_hash\":\""
           << capability_hash << "\"},\n"
           << "  \"mode\":\"" << JsonEscape(Narrow(options.mode)) << "\",\n"
           << "  \"owner\":\"" << JsonEscape(info.provider.owner) << "\",\n"
           << "  \"execution_scope\":\""
           << (options.mode == L"compare"
                   ? "comparison"
                   : (options.mode == L"baseline"
                   ? "host-only"
                   : (options.mode == L"synthetic" ||
                              options.mode == L"ept-hook"
                          ? "synthetic"
                          : "provider-gated")))
           << "\",\n"
           << "  \"provider\":{\"queried\":"
           << (info.provider.queried ? "true" : "false")
           << ",\"available\":"
           << (info.provider.available ? "true" : "false")
           << ",\"status\":" << info.provider.status
           << ",\"flags\":" << info.provider.flags
           << ",\"features\":" << info.provider.features
           << ",\"reason\":\""
           << JsonEscape(info.provider.reason) << "\"},\n"
           << "  \"workload\":\"" << JsonEscape(Narrow(options.workload))
           << "\",\n"
           << "  \"events\":\"" << JsonEscape(Narrow(options.events))
           << "\",\n"
           << "  \"profile\":\"" << JsonEscape(Narrow(options.profile))
           << "\",\n"
           << "  \"cpus\":\"" << JsonEscape(Narrow(options.cpus))
           << "\",\n"
           << "  \"device_profile\":\""
           << JsonEscape(Narrow(options.device_profile))
           << "\",\n"
           << "  \"physical_dma_enabled\":false,\n"
           << "  \"measurement_source\":\"" << measurement_source
           << "\",\n"
           << "  \"events_collected\":[],\n"
           << "  \"duration_ms\":" << options.duration_ms << ",\n"
           << "  \"repeat\":" << options.repeat << ",\n"
           << "  \"iterations\":" << options.iterations << ",\n"
           << "  \"pages\":" << options.pages << ",\n"
           << "  \"suspend_resume\":"
           << (options.suspend_resume ? "true" : "false") << ",\n"
           << "  \"allow_dma\":" << (options.allow_dma ? "true" : "false")
           << ",\n"
           << "  \"affinity\":\"" << JsonEscape(Narrow(options.affinity))
           << "\",\n"
           << "  \"seed\":" << options.seed << ",\n"
           << "  \"samples\":{\"count\":"
           << info.measurement.samples.size() << ",\"p50\":"
           << JsonNumber(p50) << ",\"p95\":" << JsonNumber(p95)
           << ",\"p99\":" << JsonNumber(p99) << ",\"max\":"
           << JsonNumber(maximum) << "},\n"
           << "  \"counters\":{\"vmexits\":0,\"invept\":0,\"invvpid\":0,\"dma_faults\":0},\n"
           << "  \"counter_source\":\"not-collected\",\n"
           << "  \"clock\":{\"qpc_frequency\":"
           << info.measurement.qpc_frequency << ",\"backwards\":"
           << (info.measurement.clock_backwards ? "true" : "false") << "},\n"
           << "  \"telemetry\":{\"etw_lost\":null,\"source\":\"not-collected\"},\n"
           << "  \"release_ready\":false,\n"
           << "  \"comparison\":{";
    if (info.has_comparison) {
        output << "\"delta_percent\":"
               << JsonNumber(info.comparison_delta_percent);
    }
    output << "},\n"
           << "  \"errors\":[";
    if (!info.reason.empty() && info.verdict != "pass") {
        output << "\"" << JsonEscape(info.reason) << "\"";
    }
    output << "],\n  \"samples_raw\":[";
    for (std::size_t index = 0U; index < info.measurement.samples.size(); ++index) {
        if (index != 0U) output << ',';
        const Sample& sample = info.measurement.samples[index];
        output << "{\"elapsed_ns\":" << sample.elapsed_ns
               << ",\"operations\":" << sample.operations
               << ",\"tsc_delta\":" << sample.tsc_delta
               << ",\"rate\":" << JsonNumber(sample.rate) << "}";
    }
    output << "]\n}\n";
    return output.str();
}

std::string BuildCsv(const Measurement& measurement) {
    std::ostringstream output;
    output << "sample_index,elapsed_ns,operations,tsc_delta,rate\n";
    for (std::size_t index = 0U; index < measurement.samples.size(); ++index) {
        const Sample& sample = measurement.samples[index];
        output << index << ',' << sample.elapsed_ns << ',' << sample.operations
               << ',' << sample.tsc_delta << ',' << JsonNumber(sample.rate) << '\n';
    }
    return output.str();
}

bool WantsCsv(const std::wstring& path) {
    if (path.size() < 4U) return false;
    const std::wstring suffix = path.substr(path.size() - 4U);
    return suffix == L".csv" || suffix == L".CSV";
}

int Compare(const Options& options, const wchar_t* name) {
    std::string baseline;
    std::string candidate;
    RunInfo info;
    info.status = "not-comparable";
    info.verdict = "not-run";
    if (!ReadText(options.baseline, baseline) ||
        !ReadText(options.candidate, candidate)) {
        info.reason = "baseline or candidate JSON cannot be read";
    } else {
        const std::string baseline_status = ExtractString(baseline, "verdict");
        const std::string candidate_status = ExtractString(candidate, "verdict");
        const std::string baseline_mode = ExtractString(baseline, "mode");
        const std::string candidate_mode = ExtractString(candidate, "mode");
        const auto ExtractComparable = [](const std::string& json,
                                          std::string_view key) {
            const std::string string_value = ExtractString(json, key);
            return string_value.empty() ? ExtractNumber(json, key)
                                        : string_value;
        };
        const std::array<std::string_view, 11> metadata_keys = {
            "workload", "events", "profile", "cpus", "device_profile",
            "affinity", "seed", "duration_ms", "repeat", "iterations",
            "pages"};
        bool metadata_match = true;
        for (const std::string_view key : metadata_keys) {
            if (ExtractComparable(baseline, key) !=
                ExtractComparable(candidate, key)) {
                metadata_match = false;
                break;
            }
        }
        const bool provenance_match =
            ExtractString(baseline, "git") == ExtractString(candidate, "git") &&
            ExtractString(baseline, "configuration") ==
                ExtractString(candidate, "configuration") &&
            ExtractString(baseline, "os_build") ==
                ExtractString(candidate, "os_build") &&
            ExtractString(baseline, "model") == ExtractString(candidate, "model") &&
            ExtractString(baseline, "bios") == ExtractString(candidate, "bios") &&
            ExtractString(baseline, "microcode") ==
                ExtractString(candidate, "microcode") &&
            ExtractString(baseline, "topology_hash") ==
                ExtractString(candidate, "topology_hash") &&
            ExtractString(baseline, "capability_hash") ==
                ExtractString(candidate, "capability_hash");
        const bool source_clean =
            ExtractString(baseline, "source_dirty") == "false" &&
            ExtractString(candidate, "source_dirty") == "false";
        const auto HasSamples = [](const std::string& json) {
            const std::string count = ExtractNumber(json, "count");
            if (count.empty()) return false;
            try {
                return std::stoull(count) > 0U;
            } catch (const std::exception&) {
                return false;
            }
        };
        if (baseline_status != "pass" || candidate_status != "pass" ||
            baseline_mode != "baseline" || candidate_mode != "native-l0" ||
            !metadata_match || !provenance_match || !source_clean ||
            !HasSamples(baseline) || !HasSamples(candidate)) {
            info.reason = "modes, provenance, cleanliness or workload metadata are not comparable";
        } else {
            const std::string base_rate = ExtractNumber(baseline, "p50");
            const std::string candidate_rate = ExtractNumber(candidate, "p50");
            if (base_rate.empty() || candidate_rate.empty()) {
                info.reason = "p50 is missing from one result";
            } else {
                info.status = "pass";
                info.verdict = "pass";
                info.reason = "metadata and p50 are comparable";
                try {
                    const double baseline_value = std::stod(base_rate);
                    const double candidate_value = std::stod(candidate_rate);
                    const double delta = baseline_value == 0.0
                                             ? 0.0
                                             : (candidate_value - baseline_value) /
                                                   baseline_value * 100.0;
                    info.has_comparison = true;
                    info.comparison_delta_percent = delta;
                } catch (const std::exception&) {
                    info.reason = "p50 is not a valid number";
                }
            }
        }
    }
    info.executable_path = CurrentExecutablePath();
    info.executable_hash = Sha256File(info.executable_path);
    Options compare_options = options;
    compare_options.mode = L"compare";
    const std::string json =
        BuildJson(BenchKind::NativeLike, name, compare_options, info);
    if (!WriteText(options.output, json)) return kExitMeasurementFailure;
    return info.verdict == "pass" ? kExitOk : kExitNotComparable;
}

}  // namespace

int Run(BenchKind kind, const wchar_t* name, int argc, wchar_t** argv) {
    Options options;
    std::string error;
    if (!ParseOptions(argc, argv, options, error)) {
        std::cerr << "argument error: " << error << '\n';
        PrintUsage(name);
        return kExitUsage;
    }
    if (error == "help") {
        PrintUsage(name);
        return kExitOk;
    }
    if (options.compare) {
        if (kind != BenchKind::NativeLike || options.baseline.empty() ||
            options.candidate.empty()) {
            std::cerr << "--compare requires --baseline and --candidate on the native-like benchmark\n";
            return kExitUsage;
        }
        return Compare(options, name);
    }

    const bool known_mode = options.mode == L"baseline" ||
                            options.mode == L"native-l0" ||
                            options.mode == L"nested-l1" ||
                            options.mode == L"synthetic" ||
                            options.mode == L"ept-hook";
    if (!known_mode) {
        std::cerr << "unsupported mode: " << Narrow(options.mode) << '\n';
        return kExitUsage;
    }

    RunInfo info;
    info.executable_path = CurrentExecutablePath();
    info.executable_hash = Sha256File(info.executable_path);
    const bool provider_required = options.mode == L"native-l0" ||
                                   options.mode == L"nested-l1";
    info.provider = provider_required ? QueryProvider() : ProviderState{};
    if (options.mode == L"native-l0") {
        const std::string expected_owner = options.require_owner.empty()
                                                ? "knhv"
                                                : Narrow(options.require_owner);
        const bool owner_ok = info.provider.available &&
                              info.provider.owner == expected_owner &&
                              (info.provider.flags & knhv::kFlagKnhvBootL0Active) != 0U &&
                              (info.provider.features & knhv::kCapBootL0) != 0U;
        if (!owner_ok) {
            info.status = "blocked";
            info.verdict = "not-run";
            info.reason = "required owner or KNHV_BOOT_L0 capability is unavailable";
        }
    }
    if (info.verdict == "pass" && options.mode == L"nested-l1" &&
        !ProviderSupportsNested(info.provider)) {
        info.status = "blocked";
        info.verdict = "not-run";
        info.reason = "provider lacks non-synthetic nested VMX capability";
    }
    if (info.verdict == "pass") {
        const std::string unsupported = WorkloadSupport(options, kind);
        if (!unsupported.empty()) {
            info.status = kind == BenchKind::DeviceIo ? "blocked" : "unsupported";
            info.verdict = "not-run";
            info.reason = unsupported;
        }
    }
    if (info.verdict == "pass" &&
        (kind == BenchKind::VmxExit || kind == BenchKind::EptHook) &&
        options.mode == L"native-l0" && info.provider.owner != "knhv") {
        info.status = "blocked";
        info.verdict = "not-run";
        info.reason = "hardware provider is not KNHV";
    }
    if (info.verdict == "pass" && !Measure(kind, options, info.measurement)) {
        info.status = "fail";
        info.verdict = "fail";
        info.reason = "performance counter or sample collection failed";
    }
    if (info.measurement.clock_backwards && info.verdict == "pass") {
        info.status = "fail";
        info.verdict = "fail";
        info.reason = "QPC or TSC moved backwards";
    }
    const std::string payload = WantsCsv(options.output)
                                    ? BuildCsv(info.measurement)
                                    : BuildJson(kind, name, options, info);
    if (!WriteText(options.output, payload)) return kExitMeasurementFailure;
    if (info.verdict == "pass") return kExitOk;
    if (info.status == "blocked") return kExitBlocked;
    if (info.status == "unsupported") return kExitUnsupported;
    return kExitMeasurementFailure;
}

}  // namespace knhv_bench
