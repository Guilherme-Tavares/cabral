#include <cabral/model/ScanConfig.hpp>

namespace cabral {

TimingParameters parametersFor(TimingProfile profile) noexcept {
    using namespace std::chrono_literals;

    switch (profile) {
    case TimingProfile::Paranoid:
        return {.timeout = 5000ms, .retries = 3, .hostConcurrency = 1, .portConcurrency = 1};
    case TimingProfile::Sneaky:
        return {.timeout = 4000ms, .retries = 3, .hostConcurrency = 1, .portConcurrency = 4};
    case TimingProfile::Polite:
        return {.timeout = 3000ms, .retries = 2, .hostConcurrency = 2, .portConcurrency = 16};
    case TimingProfile::Normal:
        return {.timeout = 1000ms, .retries = 2, .hostConcurrency = 16, .portConcurrency = 128};
    case TimingProfile::Aggressive:
        return {.timeout = 500ms, .retries = 1, .hostConcurrency = 32, .portConcurrency = 256};
    case TimingProfile::Insane:
        return {.timeout = 250ms, .retries = 0, .hostConcurrency = 64, .portConcurrency = 512};
    }
    return {};
}

} // namespace cabral
