#include <cabral/ScanEngine.hpp>
#include <cabral/model/IpAddress.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <vector>

#include <gtest/gtest.h>

#include "TestListener.hpp"

using cabral::HostResult;
using cabral::IpAddress;
using cabral::ScanCallbacks;
using cabral::ScanConfig;
using cabral::ScanEngine;
using cabral::ScanType;
using cabral::TimingProfile;

namespace {

ScanConfig configFor(std::vector<cabral::Port> ports) {
    ScanConfig config;
    config.timing = TimingProfile::Aggressive;
    config.timeoutOverride = std::chrono::milliseconds(300);
    config.ports = std::move(ports);
    return config;
}

} // namespace

TEST(ScanEngine, ReportsHostAndProgress) {
    cabral::test::TestListener listener;
    ASSERT_TRUE(listener.isValid());

    ScanEngine engine(configFor({listener.port()}));

    std::mutex mutex;
    std::vector<HostResult> hosts;
    std::size_t lastDone = 0;
    std::size_t lastTotal = 0;

    ScanCallbacks callbacks;
    callbacks.onHostComplete = [&](const HostResult& host) {
        std::lock_guard lock(mutex);
        hosts.push_back(host);
    };
    callbacks.onProgress = [&](std::size_t done, std::size_t total) {
        std::lock_guard lock(mutex);
        lastDone = done;
        lastTotal = total;
    };

    engine.start({*IpAddress::parse("127.0.0.1")}, std::move(callbacks));
    engine.wait();

    ASSERT_EQ(hosts.size(), 1u);
    EXPECT_TRUE(hosts[0].isUp);
    EXPECT_EQ(hosts[0].ports.size(), 1u);
    EXPECT_EQ(hosts[0].ports[0].state, cabral::PortState::Open);
    EXPECT_EQ(lastDone, 1u);
    EXPECT_EQ(lastTotal, 1u);
}

TEST(ScanEngine, AnnotatesServiceNames) {
    ScanEngine engine(configFor({22, 80, 443}));

    std::mutex mutex;
    std::vector<HostResult> hosts;

    ScanCallbacks callbacks;
    callbacks.onHostComplete = [&](const HostResult& host) {
        std::lock_guard lock(mutex);
        hosts.push_back(host);
    };

    engine.start({*IpAddress::parse("127.0.0.1")}, std::move(callbacks));
    engine.wait();

    ASSERT_EQ(hosts.size(), 1u);
    ASSERT_EQ(hosts[0].ports.size(), 3u);
    EXPECT_EQ(hosts[0].ports[0].service, "ssh");
    EXPECT_EQ(hosts[0].ports[1].service, "http");
    EXPECT_EQ(hosts[0].ports[2].service, "https");
}

TEST(ScanEngine, HandlesMultipleTargets) {
    ScanEngine engine(configFor({80}));

    std::atomic<std::size_t> count{0};
    ScanCallbacks callbacks;
    callbacks.onHostComplete = [&](const HostResult&) { count.fetch_add(1); };

    engine.start({*IpAddress::parse("127.0.0.1"), *IpAddress::parse("127.0.0.2"),
                  *IpAddress::parse("127.0.0.3")},
                 std::move(callbacks));
    engine.wait();

    EXPECT_EQ(count.load(), 3u);
}

TEST(ScanEngine, EmptyTargetListCompletesImmediately) {
    ScanEngine engine(configFor({80}));

    std::atomic<std::size_t> count{0};
    ScanCallbacks callbacks;
    callbacks.onHostComplete = [&](const HostResult&) { count.fetch_add(1); };

    engine.start({}, std::move(callbacks));
    engine.wait();

    EXPECT_EQ(count.load(), 0u);
    EXPECT_FALSE(engine.isRunning());
}

TEST(ScanEngine, UnimplementedScanTypeLogsAndStops) {
    auto config = configFor({80});
    config.scanType = ScanType::Syn;

    ScanEngine engine(std::move(config));

    std::mutex mutex;
    std::vector<std::string> messages;
    ScanCallbacks callbacks;
    callbacks.onLog = [&](cabral::LogLevel, std::string_view message) {
        std::lock_guard lock(mutex);
        messages.emplace_back(message);
    };

    engine.start({*IpAddress::parse("127.0.0.1")}, std::move(callbacks));
    engine.wait();

    EXPECT_FALSE(messages.empty());
    EXPECT_FALSE(engine.isRunning());
}

TEST(ScanEngine, StopRequestEndsScanPromptly) {
    std::vector<cabral::Port> ports;
    for (cabral::Port p = 1; p <= 2000; ++p) {
        ports.push_back(p);
    }

    auto config = configFor(std::move(ports));
    config.timeoutOverride = std::chrono::seconds(5);

    ScanEngine engine(std::move(config));

    ScanCallbacks callbacks;
    engine.start({*IpAddress::parse("10.255.255.1")}, std::move(callbacks));

    const auto started = std::chrono::steady_clock::now();
    engine.requestStop();
    engine.wait();
    const auto elapsed = std::chrono::steady_clock::now() - started;

    // Sem o stop, o timeout de 5 s por lote dominaria o tempo total.
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 5);
}

TEST(ScanEngine, DestructorStopsRunningScan) {
    std::vector<cabral::Port> ports;
    for (cabral::Port p = 1; p <= 2000; ++p) {
        ports.push_back(p);
    }

    auto config = configFor(std::move(ports));
    config.timeoutOverride = std::chrono::seconds(5);

    const auto started = std::chrono::steady_clock::now();
    {
        ScanEngine engine(std::move(config));
        engine.start({*IpAddress::parse("10.255.255.1")}, ScanCallbacks{});
        // Destrutor precisa pedir stop e fazer join, sem travar.
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 10);
}

TEST(LogLevel, EveryLevelHasName) {
    for (auto level : {cabral::LogLevel::Debug, cabral::LogLevel::Info, cabral::LogLevel::Warning,
                       cabral::LogLevel::Error}) {
        EXPECT_FALSE(cabral::toString(level).empty());
    }
}
