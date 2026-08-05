// Verifica a ponte entre o ScanEngine e o loop de render sem depender de janela: a fila e
// o controlador contêm toda a lógica que a Fase 5 acrescenta ao comportamento observável.
// O desenho em si é ImGui, exercitado manualmente.
#include <algorithm>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "../src/gui/ResultQueue.hpp"
#include "../src/gui/ScanController.hpp"
#include "TestListener.hpp"

using cabral::HostResult;
using cabral::IpAddress;
using cabral::LogLevel;
using cabral::PortState;
using cabral::ScanType;
using cabral::TimingProfile;
using cabral::gui::ResultQueue;
using cabral::gui::ScanController;

namespace {

HostResult hostAt(std::string_view address) {
    HostResult host;
    host.address = *IpAddress::parse(address);
    host.isUp = true;
    return host;
}

} // namespace

TEST(ResultQueue, DrainReturnsAndClears) {
    ResultQueue queue;
    queue.pushHost(hostAt("10.0.0.1"));
    queue.pushHost(hostAt("10.0.0.2"));

    EXPECT_EQ(queue.drainHosts().size(), 2u);
    EXPECT_TRUE(queue.drainHosts().empty()) << "drain must not hand out the same host twice";
}

TEST(ResultQueue, KeepsLogsWithTheirLevel) {
    ResultQueue queue;
    queue.pushLog(LogLevel::Warning, "careful");
    queue.pushLog(LogLevel::Error, "broken");

    const auto logs = queue.drainLogs();
    ASSERT_EQ(logs.size(), 2u);
    EXPECT_EQ(logs[0].level, LogLevel::Warning);
    EXPECT_EQ(logs[0].message, "careful");
    EXPECT_EQ(logs[1].level, LogLevel::Error);
}

TEST(ResultQueue, ProgressIsReadableWithoutDraining) {
    ResultQueue queue;
    queue.setProgress(3, 10);

    EXPECT_EQ(queue.progress().done, 3u);
    EXPECT_EQ(queue.progress().total, 10u);
}

TEST(ResultQueue, ClearDropsEverything) {
    ResultQueue queue;
    queue.pushHost(hostAt("10.0.0.1"));
    queue.pushLog(LogLevel::Info, "x");
    queue.setProgress(1, 2);

    queue.clear();

    EXPECT_TRUE(queue.drainHosts().empty());
    EXPECT_TRUE(queue.drainLogs().empty());
    EXPECT_EQ(queue.progress().total, 0u);
}

/// O ponto que a arquitetura marca como corrupção silenciosa: os callbacks disparam de
/// várias threads worker, e nada pode se perder no caminho até o render.
TEST(ResultQueue, SurvivesConcurrentProducers) {
    ResultQueue queue;
    constexpr int kThreads = 8;
    constexpr int kPerThread = 200;

    std::vector<std::thread> producers;
    for (int t = 0; t < kThreads; ++t) {
        producers.emplace_back([&queue] {
            for (int i = 0; i < kPerThread; ++i) {
                queue.pushHost(hostAt("10.0.0.1"));
                queue.pushLog(LogLevel::Info, "entry");
            }
        });
    }

    // Drena em paralelo, como o loop de render faria enquanto a varredura corre.
    std::size_t drained = 0;
    while (drained < kThreads * kPerThread) {
        drained += queue.drainHosts().size();
        std::this_thread::yield();
    }

    for (auto& producer : producers) {
        producer.join();
    }
    drained += queue.drainHosts().size();

    EXPECT_EQ(drained, static_cast<std::size_t>(kThreads * kPerThread));
}

TEST(ScanController, RejectsMalformedTarget) {
    ScanController controller;
    ScanController::Request request;
    request.targetSpec = "not an address";
    request.portSpec = "80";

    std::string error;
    EXPECT_FALSE(controller.start(request, error));
    EXPECT_FALSE(error.empty());
    EXPECT_FALSE(controller.isRunning());
}

TEST(ScanController, RejectsMalformedPortSpec) {
    ScanController controller;
    ScanController::Request request;
    request.targetSpec = "127.0.0.1";
    request.portSpec = "not-ports";

    std::string error;
    EXPECT_FALSE(controller.start(request, error));
    EXPECT_FALSE(error.empty());
}

TEST(ScanController, RejectsLargeRangeWithoutOptIn) {
    ScanController controller;
    ScanController::Request request;
    request.targetSpec = "10.0.0.0/16";
    request.portSpec = "80";

    std::string error;
    EXPECT_FALSE(controller.start(request, error));
    EXPECT_NE(error.find("/24"), std::string::npos);
}

/// Ping sweep não varre portas: exigir especificação válida impediria de usá-lo pela GUI.
TEST(ScanController, PingSweepIgnoresPortSpec) {
    ScanController controller;
    ScanController::Request request;
    request.targetSpec = "127.0.0.1";
    request.portSpec = "garbage";
    request.scanType = ScanType::PingSweep;

    std::string error;
    EXPECT_TRUE(controller.start(request, error)) << error;
    controller.requestStop();
}

TEST(ScanController, DeliversResultsThroughTheQueue) {
    cabral::test::TestListener listener;
    ASSERT_TRUE(listener.isValid());

    ScanController controller;
    ScanController::Request request;
    request.targetSpec = "127.0.0.1";
    request.portSpec = std::to_string(listener.port());
    request.timing = TimingProfile::Aggressive;

    std::string error;
    ASSERT_TRUE(controller.start(request, error)) << error;

    // Drena como o loop de render faria, até a varredura terminar.
    std::vector<HostResult> collected;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        controller.poll();
        auto batch = controller.queue().drainHosts();
        collected.insert(collected.end(), batch.begin(), batch.end());
        if (!collected.empty() && !controller.isRunning()) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    ASSERT_EQ(collected.size(), 1u);
    ASSERT_EQ(collected[0].ports.size(), 1u);
    EXPECT_EQ(collected[0].ports[0].state, PortState::Open);

    const auto progress = controller.queue().progress();
    EXPECT_EQ(progress.done, 1u);
    EXPECT_EQ(progress.total, 1u);
}

TEST(ScanController, StopEndsScanWithoutHanging) {
    ScanController controller;
    ScanController::Request request;
    request.targetSpec = "10.255.255.1";
    request.portSpec = "1-2000";
    request.timing = TimingProfile::Polite;

    std::string error;
    ASSERT_TRUE(controller.start(request, error)) << error;

    const auto started = std::chrono::steady_clock::now();
    controller.requestStop();

    while (controller.isRunning() &&
           std::chrono::steady_clock::now() - started < std::chrono::seconds(10)) {
        controller.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    EXPECT_FALSE(controller.isRunning());
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(10));
}

TEST(ScanController, RefusesConcurrentScans) {
    ScanController controller;
    ScanController::Request request;
    request.targetSpec = "10.255.255.1";
    request.portSpec = "1-500";
    request.timing = TimingProfile::Polite;

    std::string error;
    ASSERT_TRUE(controller.start(request, error)) << error;

    std::string secondError;
    EXPECT_FALSE(controller.start(request, secondError));
    EXPECT_FALSE(secondError.empty());

    controller.requestStop();
}
