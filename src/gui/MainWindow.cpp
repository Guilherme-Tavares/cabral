#include "MainWindow.hpp"

#include <cabral/net/RawSocket.hpp>

#include <algorithm>
#include <array>
#include <cstdio>

#include <imgui.h>

namespace cabral::gui {
namespace {

struct ScanTypeOption {
    const char* label;
    ScanType type;
    bool needsRawSocket;
};

constexpr std::array kScanTypes{
    ScanTypeOption{"TCP connect (-sT)", ScanType::Connect, false},
    ScanTypeOption{"TCP SYN (-sS)", ScanType::Syn, true},
    ScanTypeOption{"UDP (-sU)", ScanType::Udp, false},
    ScanTypeOption{"Ping sweep (-sn)", ScanType::PingSweep, false},
};

constexpr std::array kTimingLabels{"-T0 paranoid", "-T1 sneaky",     "-T2 polite",
                                   "-T3 normal",   "-T4 aggressive", "-T5 insane"};

ImVec4 colorFor(PortState state) {
    switch (state) {
    case PortState::Open:
        return ImVec4(0.36f, 0.80f, 0.42f, 1.0f);
    case PortState::Closed:
        return ImVec4(0.75f, 0.35f, 0.35f, 1.0f);
    case PortState::Filtered:
        return ImVec4(0.85f, 0.72f, 0.30f, 1.0f);
    // OpenFiltered é ambíguo por natureza; a cor não deve sugerir uma das duas leituras.
    case PortState::OpenFiltered:
        return ImVec4(0.60f, 0.70f, 0.85f, 1.0f);
    case PortState::Unknown:
        break;
    }
    return ImVec4(0.65f, 0.65f, 0.65f, 1.0f);
}

ImVec4 colorFor(LogLevel level) {
    switch (level) {
    case LogLevel::Error:
        return ImVec4(0.90f, 0.40f, 0.40f, 1.0f);
    case LogLevel::Warning:
        return ImVec4(0.90f, 0.75f, 0.35f, 1.0f);
    case LogLevel::Debug:
        return ImVec4(0.60f, 0.60f, 0.60f, 1.0f);
    case LogLevel::Info:
        break;
    }
    return ImVec4(0.85f, 0.85f, 0.85f, 1.0f);
}

} // namespace

MainWindow::MainWindow() {
    const auto capability = net::probeRawCapability();
    rawAvailable_ = capability == net::RawCapability::Available;
    if (!rawAvailable_) {
        rawUnavailableReason_ = net::rawCapabilityAdvice(capability);
    }
}

void MainWindow::drainQueue() {
    auto newHosts = controller_.queue().drainHosts();
    hosts_.insert(hosts_.end(), std::make_move_iterator(newHosts.begin()),
                  std::make_move_iterator(newHosts.end()));

    auto newLogs = controller_.queue().drainLogs();
    logs_.insert(logs_.end(), std::make_move_iterator(newLogs.begin()),
                 std::make_move_iterator(newLogs.end()));
}

void MainWindow::draw() {
    controller_.poll();
    drainQueue();

    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);

    constexpr ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                                       ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                                       ImGuiWindowFlags_MenuBar;

    if (ImGui::Begin("cabral", nullptr, flags)) {
        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu("File")) {
                if (ImGui::MenuItem("Quit")) {
                    closeRequested_ = true;
                }
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }

        drawControls();
        ImGui::Separator();
        drawProgress();
        ImGui::Separator();
        drawResults();
        ImGui::Separator();
        drawLog();
    }
    ImGui::End();
}

void MainWindow::drawControls() {
    const bool running = controller_.isRunning();

    ImGui::BeginDisabled(running);

    // Rótulo antes do campo: o padrão do ImGui é colocá-lo à direita, o que se lê como se
    // o valor pertencesse ao campo seguinte.
    ImGui::TextUnformatted("Target");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(260.0f);
    ImGui::InputText("##target", targetBuffer_, sizeof(targetBuffer_));
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("IPv4, CIDR (192.168.1.0/24), range (192.168.1.10-40),\n"
                          "comma-separated list, or hostname");
    }

    ImGui::SameLine();
    const bool pingSweep =
        kScanTypes[static_cast<std::size_t>(scanTypeIndex_)].type == ScanType::PingSweep;
    ImGui::BeginDisabled(pingSweep);
    ImGui::TextUnformatted("Ports");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200.0f);
    ImGui::InputText("##ports", portBuffer_, sizeof(portBuffer_));
    if (ImGui::IsItemHovered() && !pingSweep) {
        ImGui::SetTooltip("22 | 1-1024 | 22,80,443 | - for all");
    }
    ImGui::EndDisabled();

    ImGui::TextUnformatted("Scan type");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200.0f);
    if (ImGui::BeginCombo("##scantype",
                          kScanTypes[static_cast<std::size_t>(scanTypeIndex_)].label)) {
        for (std::size_t i = 0; i < kScanTypes.size(); ++i) {
            const auto& option = kScanTypes[i];

            // Opção privilegiada sem CAP_NET_RAW fica desabilitada, com a explicação no
            // tooltip: melhor que deixar escolher e falhar depois.
            const bool blocked = option.needsRawSocket && !rawAvailable_;

            ImGui::BeginDisabled(blocked);
            if (ImGui::Selectable(option.label, scanTypeIndex_ == static_cast<int>(i))) {
                scanTypeIndex_ = static_cast<int>(i);
            }
            ImGui::EndDisabled();

            if (blocked && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
                ImGui::SetTooltip("%s", rawUnavailableReason_.c_str());
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    ImGui::TextUnformatted("Timing");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(160.0f);
    ImGui::Combo("##timing", &timingIndex_, kTimingLabels.data(),
                 static_cast<int>(kTimingLabels.size()));

    ImGui::Checkbox("Skip host discovery (-Pn)", &skipHostDiscovery_);
    ImGui::SameLine();
    ImGui::Checkbox("Allow range wider than /24", &allowLargeRange_);

    ImGui::EndDisabled();

    if (!running) {
        if (ImGui::Button("Start scan", ImVec2(120.0f, 0.0f))) {
            ScanController::Request request;
            request.targetSpec = targetBuffer_;
            request.portSpec = portBuffer_;
            request.scanType = kScanTypes[static_cast<std::size_t>(scanTypeIndex_)].type;
            request.timing = static_cast<TimingProfile>(timingIndex_);
            request.skipHostDiscovery = skipHostDiscovery_;
            request.allowLargeRange = allowLargeRange_;

            hosts_.clear();
            logs_.clear();
            errorMessage_.clear();

            if (!controller_.start(request, errorMessage_)) {
                // Mensagem fica visível abaixo dos controles; nada é iniciado.
            }
        }
    } else {
        if (ImGui::Button("Cancel", ImVec2(120.0f, 0.0f))) {
            controller_.requestStop();
        }
    }

    if (!errorMessage_.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.90f, 0.40f, 0.40f, 1.0f), "%s", errorMessage_.c_str());
    }
}

void MainWindow::drawProgress() {
    const auto progress = controller_.queue().progress();

    float fraction = 0.0f;
    if (progress.total > 0) {
        fraction = static_cast<float>(progress.done) / static_cast<float>(progress.total);
    }

    char overlay[64];
    std::snprintf(overlay, sizeof(overlay), "%zu / %zu hosts", progress.done, progress.total);
    ImGui::ProgressBar(fraction, ImVec2(-1.0f, 0.0f), overlay);
}

void MainWindow::drawResults() {
    std::size_t hostsUp = 0;
    std::size_t openPorts = 0;
    for (const auto& host : hosts_) {
        if (host.isUp) {
            ++hostsUp;
        }
        for (const auto& port : host.ports) {
            if (port.state == PortState::Open) {
                ++openPorts;
            }
        }
    }

    ImGui::Text("Results: %zu host(s) reported, %zu up, %zu open port(s)", hosts_.size(), hostsUp,
                openPorts);

    constexpr ImGuiTableFlags tableFlags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                           ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable |
                                           ImGuiTableFlags_ScrollY;

    const float tableHeight = ImGui::GetContentRegionAvail().y * 0.6f;

    if (ImGui::BeginTable("results", 5, tableFlags, ImVec2(0.0f, tableHeight))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Host", ImGuiTableColumnFlags_DefaultSort);
        ImGui::TableSetupColumn("Port");
        ImGui::TableSetupColumn("Proto");
        ImGui::TableSetupColumn("State");
        ImGui::TableSetupColumn("Service");
        ImGui::TableHeadersRow();

        // Achata em linhas para que a ordenação valha sobre a tabela inteira, não por host.
        struct Row {
            const HostResult* host;
            const PortResult* port;
        };
        std::vector<Row> rows;
        for (const auto& host : hosts_) {
            if (host.ports.empty()) {
                rows.push_back(Row{&host, nullptr});
                continue;
            }
            for (const auto& port : host.ports) {
                rows.push_back(Row{&host, &port});
            }
        }

        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs();
            specs != nullptr && specs->SpecsCount > 0) {
            const auto& spec = specs->Specs[0];
            const bool ascending = spec.SortDirection == ImGuiSortDirection_Ascending;

            std::stable_sort(rows.begin(), rows.end(), [&](const Row& a, const Row& b) {
                auto less = [&]() {
                    switch (spec.ColumnIndex) {
                    case 0:
                        return a.host->address < b.host->address;
                    case 1:
                        return (a.port ? a.port->port : 0) < (b.port ? b.port->port : 0);
                    case 2:
                        return static_cast<int>(a.port ? a.port->protocol : Protocol::Tcp) <
                               static_cast<int>(b.port ? b.port->protocol : Protocol::Tcp);
                    case 3:
                        return static_cast<int>(a.port ? a.port->state : PortState::Unknown) <
                               static_cast<int>(b.port ? b.port->state : PortState::Unknown);
                    case 4:
                        return (a.port ? a.port->service : std::string{}) <
                               (b.port ? b.port->service : std::string{});
                    default:
                        return false;
                    }
                }();
                return ascending ? less : !less;
            });
        }

        for (const auto& row : rows) {
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(row.host->address.toString().c_str());

            if (row.port == nullptr) {
                ImGui::TableSetColumnIndex(3);
                const char* text = row.host->isUp ? "up" : "down";
                ImGui::TextColored(colorFor(row.host->isUp ? PortState::Open : PortState::Unknown),
                                   "%s", text);
                continue;
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%u", static_cast<unsigned>(row.port->port));

            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(std::string(toString(row.port->protocol)).c_str());

            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(colorFor(row.port->state), "%s",
                               std::string(toString(row.port->state)).c_str());

            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(row.port->service.empty() ? "unknown"
                                                             : row.port->service.c_str());
        }

        ImGui::EndTable();
    }
}

void MainWindow::drawLog() {
    ImGui::Text("Log");
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll", &logAutoScroll_);

    if (ImGui::BeginChild("log", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        for (const auto& entry : logs_) {
            ImGui::TextColored(colorFor(entry.level), "[%s] %s",
                               std::string(toString(entry.level)).c_str(), entry.message.c_str());
        }
        if (logAutoScroll_ && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
            ImGui::SetScrollHereY(1.0f);
        }
    }
    ImGui::EndChild();
}

} // namespace cabral::gui
