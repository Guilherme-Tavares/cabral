#include "ResultQueue.hpp"

#include <utility>

namespace cabral::gui {

void ResultQueue::pushHost(HostResult host) {
    std::lock_guard lock(mutex_);
    hosts_.push_back(std::move(host));
}

void ResultQueue::pushLog(LogLevel level, std::string_view message) {
    std::lock_guard lock(mutex_);
    logs_.push_back(LogEntry{level, std::string(message)});
}

void ResultQueue::setProgress(std::size_t done, std::size_t total) {
    std::lock_guard lock(mutex_);
    progress_ = Progress{done, total};
}

std::vector<HostResult> ResultQueue::drainHosts() {
    std::lock_guard lock(mutex_);
    return std::exchange(hosts_, {});
}

std::vector<LogEntry> ResultQueue::drainLogs() {
    std::lock_guard lock(mutex_);
    return std::exchange(logs_, {});
}

ResultQueue::Progress ResultQueue::progress() const {
    std::lock_guard lock(mutex_);
    return progress_;
}

void ResultQueue::clear() {
    std::lock_guard lock(mutex_);
    hosts_.clear();
    logs_.clear();
    progress_ = Progress{};
}

} // namespace cabral::gui
