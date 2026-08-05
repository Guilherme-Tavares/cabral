#pragma once

#include <cabral/model/IpAddress.hpp>
#include <cabral/model/PortRange.hpp>
#include <cabral/model/PortState.hpp>
#include <cabral/model/ScanConfig.hpp>
#include <cabral/model/ScanResult.hpp>

#include <span>
#include <stop_token>
#include <string_view>
#include <vector>

namespace cabral::scan {

class IScanStrategy {
public:
    virtual ~IScanStrategy() = default;

    virtual Protocol protocol() const noexcept = 0;
    virtual bool requiresRawSocket() const noexcept = 0;
    virtual std::string_view name() const noexcept = 0;

    virtual std::vector<PortResult> scan(const IpAddress& target, std::span<const Port> ports,
                                         const ScanConfig& config, std::stop_token stop) = 0;
};

} // namespace cabral::scan
