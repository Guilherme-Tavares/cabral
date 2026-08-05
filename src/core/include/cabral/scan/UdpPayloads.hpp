#pragma once

#include <cabral/model/PortRange.hpp>

#include <cstdint>
#include <span>

namespace cabral::scan {

/// Sonda específica do protocolo que costuma escutar na porta.
///
/// Um datagrama vazio quase nunca provoca resposta: o serviço o descarta como malformado e
/// a porta aberta acaba indistinguível de silêncio. Uma consulta bem formada eleva muito a
/// taxa de resposta, e resposta é a única evidência de Open no UDP.
std::span<const std::uint8_t> payloadFor(Port port) noexcept;

} // namespace cabral::scan
