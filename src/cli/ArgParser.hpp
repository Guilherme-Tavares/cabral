#pragma once

#include <cabral/model/Result.hpp>
#include <cabral/model/ScanConfig.hpp>

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cabral::cli {

/// O que a linha de comando pede. --help e --version encerram sem varrer, por isso são
/// ação e não flag: quem chama decide a saída sem reinspecionar os argumentos.
enum class Action { Scan, ShowHelp, ShowVersion };

struct ParsedArguments {
    Action action = Action::Scan;
    ScanConfig config;
    std::vector<std::string> targets; // literais; expansão de CIDR fica em discovery/
    std::string targetListFile;       // -iL
};

struct ParseError {
    std::string message;
};

/// Interpreta argv sem o nome do programa. Não toca em rede nem em arquivos: valida a
/// sintaxe e devolve a intenção.
Result<ParsedArguments, ParseError> parseArguments(std::span<const std::string_view> args);

std::string usageText();
std::string versionText();

} // namespace cabral::cli
