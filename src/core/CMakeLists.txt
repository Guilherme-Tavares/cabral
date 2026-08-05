add_library(scanner_core STATIC
    model/IpAddress.cpp
    model/PortRange.cpp
    model/PortState.cpp
    model/ScanConfig.cpp
)

add_library(cabral::scanner_core ALIAS scanner_core)

target_include_directories(scanner_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(scanner_core PRIVATE cabral_warnings)

# Fontes de rede entram por plataforma a partir da Fase 2 (docs/ARCHITECTURE.md).
if(WIN32)
    target_link_libraries(scanner_core PUBLIC ws2_32)
endif()
