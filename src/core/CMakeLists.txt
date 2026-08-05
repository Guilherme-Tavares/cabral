add_library(scanner_core STATIC
    model/IpAddress.cpp
    model/PortRange.cpp
    model/PortState.cpp
    model/ScanConfig.cpp
    net/SocketError.cpp
    scan/ConnectScanner.cpp
    services/ServiceTable.cpp
    ScanEngine.cpp
)

add_library(cabral::scanner_core ALIAS scanner_core)

target_include_directories(scanner_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(scanner_core PRIVATE cabral_warnings)

# Implementações de rede por plataforma: a seleção é do CMake, não de #ifdef espalhado.
if(WIN32)
    target_sources(scanner_core PRIVATE
        net/windows/Socket.cpp
        net/windows/Poller.cpp)
    target_link_libraries(scanner_core PUBLIC ws2_32)
else()
    target_sources(scanner_core PRIVATE
        net/posix/Socket.cpp
        net/posix/Poller.cpp)
endif()

find_package(Threads REQUIRED)
target_link_libraries(scanner_core PUBLIC Threads::Threads)
