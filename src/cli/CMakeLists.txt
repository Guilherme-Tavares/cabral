# Separado do executável para que os testes exercitem parser e formatter sem passar por
# main().
add_library(cabral_cli STATIC
    ArgParser.cpp
    ResultWriter.cpp
    TableFormatter.cpp)

target_include_directories(cabral_cli PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cabral_cli
    PUBLIC cabral::scanner_core
    PRIVATE cabral_warnings)

add_executable(cabral main.cpp)
target_link_libraries(cabral PRIVATE cabral_cli cabral_warnings)
