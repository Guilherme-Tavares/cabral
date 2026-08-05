include(FetchContent)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
    GIT_SHALLOW TRUE
    EXCLUDE_FROM_ALL)

FetchContent_MakeAvailable(googletest)

add_executable(cabral_tests
    test_ip_address.cpp
    test_port_range.cpp
    test_arg_parser.cpp
    test_result.cpp
)

target_link_libraries(cabral_tests PRIVATE
    cabral_cli
    cabral::scanner_core
    GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(cabral_tests)
