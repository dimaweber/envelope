find_package(GTest REQUIRED)

add_executable(envelope_test
        envelope.unittest.cxx
)
target_link_libraries(envelope_test PRIVATE envelope GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(envelope_test)
