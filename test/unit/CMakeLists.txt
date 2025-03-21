set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/e7b26b72461e0bfcb5a2a9c1cafd849108f834ae.zip
)

FetchContent_MakeAvailable(googletest)

add_executable(
  unit_tests
  sanity_test.cpp
  vk_ldap_test.cpp

  ../../src/vk_ldap.c
)
target_include_directories(unit_tests PRIVATE
    ../../src
)
target_link_libraries(
  unit_tests
  GTest::gtest_main
  ${OPENLDAP_LIBRARIES}
)

include(GoogleTest)
gtest_discover_tests(unit_tests)
