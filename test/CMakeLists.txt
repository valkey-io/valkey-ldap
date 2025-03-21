configure_file("CTestCustom.cmake" ${CMAKE_BINARY_DIR}/CTestCustom.cmake)

add_subdirectory(unit)
add_subdirectory(integration)