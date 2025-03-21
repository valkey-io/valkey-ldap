IF (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/venv")
    find_package (Python3 COMPONENTS Interpreter)
    execute_process (COMMAND "${Python3_EXECUTABLE}" -m venv "${CMAKE_BINARY_DIR}/test/integration/venv")


    ## update the environment with VIRTUAL_ENV variable (mimic the activate script)
    set (ENV{VIRTUAL_ENV} "${CMAKE_BINARY_DIR}/test/integration/venv")
    ## change the context of the search
    set (Python3_FIND_VIRTUALENV FIRST)
    ## unset Python3_EXECUTABLE because it is also an input variable (see documentation, Artifacts Specification section)
    unset (Python3_EXECUTABLE)

    list(APPEND CMAKE_MODULE_PATH "${CMAKE_BINARY_DIR}/test/integration/venv/share/Pytest/cmake")
    list(APPEND CMAKE_PREFIX_PATH "${CMAKE_BINARY_DIR}/test/integration/venv")

    find_package (Python3 COMPONENTS Interpreter Development)
    execute_process (COMMAND "${Python3_EXECUTABLE}" -m pip install -r ${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt --upgrade)
ELSE ()
    set (ENV{VIRTUAL_ENV} "${CMAKE_CURRENT_SOURCE_DIR}/venv")
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/venv/share/Pytest/cmake")
    list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_SOURCE_DIR}/venv")
    find_package (Python3 COMPONENTS Interpreter Development)
    execute_process (COMMAND "${Python3_EXECUTABLE}" -m pip install -r ${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt --upgrade)
ENDIF()

find_package(Pytest REQUIRED)

file(GLOB_RECURSE test_files "${CMAKE_CURRENT_SOURCE_DIR}/*.py")

pytest_discover_tests(
    integration_tests
    TRIM_FROM_NAME "^test_"
    DEPENDS
        valkeyldap
        ${test_files}
)
