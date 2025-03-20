cmake_minimum_required(VERSION 3.10)
project(ValkeyLDAP VERSION 0.0.1 DESCRIPTION "Valkey LDAP module")
include(GNUInstallDirs)
set(DEFAULT_BUILD_TYPE "Debug")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

set(VALKEYMODULE_HEADER_PATH "/usr/include/valkeymodule.h" CACHE FILEPATH "The path to the valkeymodule.h file")

cmake_path(GET VALKEYMODULE_HEADER_PATH PARENT_PATH VALKEYMODULE_HEADER_DIRECTORY)

if (NOT EXISTS "${VALKEYMODULE_HEADER_DIRECTORY}/valkeymodule.h")
    message(FATAL_ERROR "Can't find valkeymodule.h header file in ${VALKEYMODULE_HEADER_DIRECTORY}/valkeymodule.h. Please specify the location with option -DVALKEYMODULE_HEADER_PATH" )
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)

configure_file(${VALKEYMODULE_HEADER_PATH} ${CMAKE_CURRENT_BINARY_DIR}/include COPYONLY)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wunused -Wunused-parameter")

find_package(OpenLdap REQUIRED)

file(GLOB SOURCES src/*.c)

add_library(valkeyldap SHARED ${SOURCES})

target_link_libraries(valkeyldap
  ${OPENLDAP_LIBRARIES}
)

target_include_directories(valkeyldap PRIVATE
    src
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${OPENLDAP_INCLUDE_DIR}
)

set_target_properties(valkeyldap PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    COMPILE_WARNING_AS_ERROR ON
    C_STANDARD 17)

install(TARGETS valkeyldap
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
