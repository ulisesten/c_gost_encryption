cmake_minimum_required(VERSION 3.16)

project(gost
    VERSION 1.0.0
    DESCRIPTION "Cryptographic primitives per GOST 28147-89, GOST R 34.11-2012 and GOST R 34.10-2012"
    LANGUAGES C
)

option(GOST_BUILD_TESTS "Build the test suite" ON)
option(GOST_BUILD_EXAMPLES "Build the usage examples" ON)
option(GOST_BUILD_DOCS "Build the Doxygen documentation" OFF)

add_library(gost STATIC
    gost/bigint/bigint.c
    gost/cipher/cipher.c
    gost/hash/hash.c
    gost/ecc/ecc.c
    gost/signature/signature.c
    gost/rng/rng.c
)
add_library(gost::gost ALIAS gost)

target_compile_features(gost PUBLIC c_std_11)
set_target_properties(gost PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_include_directories(gost
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)

if(MSVC)
    target_compile_options(gost PRIVATE /W4)
else()
    target_compile_options(gost PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(GOST_BUILD_DOCS)
    find_package(Doxygen REQUIRED)
    set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs)
    doxygen_add_docs(gost_docs
        ${CMAKE_CURRENT_SOURCE_DIR}/gost
        ${CMAKE_CURRENT_SOURCE_DIR}/README.md
        COMMENT "Generating the API documentation with Doxygen"
    )
endif()

include(GNUInstallDirs)
install(TARGETS gost
    EXPORT gostTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY gost/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gost
    FILES_MATCHING PATTERN "*.h"
)
install(EXPORT gostTargets
    NAMESPACE gost::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gost
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/gostConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/gostConfig.cmake
    "include(\"\${CMAKE_CURRENT_LIST_DIR}/gostTargets.cmake\")\n"
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/gostConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/gostConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gost
)

if(GOST_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(GOST_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
