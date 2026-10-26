cmake_minimum_required(VERSION 3.20)

# This library is self-contained; its only dependencies (OpenSSL, zlib) are
# third-party. This CMake project works both standalone and as a subdirectory.

project(envelope LANGUAGES CXX)

set(TARGET_ENVELOPE envelope)

add_library(${TARGET_ENVELOPE} STATIC
        src/base64.cxx
        src/compress.cxx
        src/crypto.cxx
        src/envelope.cxx
)

target_include_directories(${TARGET_ENVELOPE} PUBLIC include)
target_compile_features(${TARGET_ENVELOPE} PUBLIC cxx_std_23)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
target_link_libraries(${TARGET_ENVELOPE} PRIVATE OpenSSL::Crypto ZLIB::ZLIB)

if (NOT DEFINED BUILD_TESTS)
    set(BUILD_TESTS ON)
endif ()
option(ENVELOPE_BUILD_TESTS "Build envelope's own tests" ${BUILD_TESTS})
if (ENVELOPE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()

# `cmake --build . --target envelope_docs` regenerates ./docs/html/ from
# this library's own Doxyfile (include/) - deliberately separate from the
# parent project's `docs` target/Doxyfile, same reasoning as everything
# else about keeping this directory self-contained. Optional: doesn't fail
# configure if Doxygen isn't installed, and isn't part of the default
# `all` target.
find_package(Doxygen)
if (DOXYGEN_FOUND)
    add_custom_target(envelope_docs
            COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Generating HTML documentation with Doxygen into docs/html/"
            VERBATIM)
endif ()
