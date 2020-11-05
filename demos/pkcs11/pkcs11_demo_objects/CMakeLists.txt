set( DEMO_NAME "pkcs11_demo_objects" )

# Set path to corePKCS11 and it's third party libraries.
set(COREPKCS11_LOCATION "${CMAKE_SOURCE_DIR}/libraries/standard/corePKCS11")
set(3RDPARTY_LOCATION "${COREPKCS11_LOCATION}/3rdparty")

# Include PKCS #11 library's source and header path variables.
include( ${COREPKCS11_LOCATION}/pkcsFilePaths.cmake )

file(GLOB MBEDTLS_FILES CONFIGURE_DEPENDS "${3RDPARTY_LOCATION}/mbedtls/library/*.c")
set_source_files_properties(
    ${MBEDTLS_FILES}
    PROPERTIES COMPILE_FLAGS
    "-Wno-pedantic"
)

list(APPEND PKCS_SOURCES
            "${MBEDTLS_FILES}"
            "../common/src/demo_helpers.c"
            "${COREPKCS11_LOCATION}/source/portable/posix/core_pkcs11_pal.c"
            "${3RDPARTY_LOCATION}/mbedtls_utils/mbedtls_utils.c"
            "${3RDPARTY_LOCATION}/mbedtls_utils/mbedtls_error.c"
            )

# Demo target.
add_executable(
    ${DEMO_NAME}
    "${DEMO_NAME}.c"
    ${PKCS_SOURCES}
)

target_compile_definitions(
    ${DEMO_NAME}
    PUBLIC
        -DMBEDTLS_CONFIG_FILE="mbedtls_config.h"
)


target_include_directories(
    ${DEMO_NAME}
    PUBLIC
        "../common/include"
        ${PKCS_INCLUDE_PUBLIC_DIRS}
        ${CMAKE_CURRENT_LIST_DIR}
        ${LOGGING_INCLUDE_DIRS}
    PRIVATE
        "${3RDPARTY_LOCATION}/mbedtls/include"
        "${3RDPARTY_LOCATION}/mbedtls_utils"
)

