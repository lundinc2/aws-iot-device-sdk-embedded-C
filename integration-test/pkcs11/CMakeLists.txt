project ("pkcs11 system test")
cmake_minimum_required (VERSION 3.2.0)

# Include PKCS #11 library's source and header path variables.
include("${CMAKE_SOURCE_DIR}/libraries/standard/corePKCS11/pkcsFilePaths.cmake")

# ====================  Define your project name (edit) ========================
set(project_name "pkcs11_system")

# ================= Create the library under test here (edit) ==================

# list the files you would like to test here
set(real_source_files "${PKCS_SOURCES}")
set(corePKCS11_location "${CMAKE_SOURCE_DIR}/libraries/standard/corePKCS11")
set(3rdparty_location "${corePKCS11_location}/3rdparty")
set(test_config "test-config")

file(GLOB MBEDTLS_FILES CONFIGURE_DEPENDS "${3rdparty_location}/mbedtls/library/*.c")
file(GLOB MBEDTLS_FILES_INCLUDES CONFIGURE_DEPENDS "${3rdparty_location}/mbedtls/include/mbedtls/*.h")
file(GLOB test_config_sources CONFIGURE_DEPENDS "${test_config}/*.h")
list(APPEND real_source_files
            ${MBEDTLS_FILES}
            ${test_config_sources}
            "${CMAKE_SOURCE_DIR}/platform/posix/pkcs11_pal.c"
            "${3rdparty_location}/mbedtls_utils/mbedtls_utils.c"
            )

# list the directories the module under test includes
list(APPEND real_include_directories
            .
            ${test_config}
            ${PKCS_INCLUDE_PUBLIC_DIRS}
            ${LOGGING_INCLUDE_DIRS}
            "${3rdparty_location}/mbedtls/include"
            "${3rdparty_location}/mbedtls_utils"
        )

# =====================  Create UnitTest Code here (edit)  =====================

# list the directories your test needs to include
list(APPEND test_include_directories
            .
            ${PKCS_INCLUDE_PUBLIC_DIRS}
            ${LOGGING_INCLUDE_DIRS}
            "${mbedtls_location}/include"
        )

# =============================  (end edit)  ===================================
set(real_name "${project_name}_real")

create_real_library(${real_name}
                    "${real_source_files}"
                    "${real_include_directories}"
                    # Empty mock name as create_real_library needs the 4th argument.
                    ""
        )
target_compile_definitions(
    ${real_name}
    PUBLIC
        -DMBEDTLS_CONFIG_FILE="mbedtls_config.h"
)

set_source_files_properties(
    ${MBEDTLS_FILES}
    PROPERTIES COMPILE_FLAGS
    "-Wno-pedantic"
)

set_source_files_properties(
    ${MBEDTLS_FILES_INCLUDES}
    PROPERTIES COMPILE_FLAGS
    "-Wno-pedantic"
)

list(APPEND stest_link_list
            lib${real_name}.a
        )

list(APPEND stest_dep_list
            ${real_name}
        )

set(stest_name "${project_name}_test")
set(stest_source "system-tests/${project_name}_test.c")
create_test(${stest_name}
            ${stest_source}
            "${stest_link_list}"
            "${stest_dep_list}"
            "${test_include_directories}"
        )
