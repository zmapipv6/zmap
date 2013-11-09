cmake_minimum_required (VERSION 2.6)
project (ZMAP C)

set(CMAKE_BINARY_DIR "${PROJECT_SOURCE_DIR}/bin")

option(WITH_REDIS "Build with support for Redis DB" OFF)
option(WITH_JSON "Build with support for JSON" OFF)
option(ENABLE_DEVELOPMENT "Enable development specific compiler and linker flags" OFF)
option(ENABLE_HARDENING "Add hardening specific compiler and linker flags" ON)
option(ENABLE_TEST "Enable building of regression tests" OFF)
option(EVERYTHING "Build all the features, with developement flags" OFF)

if(EVERYTHING)
	SET(WITH_REDIS ON)
	SET(WITH_JSON ON)
	SET(ENABLE_DEVELOPMENT ON)
	SET(ENABLE_HARDENING ON)
	SET(ENABLE_TEST ON)
endif()

if(ENABLE_DEVELOPMENT)
	# Hardening and warnings for building with gcc
	# Maybe add -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
	set(GCCWARNINGS 
		"-Wall -Wformat=2 -Wno-format-nonliteral"
		"-pedantic -fno-strict-aliasing"
		"-Wextra"
		"-Wfloat-equal -Wundef -Wwrite-strings -Wredundant-decls"
		"-Wnested-externs -Wbad-function-cast -Winit-self"
		"-Wmissing-noreturn -Wnormalized=id"
		"-Wstack-protector"
		"-Werror"
		)

	# Fix line breaks
	string(REPLACE ";" " "  GCCWARNINGS "${GCCWARNINGS}")

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCCWARNINGS} -g")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -g")
endif()

if(ENABLE_HARDENING)
	set(GCCHARDENING "-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-all -fwrapv -fPIC --param ssp-buffer-size=1")
	set(LDHARDENING "-z relro -z now")

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GCCHARDENING}")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LDHARDENING}")
endif()

if(WITH_REDIS)
	set(REDIS_LIBS hiredis)
	add_definitions("-DREDIS")
endif()

if(WITH_JSON)
	include(FindPkgConfig)
	pkg_check_modules(JSON json)
	if(JSON_FOUND)
		include_directories(JSON_INCLUDE_DIRS)
	else()
		message(FATAL_ERROR "Did not find libjson")
	endif()

	add_definitions("-DJSON")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${JSON_CFLAGS}")
endif()

# Standard FLAGS
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")

# Extra target FLAGS
set(CMAKE_C_FLAGS_DEBUG "-O2 -g")
set(CMAKE_C_FLAGS_RELEASE "-O2")

# Set some directory names
SET(ZMAP_SOURCE_DIR "${PROJECT_SOURCE_DIR}/src")
SET(PROBE_MODULE_SOURCE_DIR "${ZMAP_SOURCE_DIR}/probe_modules")
SET(OUTPUT_MODULE_SOURCE_DIR "${ZMAP_SOURCE_DIR}/output_modules")
SET(LIB_SOURCE_DIR "${PROJECT_SOURCE_DIR}/lib")
SET(TEST_SOURCE_DIR "${PROJECT_SOURCE_DIR}/test")

# Make sure all folders play nice together
include_directories(
	${LIB_SOURCE_DIR}
	${ZMAP_SOURCE_DIR}
	${OUTPUT_MODULE_SOURCE_DIR}
)

# Set up testing, if enabled
if(ENABLE_TEST)
	include(FindPkgConfig)
	pkg_check_modules(CHECK check)
	if(CHECK_FOUND)
		include_directories(CHECK_INCLUDE_DIRS)
	else()
		message(FATAL_ERROR "Did not find check")
	endif()
	# Set up compilation with check
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CHECK_CFLAGS}")
	# Configure make check
	enable_testing()
	set(CMAKE_CTEST_COMMAND ctest -V)
	add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
endif()

# Set up ZMap target and sources and test sources
add_subdirectory("${ZMAP_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/zmap")





# Install conf files
FILE(GLOB CONF_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/conf" "conf/*")
configure_file(zmap_conf_install.cmake.in zmap_conf_install.cmake)
install(SCRIPT zmap_conf_install.cmake)
