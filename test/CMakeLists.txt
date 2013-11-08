
SET(TEST_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

# Unit test sources
SET(TEST_MODULE_SOURCES
	"${TEST_SOURCE_DIR}/util_test.c"
)

# Unit test runner
SET(TEST_SOURCES
	"${TEST_SOURCE_DIR}/test_main.c"
	${TEST_MODULE_SOURCES}
)
message(STATUS "yolo")
message(STATUS ${LIB_SOURCE_DIR})

# Unit test executable
add_executable(zmap-unit-test EXCLUDE_FROM_ALL ${SOURCES} ${TEST_SOURCES})
target_link_libraries(
	zmap-unit-test
	${CHECK_LIBRARIES}
)


# All unit tests (check test) as a single CTest
add_test(unit-tests zmap-unit-test)

# Integration test executables would go here
#add_executable(integrations-tests EXCLUDE_FROM_ALL ...)

# Integration tests would go here
#add_test(integration-tests)

# Make make check work like autotools
add_dependencies(check zmap-unit-test)

