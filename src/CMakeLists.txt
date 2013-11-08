SET(ZMAP_SOURCE_DIR "${PROJECT_SOURCE_DIR}/src")
SET(PROBE_MODULE_SOURCE_DIR "${ZMAP_SOURCE_DIR}/probe_modules")
SET(OUTPUT_MODULE_SOURCE_DIR "${ZMAP_SOURCE_DIR}/output_modules")
SET(LIB_SOURCE_DIR "${PROJECT_SOURCE_DIR}/lib")

include_directories(
	${LIB_SOURCE_DIR}
	${ZMAP_SOURCE_DIR}
	${OUTPUT_MODULE_SOURCE_DIR}
	)

SET(LIB_SOURCES
	"${LIB_SOURCE_DIR}/blacklist.c"
	"${LIB_SOURCE_DIR}/constraint.c"
	"${LIB_SOURCE_DIR}/logger.c"
	"${LIB_SOURCE_DIR}/pbm.c"
	"${LIB_SOURCE_DIR}/random.c"
	"${LIB_SOURCE_DIR}/rijndael-alg-fst.c"
	"${LIB_SOURCE_DIR}/stack.c"
	"${LIB_SOURCE_DIR}/util.c"
	"${LIB_SOURCE_DIR}/xalloc.c"
)



# ADD YOUR PROBE MODULE HERE
SET(EXTRA_PROBE_MODULES

	)

# ADD YOUR OUTPUT MODULE HERE
SET(EXTRA_OUTPUT_MODULES
	)

SET(OUTPUT_MODULE_SOURCES
	"${OUTPUT_MODULE_SOURCE_DIR}/module_csv.c"
	"${OUTPUT_MODULE_SOURCE_DIR}/output_modules.c"
)

SET(PROBE_MODULE_SOURCES
	"${PROBE_MODULE_SOURCE_DIR}/module_icmp_echo.c"
	"${PROBE_MODULE_SOURCE_DIR}/module_tcp_synscan.c"
	"${PROBE_MODULE_SOURCE_DIR}/module_udp.c"
	"${PROBE_MODULE_SOURCE_DIR}/packet.c"
	"${PROBE_MODULE_SOURCE_DIR}/probe_modules.c"
)

SET(ZMAP_SOURCES
	"${ZMAP_SOURCE_DIR}/aesrand.c"
	"${ZMAP_SOURCE_DIR}/cyclic.c"
	"${ZMAP_SOURCE_DIR}/expression.c"
	"${ZMAP_SOURCE_DIR}/fieldset.c"
	"${ZMAP_SOURCE_DIR}/filter.c"
	"${ZMAP_SOURCE_DIR}/get_gateway.c"
	"${ZMAP_SOURCE_DIR}/monitor.c"
	"${ZMAP_SOURCE_DIR}/recv.c"
	"${ZMAP_SOURCE_DIR}/send.c"
	"${ZMAP_SOURCE_DIR}/state.c"
	"${ZMAP_SOURCE_DIR}/validate.c"
	"${ZMAP_SOURCE_DIR}/zopt_compat.c"
)

SET(ZMAP_MAIN "${ZMAP_SOURCE_DIR}/zmap.c")

# Because CMake is too dumb to figure this out if it's not explicit, these
# are explicity stated as their own variables and added as a source to the
# executable manually.
SET(ZOPT_FILES "${ZMAP_SOURCE_DIR}/zopt.h")
SET(PARSER_FILES "${ZMAP_SOURCE_DIR}/parser.c")
SET(LEXER_FILES "${ZMAP_SOURCE_DIR}/lexer.c")

SET(SOURCES
	${ZMAP_SOURCES}
	${EXTRA_PROBE_MODULES}
	${EXTRA_OUTPUT_MODULES}
	${PROBE_MODULE_SOURCES}
	${OUTPUT_MODULE_SOURCES}
	${LIB_SOURCES}
	)

if (WITH_JSON)
	SET(SOURCES ${SOURCES} ${OUTPUT_MODULE_SOURCE_DIR}/module_json.c)
endif()

if (WITH_REDIS)
	SET(SOURCES ${SOURCES} ${LIB_SOURCE_DIR}/redis.c ${OUTPUT_MODULE_SOURCE_DIR}/module_redis.c ${OUTPUT_MODULE_SOURCE_DIR}/module_csvredis.c)
endif()

add_custom_command(OUTPUT ${ZOPT_FILES}
	COMMAND gengetopt -C --no-help --no-version --unamed-opts=SUBNETS -i "${ZMAP_SOURCE_DIR}/zopt.ggo" -F "${ZMAP_SOURCE_DIR}/zopt"
)

add_custom_command(OUTPUT ${LEXER_FILES}
	COMMAND flex -o "${ZMAP_SOURCE_DIR}/lexer.c" --header-file="${ZMAP_SOURCE_DIR}/lexer.h" "${ZMAP_SOURCE_DIR}/lexer.l"
)

add_custom_command(OUTPUT ${PARSER_FILES}
	COMMAND byacc -d -o "${ZMAP_SOURCE_DIR}/parser.c" "${ZMAP_SOURCE_DIR}/parser.y"
)

add_executable(zmap ${ZMAP_MAIN} ${SOURCES} ${ZOPT_FILES} ${LEXER_FILES} ${PARSER_FILES})

#add_dependencies(zmap generated_code)

target_link_libraries(
	zmap 
	pcap gmp m
	${REDIS_LIBS}
	${JSON_LIBRARIES}
)

# Install binary
install(
	TARGETS
	zmap
	RUNTIME DESTINATION sbin
)

# Install Manpages
install(
	FILES
	"${ZMAP_SOURCE_DIR}/zmap.1"
	DESTINATION share/man/man1
	)
