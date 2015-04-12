project(twamp-wireshark-plugin C)

cmake_minimum_required(VERSION 2.6)
set(CMAKE_BACKWARDS_COMPATIBILITY 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
set(CMAKE_INSTALL_LIBDIR ~/.wireshark)

INCLUDE(UseMakeDissectorReg)
  
set(GLIB2_MIN_VERSION 2.4.0)

find_package(GLIB2)
include_directories (${GLIB2_INCLUDE_DIRS})

find_package(Wireshark)
include_directories (${WIRESHARK_INCLUDE_DIRS})

set(LINK_MODE_LIB SHARED)
set(LINK_MODE_MODULE MODULE)


set(DISSECTOR_SRC
	packet-twamp.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_dissector_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_library(twamp ${LINK_MODE_MODULE}
	${PLUGIN_FILES}
)
set_target_properties(twamp PROPERTIES PREFIX "")
set_target_properties(twamp PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

target_link_libraries(twamp wireshark)

install(TARGETS twamp
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/plugins NAMELINK_SKIP
)

