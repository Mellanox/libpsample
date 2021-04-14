cmake_minimum_required(VERSION 3.3)
set (CMAKE_BUILD_TYPE Debug)
enable_language (C)
include ("GNUInstallDirs")

project (libpsample)
set (LIBPSAMPLE_MAJOR_VERSION 1)
set (LIBPSAMPLE_MINOR_VERSION 0)
set (LIBPSAMPLE_API_VERSION 1)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

## libpsample library
add_library (psample SHARED src/psample.c src/mnlg.c)
target_link_libraries (psample mnl -lpcap)
target_include_directories (psample PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties (psample PROPERTIES
	VERSION ${LIBPSAMPLE_MAJOR_VERSION}.${LIBPSAMPLE_MINOR_VERSION}
	SOVERSION ${LIBPSAMPLE_API_VERSION}
)

## test executable
add_executable (psample_tool psample_tool/psample.c)
target_include_directories (psample_tool PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries (psample_tool psample)
set_target_properties(psample_tool PROPERTIES OUTPUT_NAME psample)

## install
install (TARGETS psample DESTINATION ${CMAKE_INSTALL_LIBDIR})
install (TARGETS psample_tool DESTINATION ${CMAKE_INSTALL_BINDIR})
install (FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/psample.h DESTINATION
	${CMAKE_INSTALL_INCLUDEDIR})
install (FILES ${CMAKE_CURRENT_SOURCE_DIR}/man/psample.8 DESTINATION
	${CMAKE_INSTALL_MANDIR}/man8)

