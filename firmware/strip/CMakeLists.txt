cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(strip)

add_custom_command(
	TARGET ${CMAKE_PROJECT_NAME}.elf
	POST_BUILD
	COMMAND ${CMAKE_STRIP} $<TARGET_FILE:${CMAKE_PROJECT_NAME}.elf>
	COMMENT "Stripping debug symbols from ${CMAKE_PROJECT_NAME}.elf")
