cmake_minimum_required( VERSION 3.16 )

project( finoa_xtz )

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

add_subdirectory( src )
add_subdirectory( test )