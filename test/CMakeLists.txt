cmake_minimum_required( VERSION 3.16 )

project( finoa_xtz_tests CXX )

set( TEST_SRC
    unitTests.cpp
    ../src/finoa_xtz.c
    third_party/BLAKE2/sse/blake2b.c
    third_party/sha-2/sha-256.c
    third_party/libbase58/base58.c
)

add_executable( finoa_xtz_tests ${TEST_SRC} )
target_include_directories( finoa_xtz_tests PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} )
target_link_libraries( finoa_xtz_tests finoa_xtz ssl crypto )

set_target_properties( finoa_xtz PROPERTIES COMPILE_DEFINITIONS "DEFAULT_CONFIG" )
set_target_properties( finoa_xtz_tests PROPERTIES COMPILE_DEFINITIONS "DEFAULT_CONFIG" )
target_include_directories( finoa_xtz PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party )
