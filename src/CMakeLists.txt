set( LIB_SRC
    finoa_xtz.c
    finoa_xtz_utils.c
)

add_library( finoa_xtz STATIC ${LIB_SRC} )
target_include_directories( finoa_xtz PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} )