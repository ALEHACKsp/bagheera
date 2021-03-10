#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "asmjit::asmjit" for configuration ""
set_property(TARGET asmjit::asmjit APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(asmjit::asmjit PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libasmjit.so"
  IMPORTED_SONAME_NOCONFIG "libasmjit.so"
  )

list(APPEND _IMPORT_CHECK_TARGETS asmjit::asmjit )
list(APPEND _IMPORT_CHECK_FILES_FOR_asmjit::asmjit "${_IMPORT_PREFIX}/lib/libasmjit.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
