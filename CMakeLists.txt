cmake_minimum_required(VERSION 3.12)

project(lzmadiffpatch VERSION 1.0)

include(CMakeDependentOption)
include(FindPython)
find_package(Python COMPONENTS Interpreter)

include(ExternalProject)

enable_testing()

set(LZMA_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lzma1900" CACHE PATH
  "Existing LZMA SDK directory")

if(IS_DIRECTORY "${LZMA_SOURCE_DIR}")
  set(USE_EXISTING_LZMA_DIR ON CACHE BOOL "Use existing LZMA SDK dir")
else()
  set(USE_EXISTING_LZMA_DIR OFF CACHE BOOL "Use existing LZMA SDK dir")
endif()

cmake_dependent_option(LZMA_APPLY_PATCH "Apply lzma SDK patch" OFF
  USE_EXISTING_LZMA_DIR ON)


if(LZMA_APPLY_PATCH OR NOT USE_EXISTING_LZMA_DIR)
  set(LZMA_PATCH_COMMAND "${Python_EXECUTABLE};${CMAKE_SOURCE_DIR}/patch.py;\
-p;2;-d;<SOURCE_DIR>;${CMAKE_SOURCE_DIR}/lzma1900.diff")
else()
  set(LZMA_PATCH_COMMAND "")
endif()

if(USE_EXISTING_LZMA_DIR)
  ExternalProject_Add(lzmaSDK
    SOURCE_DIR "${LZMA_SOURCE_DIR}"
    BUILD_IN_SOURCE 1
    UPDATE_COMMAND      ""
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    PATCH_COMMAND       "${LZMA_PATCH_COMMAND}"
    )
else()
  ExternalProject_Add(lzmaSDK
    URL https://www.7-zip.org/a/lzma1900.7z
    URL_HASH SHA256=00f569e624b3d9ed89cf8d40136662c4c5207eaceb92a70b1044c77f84234bad
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    PATCH_COMMAND       "${LZMA_PATCH_COMMAND}"
    )
endif()


ExternalProject_Add(minlzma
  GIT_REPOSITORY  "https://github.com/ionescu007/minlzma"
  GIT_TAG         "refs/tags/v1.1.5"
  GIT_SHALLOW     TRUE
  PREFIX          minlzma
  BUILD_COMMAND   "${CMAKE_COMMAND}" --build <BINARY_DIR> --target minlzlib
  # No install() is specified for minlzma, so 
  INSTALL_COMMAND ""
  )

ExternalProject_Get_Property(minlzma BINARY_DIR)
ExternalProject_Get_Property(minlzma SOURCE_DIR)
add_library(minlzlib STATIC IMPORTED)
set_property(TARGET minlzlib PROPERTY IMPORTED_LOCATION
  "${BINARY_DIR}/minlzlib/${CMAKE_CFG_INTDIR}/\
${CMAKE_STATIC_LIBRARY_PREFIX}minlzlib${CMAKE_STATIC_LIBRARY_SUFFIX}")
add_dependencies(minlzlib minlzma)
target_include_directories(minlzlib INTERFACE "${SOURCE_DIR}")

add_subdirectory(lzmadiff)
add_subdirectory(lzmapatch)

install(TARGETS lzmadiff lzmapatch RUNTIME DESTINATION bin)

# These two fake "test" targets are so that "make test" builds the
# stuff you'd expect it to before running the test.
# See https://stackoverflow.com/a/10824578
add_test(
  NAME lzdp_build_lzmadiff
  COMMAND "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR} --target lzmadiff)
add_test(
  NAME lzdp_build_lzmapatch
  COMMAND "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR} --target lzmapatch)

# The real test
add_test(
  NAME lzdptest
  COMMAND ${Python_EXECUTABLE} ${CMAKE_SOURCE_DIR}/lzdptest.py
          --diff $<TARGET_FILE:lzmadiff> --patch $<TARGET_FILE:lzmapatch>
  )
SET_TESTS_PROPERTIES(lzdptest
  PROPERTIES DEPENDS "lzdp_build_lzmapatch;lzdp_build_lzmadiff")

