include(CheckIPOSupported)
include(ExternalProject)

ExternalProject_Get_Property(lzmaSDK SOURCE_DIR)
set(LZMA_C_DIR "${SOURCE_DIR}/C")

add_executable(lzmapatch "lzmapatch.c" "${LZMA_C_DIR}/Sha256.c")
set_property(SOURCE "${LZMA_C_DIR}/Sha256.c" PROPERTY GENERATED TRUE)
add_dependencies(lzmapatch lzmaSDK minlzlib)
target_link_libraries(lzmapatch minlzlib)

check_ipo_supported(RESULT result OUTPUT output)
if(result)
  set_property(TARGET lzmapatch PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

if(MSVC)
    set(CMAKE_C_STANDARD_LIBRARIES "")
    string(REGEX REPLACE "/W[1-3]" "/W4 /WX" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wno-multichar")
endif()
