include(CheckIPOSupported)
include(ExternalProject)

add_executable(lzmadiff lzmadiff.c)

ExternalProject_Get_Property(lzmaSDK SOURCE_DIR)
set(LZMA_C_DIR "${SOURCE_DIR}/C")

# lzmadiff depends on only a small handful of the sources in the LZMA SDK
list(APPEND LzFiles
  7zCrc 7zCrcOpt Alloc Bra86 CpuArch LzFind LzmaDec LzmaEnc
  Lzma86Dec Lzma86Enc 7zFile Lzma2Enc Sha256 Lzma2Dec
  Delta Bra BraIA64)
foreach(lzlib ${LzFiles})
  list(APPEND LzSources "${LZMA_C_DIR}/${lzlib}.c")
  set_property(SOURCE "${LZMA_C_DIR}/${lzlib}.c" PROPERTY GENERATED TRUE)
endforeach()

add_library(lzmasdk_obj OBJECT ${LzSources})
add_dependencies(lzmasdk_obj lzmaSDK)
target_compile_definitions(lzmasdk_obj PRIVATE "_7ZIP_ST")
target_include_directories(lzmasdk_obj PUBLIC "${LZMA_C_DIR}")
target_link_libraries(lzmadiff lzmasdk_obj)
#target_include_directories(lzmadiff PRIVATE "${LZMA_C_DIR}")

check_ipo_supported(RESULT result OUTPUT output)
if(result)
  set_property(TARGET lzmadiff PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
  set_property(TARGET lzmasdk_obj PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

if(MSVC)
  set(CMAKE_C_STANDARD_LIBRARIES "")
  string(REGEX REPLACE "/W[1-3]" "/W4 /WX" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wno-unknown-pragmas -Wno-multichar")
endif()
