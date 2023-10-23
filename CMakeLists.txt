cmake_minimum_required(VERSION 3.24)
project(SelfModifyingBehavior C)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

set(CMAKE_C_STANDARD 99)

add_executable(SelfModifyingBehavior main.c utils.h utils.c dynarr.h dynarr.c)
target_link_libraries(SelfModifyingBehavior PRIVATE Zydis)
