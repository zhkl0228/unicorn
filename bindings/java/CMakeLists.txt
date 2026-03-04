cmake_minimum_required(VERSION 2.8.12)
project(unicorn_java C)

find_package(JNI REQUIRED)

set(UNICORN_HOME "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH "Path to unicorn source tree")
set(UNICORN_BUILD "${UNICORN_HOME}/build" CACHE PATH "Path to unicorn build tree")

add_library(unicorn_java SHARED
    unicorn_Unicorn.c
)

target_include_directories(unicorn_java PRIVATE
    ${UNICORN_HOME}/include
    ${JNI_INCLUDE_DIRS}
)

set_target_properties(unicorn_java PROPERTIES C_STANDARD 99)
target_compile_options(unicorn_java PRIVATE -O3 -DNDEBUG)

target_link_libraries(unicorn_java PRIVATE
    ${UNICORN_BUILD}/libunicorn.a
    ${UNICORN_BUILD}/libarm-softmmu.a
    ${UNICORN_BUILD}/libarmeb-softmmu.a
    ${UNICORN_BUILD}/libaarch64-softmmu.a
    ${UNICORN_BUILD}/libaarch64eb-softmmu.a
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(unicorn_java PRIVATE rt)
endif()
