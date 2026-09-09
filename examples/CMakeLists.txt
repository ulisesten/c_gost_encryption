cmake_minimum_required(VERSION 3.16)

add_executable(encrypt_service encrypt_service.c)
target_link_libraries(encrypt_service PRIVATE gost::gost)
if(NOT MSVC)
    target_compile_options(encrypt_service PRIVATE -Wall -Wextra -Wpedantic)
endif()
