cmake_minimum_required(VERSION 3.16)

add_executable(test_gost test_gost.c)
target_link_libraries(test_gost PRIVATE gost::gost)
if(NOT MSVC)
    target_compile_options(test_gost PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME gost_vectors COMMAND test_gost)
