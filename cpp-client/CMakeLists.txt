cmake_minimum_required(VERSION 3.12)
project(opentrackio_client CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(opentrackio_client opentrackio_client.cpp)

if(MSVC)
    target_compile_options(opentrackio_client PRIVATE /W4 /permissive-)
else()
    target_compile_options(opentrackio_client PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    target_link_libraries(opentrackio_client PRIVATE ws2_32)
endif()
