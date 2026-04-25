cmake_minimum_required(VERSION 3.12)
project(opentrackio_server CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(opentrackio_server opentrackio_server.cpp)

if(MSVC)
    target_compile_options(opentrackio_server PRIVATE /W4 /permissive-)
else()
    target_compile_options(opentrackio_server PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    target_link_libraries(opentrackio_server PRIVATE ws2_32)
endif()
