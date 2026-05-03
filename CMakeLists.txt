cmake_minimum_required(VERSION 3.20)
project(.)

set(CMAKE_CXX_STANDARD 17)

add_executable(WinSentry WIN32 main.cpp)

target_link_options(WinSentry PRIVATE -static)

target_link_libraries(WinSentry PRIVATE iphlpapi)