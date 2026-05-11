cmake_minimum_required(VERSION 3.20)
project(WinSentry)

set(CMAKE_CXX_STANDARD 17)

add_executable(WinSentry WIN32 main.cpp resource.rc)

target_link_options(WinSentry PRIVATE -static)

# 链接网络相关库
target_link_libraries(WinSentry PRIVATE ws2_32 iphlpapi)