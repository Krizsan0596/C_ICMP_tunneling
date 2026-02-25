cmake_minimum_required(VERSION 3.16)
project(icmp_tunnel C)

set(CMAKE_C_STANDARD 11)

# Static libraries
add_library(util STATIC lib/util.c)
target_include_directories(util PUBLIC lib)

add_library(sender STATIC lib/sender.c)
target_include_directories(sender PUBLIC lib)
target_link_libraries(sender PRIVATE util pthread)

add_library(receiver STATIC lib/receiver.c)
target_include_directories(receiver PUBLIC lib)
target_link_libraries(receiver PRIVATE util)

# Executables
add_executable(client src/client.c)
target_link_libraries(client PRIVATE receiver util)

add_executable(server src/server.c)
target_link_libraries(server PRIVATE sender util pthread)
