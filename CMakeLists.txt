cmake_minimum_required(VERSION 3.11)
project(memcache_sniffer)

set(CMAKE_CXX_STANDARD 17)

add_executable(memcache_sniffer main.cpp protocols_headers.h memcached_protocol.h)

target_link_libraries(memcache_sniffer pcap)
