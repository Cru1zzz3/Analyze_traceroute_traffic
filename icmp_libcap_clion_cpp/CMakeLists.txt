cmake_minimum_required(VERSION 3.13)
project(icmp_libcap_clion_cpp)

set(CMAKE_CXX_STANDARD 11)

include (FindPCAP.cmake)

include_directories("/home/cru1zzz3/curs/libpcap-1.9.0")

SET(CMAKE_MODULE_PATH "/home/cru1zzz3/curs/icmp_libcap_clion_cpp")
find_package(PCAP)

set(SOURCE_FILES main.cpp)
add_executable(icmp_libcap_clion_cpp ${SOURCE_FILES})

target_link_libraries(icmp_libcap_clion_cpp ${PCAP_LIBRARY})



