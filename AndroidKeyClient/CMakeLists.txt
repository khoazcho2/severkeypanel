cmake_minimum_required(VERSION 3.4.1)

add_library(keyclient SHARED client_android.cpp)
find_library(log-lib log)
target_link_libraries(keyclient ${log-lib} curl uuid)
