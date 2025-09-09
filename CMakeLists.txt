cmake_minimum_required(VERSION 3.15)
project(MySSHServer)

# Enable server support for libssh
add_definitions(-DWITH_SERVER)

# Find libssh via vcpkg
find_package(libssh CONFIG REQUIRED)

add_executable(main src/main.cpp)
target_link_libraries(main PRIVATE ssh)
