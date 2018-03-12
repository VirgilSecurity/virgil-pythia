cmake_minimum_required(VERSION 3.8)
project(pythia C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(relic)
add_subdirectory(src)

# flags
set(ENABLE_TESTING OFF CACHE BOOL "Defines whether include unit testing or not.")
set(USE_GMP OFF CACHE BOOL "Defines whether use gmp arithmetic or relic.")

if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()