cmake_minimum_required(VERSION 3.8)
project(pythia C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(relic)
add_subdirectory(src)

# flags
set(ENABLE_TESTING OFF CACHE BOOL "Defines whether include unit testing or not.")

set(RELIC_USE_GMP OFF CACHE BOOL "Defines whether use gmp arithmetic or relic.")
set(RELIC_FORCE_REINIT ON CACHE BOOL "Defines whether relic core_init&core_clean should be called on evey operation")
set(RELIC_USE_PTHREAD ON CACHE BOOL  "Defines whether to enable relic multithreading using pthread")

if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/pythia_conf.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/include/pythia_conf.h @ONLY)