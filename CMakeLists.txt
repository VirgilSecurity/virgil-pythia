cmake_minimum_required(VERSION 3.8)
project(pythia C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(relic)
add_subdirectory(src)

# flags
option(ENABLE_TESTING "Defines whether include unit testing or not." OFF)

option(RELIC_USE_GMP "Defines whether use gmp arithmetic or relic." OFF)
option(RELIC_FORCE_REINIT "Defines whether relic core_init and core_clean should be called on evey operation" ON)
option(RELIC_USE_PTHREAD "Defines whether to enable relic multithreading using pthread" ON)

if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/include/pythia_conf.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/include/pythia_conf.h @ONLY)
