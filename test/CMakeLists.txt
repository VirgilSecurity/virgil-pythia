file(GLOB_RECURSE TEST_SOURCE_FILES ${CMAKE_SOURCE_DIR}/test/test.c)

add_subdirectory(unity)

add_executable(pythia_test ${TEST_SOURCE_FILES})

target_include_directories(pythia_test PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(pythia_test pythia unity)

if(RELIC_USE_GMP)
    find_library(GMP_LIBRARIES NAMES libgmp.a gmp)
    target_link_libraries(pythia_test ${GMP_LIBRARIES})
endif()


add_test(pythia_test_target pythia_test)