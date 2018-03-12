# pythia library
file(GLOB_RECURSE SOURCE_FILES ${CMAKE_SOURCE_DIR}/include/*.h ${CMAKE_SOURCE_DIR}/src/*.c)
add_library(pythia ${SOURCE_FILES})

add_dependencies(pythia relic)

target_include_directories(pythia PUBLIC
        ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(pythia relic-lib)

if(USE_GMP)
    find_library(GMP_LIBRARIES NAMES libgmp.a gmp)
    target_link_libraries(pythia ${GMP_LIBRARIES})
endif()



