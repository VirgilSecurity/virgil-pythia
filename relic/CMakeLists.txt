# relic dependency
set(RELIC_LOCATION ${CMAKE_CURRENT_LIST_DIR}/relic)
set(RELIC_ARGS_FILE ${CMAKE_CURRENT_LIST_DIR}/relic-args.cmake)

if(USE_GMP)
    set(RELIC_CMAKE_ARGS ${RELIC_CMAKE_ARGS} -DARITH=gmp)
endif()

include(ExternalProject)
ExternalProject_Add(relic
        GIT_REPOSITORY https://github.com/relic-toolkit/relic
        GIT_TAG 602605f1fccda1a9208c6e69e7f2a14688f2be1f
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${RELIC_LOCATION} -C "${RELIC_ARGS_FILE}")

add_library(relic-lib STATIC IMPORTED GLOBAL)
target_link_libraries(relic-lib)
file(MAKE_DIRECTORY ${RELIC_LOCATION}/include)
set_target_properties(relic-lib PROPERTIES
        IMPORTED_LOCATION ${RELIC_LOCATION}/lib/librelic_s.a
        INTERFACE_INCLUDE_DIRECTORIES ${RELIC_LOCATION}/include)
