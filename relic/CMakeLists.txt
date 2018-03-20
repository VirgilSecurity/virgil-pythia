# relic dependency
set(RELIC_LOCATION ${CMAKE_CURRENT_LIST_DIR}/relic)
set(RELIC_ARGS_FILE ${CMAKE_CURRENT_LIST_DIR}/relic-args.cmake)

if(RELIC_USE_GMP)
    set(RELIC_CMAKE_ARGS ${RELIC_CMAKE_ARGS} -DARITH=gmp)
endif()

if(ENABLE_TESTING)
    set(RELIC_CMAKE_ARGS ${RELIC_CMAKE_ARGS} -DQUIET=OFF)
endif()

if(RELIC_USE_PTHREAD)
    set(RELIC_CMAKE_ARGS ${RELIC_CMAKE_ARGS} -DMULTI=PTHREAD)
endif()

include(ExternalProject)
ExternalProject_Add(relic-ext
        GIT_REPOSITORY https://github.com/relic-toolkit/relic
        GIT_TAG e512208c8de089720fa236fba6f6dfe991a39a80
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${RELIC_LOCATION} ${RELIC_CMAKE_ARGS} -C "${RELIC_ARGS_FILE}")

add_library(relic STATIC IMPORTED GLOBAL)
add_dependencies(relic relix-ext)
file(MAKE_DIRECTORY ${RELIC_LOCATION}/include)
set_target_properties(relic PROPERTIES
        IMPORTED_LOCATION ${RELIC_LOCATION}/lib/librelic_s.a
        INTERFACE_INCLUDE_DIRECTORIES ${RELIC_LOCATION}/include)
