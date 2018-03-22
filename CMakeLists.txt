#
# Copyright (C) 2015-2018 Virgil Security Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#

cmake_minimum_required(VERSION 3.8)

project(pythia C)
set(CMAKE_C_STANDARD 99)

# ---------------------------------------------------------------------------
#   Options
# ---------------------------------------------------------------------------
option(ENABLE_TESTING "Defines whether include unit testing or not." OFF)

option(RELIC_USE_GMP "Defines whether use gmp arithmetic or relic" OFF)
option(RELIC_AUTO_INIT "Defines whether relic core_init should be called automatically before every operation" ON)
option(RELIC_AUTO_DEINIT "Defines whether relic core_clean should be called automatically after every operation" ON)
option(RELIC_USE_PTHREAD "Defines whether to enable relic multithreading using pthread" ON)

# ---------------------------------------------------------------------------
#   Helpers
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# ---------------------------------------------------------------------------
#   Dependencies
# ---------------------------------------------------------------------------
if(RELIC_USE_GMP)
    find_package(GMP REQUIRED)

    if(NOT GMP_FOUND)
        message(FATAL_ERROR "Library GMP is required, but not found.")
    endif()
endif()

add_subdirectory(relic)

# ---------------------------------------------------------------------------
#   Library
# ---------------------------------------------------------------------------
add_library(pythia "")
set_target_properties (pythia PROPERTIES DEBUG_POSTFIX "_d")

configure_file(
        ${CMAKE_CURRENT_LIST_DIR}/include/pythia_conf.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/include/pythia_conf.h @ONLY)


target_sources(pythia
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include/pythia.h
        ${CMAKE_CURRENT_LIST_DIR}/include/pythia_buf.h
        ${CMAKE_CURRENT_LIST_DIR}/include/pythia_init.h
        ${CMAKE_CURRENT_LIST_DIR}/include/go_pythia.h
        ${CMAKE_BINARY_DIR}/include/pythia_conf.h

        ${CMAKE_CURRENT_LIST_DIR}/src/pythia.c
        ${CMAKE_CURRENT_LIST_DIR}/src/go_pythia.c)


target_include_directories(pythia
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        PUBLIC $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
        PUBLIC $<BUILD_INTERFACE:${GMP_INCLUDES}>
        PUBLIC $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

add_dependencies(pythia relic-ext)
target_link_libraries(pythia PUBLIC relic)

if(RELIC_USE_GMP AND GMP_FOUND)
    target_link_libraries(pythia PRIVATE ${GMP_LIBRARIES})
endif()

# ---------------------------------------------------------------------------
#   Tests
# ---------------------------------------------------------------------------
if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

# ---------------------------------------------------------------------------
#   Install
# ---------------------------------------------------------------------------
install(TARGETS pythia EXPORT pythia
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(EXPORT pythia
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/pythia"
        COMPONENT dev)

install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/include/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        COMPONENT dev
        FILES_MATCHING PATTERN "*.h")

install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        COMPONENT dev
        FILES_MATCHING PATTERN "*.h")
