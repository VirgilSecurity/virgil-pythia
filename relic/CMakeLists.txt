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
        GIT_REPOSITORY https://github.com/VirgilSecurity/relic
        GIT_TAG e512208c8de089720fa236fba6f6dfe991a39a80
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${RELIC_LOCATION} ${RELIC_CMAKE_ARGS} -C "${RELIC_ARGS_FILE}")

add_library(relic STATIC IMPORTED GLOBAL)
add_dependencies(relic relix-ext)
file(MAKE_DIRECTORY ${RELIC_LOCATION}/include)
set_target_properties(relic PROPERTIES
        IMPORTED_LOCATION ${RELIC_LOCATION}/lib/librelic_s.a
        INTERFACE_INCLUDE_DIRECTORIES ${RELIC_LOCATION}/include)
