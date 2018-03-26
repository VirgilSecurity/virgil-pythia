/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#ifndef PYTHIA_PYTHIA_BUF_H
#define PYTHIA_PYTHIA_BUF_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Byte buffers used to pass data to/from pythia library
typedef struct pythia_buf {
    uint8_t *p;         /// Byte array pointer
    int allocated;      /// Number of allocated bytes
    int len;            /// Returned size
} pythia_buf_t;

/// Creates new emoty pythia buffer (WARNING: Memory for actual byte array is not allocated here)
/// \return allocated empty pythia buffer
inline pythia_buf_t *pythia_buf_new(void) {
    pythia_buf_t *buf = (pythia_buf_t *)malloc(sizeof(pythia_buf_t));
    buf->p = NULL;
    buf->allocated = 0;
    buf->len = 0;

    return buf;
}

/// Frees pythia buffer (WARNING: Doesn't free actual buffer memory, only memory needed for pythia_buf instance itself)
inline void pythia_buf_free(pythia_buf_t *buf) {
    free(buf);
}

/// Initializes pythia buffer with given values
/// \param buf pythia buffer to be initialized
/// \param p byte array pointer
/// \param allocated number of allocated bytes
/// \param len returning length
inline void pythia_buf_setup(pythia_buf_t *buf, uint8_t *p, int allocated, int len) {
    buf->p = p;
    buf->allocated = allocated;
    buf->len = len;
}

#ifdef __cplusplus
}
#endif

#endif //PYTHIA_PYTHIA_BUF_H
