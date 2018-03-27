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

#include <relic/relic.h>
#include <relic/relic_err.h>
#include "pythia_buf.h"
#include "pythia_buf_exports.h"

void check_size(const pythia_buf_t *buf, int size) {
    if (!buf || buf->allocated < size)
        THROW(ERR_NO_BUFFER);
}

void bn_read_buf(bn_t b, const pythia_buf_t *buf) {
    check_size(buf, 2);
    bn_read_bin(b, buf->p + 1, buf->len - 1);
    b->sign = buf->p[0];
}

void gt_read_buf(gt_t g, const pythia_buf_t *buf) {
    check_size(buf, 1);
    gt_read_bin(g, buf->p, buf->len);
}

void g1_read_buf(g1_t g, const pythia_buf_t *buf) {
    check_size(buf, 1);
    g1_read_bin(g, buf->p, buf->len);
}

void g2_read_buf(g2_t g, const pythia_buf_t *buf) {
    check_size(buf, 1);
    g2_read_bin(g, buf->p, buf->len);
}

void bn_write_buf(pythia_buf_t *buf, bn_t b) {
    int size = bn_size_bin(b) + 1;
    check_size(buf, size);
    bn_write_bin(buf->p + 1, size - 1, b);
    buf->p[0] = (uint8_t )b->sign;
    buf->len = size;
}

void g2_write_buf(pythia_buf_t *buf, g2_t e) {
    int size = g2_size_bin(e, 1);
    check_size(buf, size);
    g2_write_bin(buf->p, size, e, 1);
    buf->len = size;
}

void gt_write_buf(pythia_buf_t *buf, gt_t g) {
    int size = gt_size_bin(g, 1);
    check_size(buf, size);
    gt_write_bin(buf->p, size, g, 1);
    buf->len = size;
}

void g1_write_buf(pythia_buf_t *buf, g1_t g) {
    int size = g1_size_bin(g, 1);
    check_size(buf, size);
    g1_write_bin(buf->p, size, g, 1);
    buf->len = size;
}
