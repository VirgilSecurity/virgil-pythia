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

#ifndef PYTHIA_GO_PYTHIA_H
#define PYTHIA_GO_PYTHIA_H

#include "pythia_buf.h"

void go_pythia_blind(/*ep_t*/ pythia_buf_t *blinded, /*bn_t*/ pythia_buf_t *rInv, pythia_buf_t msg);

void go_pythia_eval(/*gt_t*/ pythia_buf_t *y, /*bn_t*/ pythia_buf_t *kw, /*ep2_t*/ pythia_buf_t *tTilde,
                             pythia_buf_t w, pythia_buf_t t, /*ep_t*/ pythia_buf_t x, pythia_buf_t msk, pythia_buf_t s);

void go_pythia_deblind(/*gt_t*/ pythia_buf_t *a, /*gt_t*/ pythia_buf_t y, /*bn_t*/ pythia_buf_t rInv);

void go_pythia_prove(/*g1_t*/ pythia_buf_t *p, /*bn_t*/ pythia_buf_t *c, /*bn_t*/ pythia_buf_t *u, /*g1_t*/ pythia_buf_t x,
                     /*g2_t*/ pythia_buf_t tTilde, /*bn_t*/ pythia_buf_t kw, /*gt_t*/ pythia_buf_t y);

int go_pythia_verify(/*g1_t*/ pythia_buf_t x, pythia_buf_t t, /*gt_t*/ pythia_buf_t y, /*g1_t*/ pythia_buf_t p, /*bn_t*/ pythia_buf_t c, /*bn_t*/ pythia_buf_t u);

void go_pythia_get_delta(/*bn_t*/ pythia_buf_t *delta, /*gt_t*/ pythia_buf_t *pPrime,
                                  pythia_buf_t w0, pythia_buf_t msk0, pythia_buf_t z0,
                                  pythia_buf_t w1, pythia_buf_t msk1, pythia_buf_t z1);

void go_pythia_update(/*gt_t*/ pythia_buf_t *r, /*gt_t*/ pythia_buf_t z, /*bn_t*/ pythia_buf_t delta);

#endif //PYTHIA_GO_PYTHIA_H
