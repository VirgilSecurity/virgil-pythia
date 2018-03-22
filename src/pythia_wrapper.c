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

#include <pythia.h>
#include <relic/relic_bn.h>
#include <pythia_init.h>
#include "pythia_wrapper.h"
#include "pythia_conf.h"
#include "pythia_buf_exports.h"

int pythia_w_blind(/*ep_t*/ pythia_buf_t *blinded, /*bn_t*/ pythia_buf_t *rInv, pythia_buf_t msg) {
    pythia_err_init();

    ep_t blinded_ep; ep_null(blinded_ep);
    bn_t rInv_bn; bn_null(rInv_bn);

    TRY {
        ep_new(blinded_ep);

        bn_new(rInv_bn);

        pythia_blind(blinded_ep, rInv_bn, msg.p, msg.allocated);

        ep_write_buf(blinded, blinded_ep);
        bn_write_buf(rInv, rInv_bn);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        bn_free(rInv_bn);
        ep_free(blinded_ep);
    }

    return 0;
}

int pythia_w_eval(/*gt_t*/ pythia_buf_t *y, /*bn_t*/ pythia_buf_t *kw, /*ep2_t*/ pythia_buf_t *tTilde,
                             pythia_buf_t w, pythia_buf_t t, /*ep_t*/ pythia_buf_t x, pythia_buf_t msk, pythia_buf_t s) {
    pythia_err_init();

    gt_t y_gt; gt_null(y_gt);
    bn_t kw_bn; bn_null(kw_bn);
    ep2_t tTilde_ep2; ep2_null(tTilde_ep2);
    ep_t x_ep; ep_null(x_ep);

    TRY {
        gt_new(y_gt);
        bn_new(kw_bn);
        ep2_new(tTilde_ep2);
        ep_new(x_ep);

        ep_read_buf(x_ep, x);

        pythia_eval(y_gt, kw_bn, tTilde_ep2, w.p, w.allocated, t.p, t.allocated, x_ep, msk.p,
                    msk.allocated, s.p, s.allocated);

        gt_write_buf(y, y_gt);
        bn_write_buf(kw, kw_bn);
        ep2_write_buf(tTilde, tTilde_ep2);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        ep_free(x_ep);
        ep2_free(tTilde_ep2);
        bn_free(kw_bn);
        gt_free(y_gt);
    }

    return 0;
}

int pythia_w_deblind(/*gt_t*/ pythia_buf_t *a, /*gt_t*/ pythia_buf_t y, /*bn_t*/ pythia_buf_t rInv) {
    pythia_err_init();

    gt_t a_gt; gt_null(a_gt);
    gt_t y_gt; gt_null(y_gt);
    bn_t rInv_bn; bn_null(rInv_bn);

    TRY {
        gt_new(a_gt);
        gt_new(y_gt);
        gt_read_buf(y_gt, y);

        bn_new(rInv_bn);
        bn_read_buf(rInv_bn, rInv);

        pythia_deblind(a_gt, y_gt, rInv_bn);

        gt_write_buf(a, a_gt);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        bn_free(rInv_bn);
        gt_free(y_gt);
        gt_free(a_gt);
    }

    return 0;
}

int pythia_w_prove(/*g1_t*/ pythia_buf_t *p, /*bn_t*/ pythia_buf_t *c, /*bn_t*/ pythia_buf_t *u, /*g1_t*/ pythia_buf_t x,
                     /*g2_t*/ pythia_buf_t tTilde, /*bn_t*/ pythia_buf_t kw, /*gt_t*/ pythia_buf_t y) {
    pythia_err_init();

    g1_t p_g1; g1_null(p_g1);
    bn_t c_bn; bn_null(c_bn);
    bn_t u_bn; bn_null(u_bn);
    g1_t x_g1; g1_null(x_g1);
    g2_t tTilde_g2; g2_null(tTilde_g2);
    bn_t kw_bn; bn_null(kw_bn);
    gt_t y_gt; gt_null(y_gt);

    TRY {
        g1_new(p_g1);
        bn_new(c_bn);
        bn_new(u_bn);
        g1_new(x_g1);
        g1_read_buf(x_g1, x);

        g2_t tTilde_g2;
        g2_new(tTilde_g2);
        g2_read_buf(tTilde_g2, tTilde);

        bn_t kw_bn;
        bn_new(kw_bn);
        bn_read_buf(kw_bn, kw);

        gt_t y_gt;
        gt_new(y_gt);
        gt_read_buf(y_gt, y);

        pythia_prove(p_g1, c_bn, u_bn, x_g1, tTilde_g2, kw_bn, y_gt);

        g1_write_buf(p, p_g1);
        bn_write_buf(c, c_bn);
        bn_write_buf(u, u_bn);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        gt_free(y_gt);
        bn_free(kw_bn);
        g2_free(tTilde_g2);
        g1_free(x_g1);
        bn_free(u_bn);
        bn_free(c_bn);
        g1_free(p_g1);
    }

    return 0;
}

int pythia_w_verify(int *verified, /*g1_t*/ pythia_buf_t x, pythia_buf_t t, /*gt_t*/ pythia_buf_t y, /*g1_t*/ pythia_buf_t p, /*bn_t*/ pythia_buf_t c, /*bn_t*/ pythia_buf_t u) {
    pythia_err_init();

    g1_t x_g1; g1_null(x_g1);
    gt_t y_gt; gt_null(y_gt);
    g1_t p_g1; g1_null(p_g1);
    bn_t c_bn; bn_null(c_bn);
    bn_t u_bn; bn_null(u_bn);

    TRY {
        g1_new(x_g1);
        g1_read_buf(x_g1, x);

        gt_new(y_gt);
        gt_read_buf(y_gt, y);

        g1_new(p_g1);
        g1_read_buf(p_g1, p);

        bn_new(c_bn);
        bn_read_buf(c_bn, c);

        bn_new(u_bn);
        bn_read_buf(u_bn, u);

        pythia_verify(verified, x_g1, t.p, t.allocated, y_gt, p_g1, c_bn, u_bn);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        gt_free(y_gt);
        g1_free(x_g1);
        bn_free(u_bn);
        bn_free(c_bn);
        g1_free(p_g1);
    }

    return 0;
}

int pythia_w_get_delta(/*bn_t*/ pythia_buf_t *delta, /*gt_t*/ pythia_buf_t *pPrime,
                                  pythia_buf_t w0, pythia_buf_t msk0, pythia_buf_t z0,
                                  pythia_buf_t w1, pythia_buf_t msk1, pythia_buf_t z1) {
    pythia_err_init();

    bn_t delta_bn; bn_null(delta_bn);
    g1_t pPrime_g1; g1_null(pPrime_g1);

    TRY {
        bn_new(delta_bn);
        g1_new(pPrime_g1);

        pythia_get_delta(delta_bn, pPrime_g1,
                         w0.p, w0.allocated, msk0.p, msk0.allocated, z0.p, z0.allocated,
                         w1.p, w1.allocated, msk1.p, msk1.allocated, z1.p, z1.allocated);

        bn_write_buf(delta, delta_bn);
        g1_write_buf(pPrime, pPrime_g1);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        g1_free(pPrime_g1);
        bn_free(delta_bn);
    }

    return 0;
}

int pythia_w_update(/*gt_t*/ pythia_buf_t *r, /*gt_t*/ pythia_buf_t z, /*bn_t*/ pythia_buf_t delta) {
    pythia_err_init();

    gt_t r_gt; gt_null(r_gt);
    gt_t z_gt; gt_null(z_gt);
    bn_t delta_bn; bn_null(delta_bn);

    TRY {
        gt_new(r_gt);
        gt_new(z_gt);
        gt_read_buf(z_gt, z);

        bn_new(delta_bn);
        bn_read_buf(delta_bn, delta);

        pythia_update(r_gt, z_gt, delta_bn);

        gt_write_buf(r, r_gt);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        bn_free(delta_bn);
        gt_free(z_gt);
        gt_free(r_gt);
    }

    return 0;
}