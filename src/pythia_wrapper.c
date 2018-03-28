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

#include "pythia_c.h"
#include "pythia_buf_exports.h"
#include "pythia_conf.h"
#include "pythia_init.h"
#include "pythia_init_c.h"
#include "pythia_wrapper.h"

#include <relic/relic_bn.h>

int pythia_w_blind(pythia_buf_t *blinded_password, pythia_buf_t *blinding_secret, const pythia_buf_t *password) {
    pythia_err_init();

    g1_t blinded_ep; g1_null(blinded_ep);
    bn_t rInv_bn; bn_null(rInv_bn);

    TRY {
        g1_new(blinded_ep);
        bn_new(rInv_bn);

        pythia_blind(blinded_ep, rInv_bn, password->p, password->len);

        g1_write_buf(blinded_password, blinded_ep);
        bn_write_buf(blinding_secret, rInv_bn);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        bn_free(rInv_bn);
        g1_free(blinded_ep);
    }

    return 0;
}

int pythia_w_transform(pythia_buf_t *transformed_password, pythia_buf_t *transformation_private_key,
                       pythia_buf_t *transformed_tweak, const pythia_buf_t *blinded_password,
                       const pythia_buf_t *transformation_key_id, const pythia_buf_t *tweak,
                       const pythia_buf_t *pythia_secret, const pythia_buf_t *pythia_scope_secret) {
    pythia_err_init();

    gt_t y_gt; gt_null(y_gt);
    bn_t kw_bn; bn_null(kw_bn);
    g2_t tTilde_g2; g2_null(tTilde_g2);
    g1_t x_ep; g1_null(x_ep);

    TRY {
        gt_new(y_gt);
        bn_new(kw_bn);
        g2_new(tTilde_g2);
        g1_new(x_ep);

        g1_read_buf(x_ep, blinded_password);

        pythia_transform(y_gt, kw_bn, tTilde_g2, x_ep, transformation_key_id->p,
                         transformation_key_id->len, tweak->p, tweak->len, pythia_secret->p,
                         pythia_secret->len, pythia_scope_secret->p, pythia_scope_secret->len);

        gt_write_buf(transformed_password, y_gt);
        bn_write_buf(transformation_private_key, kw_bn);
        g2_write_buf(transformed_tweak, tTilde_g2);
    }
    CATCH_ANY {
        pythia_err_init();

        return -1;
    }
    FINALLY {
        g1_free(x_ep);
        g2_free(tTilde_g2);
        bn_free(kw_bn);
        gt_free(y_gt);
    }

    return 0;
}

int pythia_w_deblind(pythia_buf_t *deblinded_password,
                     const pythia_buf_t *transformed_password, const pythia_buf_t *blinding_secret) {
    pythia_err_init();

    gt_t a_gt; gt_null(a_gt);
    gt_t y_gt; gt_null(y_gt);
    bn_t rInv_bn; bn_null(rInv_bn);

    TRY {
        gt_new(a_gt);
        gt_new(y_gt);
        gt_read_buf(y_gt, transformed_password);

        bn_new(rInv_bn);
        bn_read_buf(rInv_bn, blinding_secret);

        pythia_deblind(a_gt, y_gt, rInv_bn);

        gt_write_buf(deblinded_password, a_gt);
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

int pythia_w_prove(pythia_buf_t *transformation_public_key, pythia_buf_t *proof_value_c, pythia_buf_t *proof_value_u,
                   const pythia_buf_t *transformed_password, const pythia_buf_t *blinded_password,
                   const pythia_buf_t *transformed_tweak, const pythia_buf_t *transformation_private_key) {
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
        g1_read_buf(x_g1, blinded_password);

        g2_t tTilde_g2;
        g2_new(tTilde_g2);
        g2_read_buf(tTilde_g2, transformed_tweak);

        bn_t kw_bn;
        bn_new(kw_bn);
        bn_read_buf(kw_bn, transformation_private_key);

        gt_t y_gt;
        gt_new(y_gt);
        gt_read_buf(y_gt, transformed_password);

        pythia_prove(p_g1, c_bn, u_bn, y_gt, x_g1, tTilde_g2, kw_bn);

        g1_write_buf(transformation_public_key, p_g1);
        bn_write_buf(proof_value_c, c_bn);
        bn_write_buf(proof_value_u, u_bn);
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

int pythia_w_verify(int *verified, const pythia_buf_t *transformed_password, const pythia_buf_t *blinded_password,
                    const pythia_buf_t *tweak, const pythia_buf_t *transformation_public_key,
                    const pythia_buf_t *proof_value_c, const pythia_buf_t *proof_value_u) {
    pythia_err_init();

    g1_t x_g1; g1_null(x_g1);
    gt_t y_gt; gt_null(y_gt);
    g1_t p_g1; g1_null(p_g1);
    bn_t c_bn; bn_null(c_bn);
    bn_t u_bn; bn_null(u_bn);

    TRY {
        g1_new(x_g1);
        g1_read_buf(x_g1, blinded_password);

        gt_new(y_gt);
        gt_read_buf(y_gt, transformed_password);

        g1_new(p_g1);
        g1_read_buf(p_g1, transformation_public_key);

        bn_new(c_bn);
        bn_read_buf(c_bn, proof_value_c);

        bn_new(u_bn);
        bn_read_buf(u_bn, proof_value_u);

        pythia_verify(verified, y_gt, x_g1, tweak->p, tweak->len, p_g1, c_bn, u_bn);
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

int pythia_w_get_password_update_token(pythia_buf_t *password_update_token, pythia_buf_t *updated_transformation_public_key,
                                       const pythia_buf_t *previous_transformation_key_id, const pythia_buf_t *previous_pythia_secret, const pythia_buf_t *previous_pythia_scope_secret,
                                       const pythia_buf_t *new_transformation_key_id, const pythia_buf_t *new_pythia_secret, const pythia_buf_t *new_pythia_scope_secret) {
    pythia_err_init();

    bn_t delta_bn; bn_null(delta_bn);
    g1_t pPrime_g1; g1_null(pPrime_g1);

    TRY {
        bn_new(delta_bn);
        g1_new(pPrime_g1);

        pythia_get_password_update_token(delta_bn, pPrime_g1,
                                         previous_transformation_key_id->p, previous_transformation_key_id->len,
                                         previous_pythia_secret->p, previous_pythia_secret->len,
                                         previous_pythia_scope_secret->p, previous_pythia_scope_secret->len,
                                         new_transformation_key_id->p, new_transformation_key_id->len,
                                         new_pythia_secret->p, new_pythia_secret->len,
                                         new_pythia_scope_secret->p, new_pythia_scope_secret->len);

        bn_write_buf(password_update_token, delta_bn);
        g1_write_buf(updated_transformation_public_key, pPrime_g1);
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

int pythia_w_update_deblinded_with_token(pythia_buf_t *updated_deblinded_password,
                                         const pythia_buf_t *deblinded_password,
                                         const pythia_buf_t *password_update_token) {
    pythia_err_init();

    gt_t r_gt; gt_null(r_gt);
    gt_t z_gt; gt_null(z_gt);
    bn_t delta_bn; bn_null(delta_bn);

    TRY {
        gt_new(r_gt);
        gt_new(z_gt);
        gt_read_buf(z_gt, deblinded_password);

        bn_new(delta_bn);
        bn_read_buf(delta_bn, password_update_token);

        pythia_update_deblinded_with_token(r_gt, z_gt, delta_bn);

        gt_write_buf(updated_deblinded_password, r_gt);
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
