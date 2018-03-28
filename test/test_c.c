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
#include "pythia_init.h"
#include "pythia_init_c.h"

#include "unity.h"

static const char deblinded_hex[769] = "13273238e3119262f86d3213b8eb6b99c093ef48737dfcfae96210f7350e096cbc7e6b992e4e6f705ac3f0a915d1622c1644596408e3d16126ddfa9ce594e9f361b21ef9c82309e5714c09bcd7f7ec5c2666591134c645d45ed8c9703e718ee005fe4b97fc40f69b424728831d0a889cd39be04683dd380daa0df67c38279e3b9fe32f6c40780311f2dfbb6e89fc90ef15fb2c7958e387182dc7ef57f716fdd152a58ac1d3f0d19bfa2f789024333976c69fbe9e24b58d6cd8fa49c5f4d642b00f8e390c199f37f7b3125758ef284ae10fd9c2da7ea280550baccd55dadd70873a063bcfc9cac9079042af88a543a6cc09aaed6ba4954d6ee8ccc6e1145944328266616cd00f8a616f0e79e52ddd2ef970c8ba8f8ffce35505dc643c8e2b6e430a1474a6d043a4daf9b62af87c1d45ca994d23f908f7898a3f44ca7bb642122087ca819308b3d8afad17ca1f6148e8750870336ca68eb783c89b0dc9d92392f453c650e9f09232b9fcffd1c2cad24b14d2b4952b7f54552295ce0e854996913c";
static const uint8_t password[9] = "password";
static const uint8_t w[11] = "virgil.com";
static const uint8_t t[6] = "alice";
static const uint8_t msk[14] = "master secret";
static const uint8_t ssk[14] = "server secret";

void blind_eval_deblind(gt_t deblinded) {
    ep_t blinded; ep_null(blinded);
    bn_t rInv; bn_null(rInv);
    gt_t y; gt_null(y);
    bn_t kw; bn_null(kw);
    ep2_t tTilde; ep2_null(tTilde);

    TRY {
        ep_new(blinded);
        bn_new(rInv);

                        pythia_blind(password, 8, blinded, rInv);

        gt_new(y);
        bn_new(kw);
        ep2_new(tTilde);

                        pythia_transform(blinded, w, 10, t, 5, msk, 13, ssk, 13, y, kw, tTilde);

                        pythia_deblind(y, rInv, deblinded);
    }
    CATCH_ANY {
        TEST_FAIL();
    }
    FINALLY {
        ep_free(blinded);
        bn_free(rInv);
        gt_free(y);
        bn_free(kw);
        ep2_free(tTilde);
    }
}

void test1_DeblindStability() {
    TEST_ASSERT_EQUAL_INT(pythia_init(NULL), 0);
    pythia_err_init();

    gt_t deblinded1; gt_null(deblinded1);
    gt_t deblinded2; gt_null(deblinded2);

    TRY {
        gt_new(deblinded1);

        uint8_t deblinded_bin[384];
        const char *pos = deblinded_hex;
        for (size_t count = 0; count < 384; count++) {
            sscanf(pos, "%2hhx", &deblinded_bin[count]);
            pos += 2;
        }

        gt_read_bin(deblinded1, deblinded_bin, 384);

        const int iterations = 10;

        for (int i = 0; i < iterations; i++) {
            gt_new(deblinded2);
            blind_eval_deblind(deblinded2);

            TEST_ASSERT_EQUAL_INT(gt_cmp(deblinded1, deblinded2), CMP_EQ);
            gt_free(deblinded2);
        }
    }
    CATCH_ANY {
        TEST_FAIL();
    }
    FINALLY {
        gt_free(deblinded1);
        gt_free(deblinded2);
    }

    pythia_deinit();
}

void test2_BlindEvalProveVerify() {
    TEST_ASSERT_EQUAL_INT(pythia_init(NULL), 0);
    pythia_err_init();

    const uint8_t password[9] = "password";
    const uint8_t w[11] = "virgil.com";
    const uint8_t t[6] = "alice";
    const uint8_t msk[14] = "master secret";
    const uint8_t ssk[14] = "server secret";

    ep_t blinded; ep_null(blinded);
    bn_t rInv; bn_null(rInv);
    gt_t y; gt_null(y);
    bn_t kw; bn_null(kw);
    ep2_t tTilde; ep2_null(tTilde);
    g1_t p; g1_null(p);
    bn_t c; bn_null(c);
    bn_t u; bn_null(u);

    TRY {
        ep_new(blinded);
        bn_new(rInv);

                        pythia_blind(password, 8, blinded, rInv);

        gt_new(y);
        bn_new(kw);
        ep2_new(tTilde);

                        pythia_transform(blinded, w, 10, t, 5, msk, 13, ssk, 13, y, kw, tTilde);

        g1_new(p);
        bn_new(c);
        bn_new(u);

                        pythia_prove(y, blinded, tTilde, kw, p, c, u);

        int verified = 0;
                        pythia_verify(y, blinded, t, 5, p, c, u, &verified);
        TEST_ASSERT_NOT_EQUAL(verified, 0);
    }
    CATCH_ANY {
        TEST_FAIL();
    }
    FINALLY {
        bn_free(u);
        bn_free(c);
        g1_free(p);
        ep2_free(tTilde);
        bn_free(kw);
        gt_free(y);
        bn_free(rInv);
        ep_free(blinded);
    }

    pythia_deinit();
}

void test3_UpdateDelta() {
    TEST_ASSERT_EQUAL_INT(pythia_init(NULL), 0);
    pythia_err_init();

    const uint8_t password[9] = "password";
    const uint8_t w[11] = "virgil.com";
    const uint8_t t[6] = "alice";
    const uint8_t msk0[14] = "master secret";
    const uint8_t ssk[14] = "server secret";

    ep_t blinded; ep_new(blinded);
    bn_t rInv; bn_new(rInv);
    pythia_blind(password, 8, blinded, rInv);

    gt_t y; gt_new(y);

    bn_t kw; bn_new(kw);

    ep2_t tTilde; ep2_new(tTilde);

    pythia_transform(blinded, w, 10, t, 5, msk0, 13, ssk, 13, y, kw, tTilde);

    gt_t deblinded0; gt_new(deblinded0);

    pythia_deblind(y, rInv, deblinded0);

    const uint8_t msk1[14] = "secret master";

    bn_t del; bn_new(del);
    g1_t pPrime; g1_new(pPrime);

    pythia_get_password_update_token(w, 10, msk0, 13, ssk, 13, w, 10, msk1, 13, ssk, 13, del, pPrime);

    gt_t deblinded1; gt_new(deblinded1);

    pythia_update_deblinded_with_token(deblinded0, del, deblinded1);

    ep_t blinded1; ep_new(blinded1);
    bn_t rInv1; bn_new(rInv1);

    pythia_blind(password, 8, blinded1, rInv1);

    gt_t y1; gt_new(y1);
    bn_t kw1; bn_new(kw1);
    ep2_t tTilde1; ep2_new(tTilde1);

    pythia_transform(blinded1, w, 10, t, 5, msk1, 13, ssk, 13, y1, kw1, tTilde1);

    gt_t deblinded2; gt_new(deblinded2);

    pythia_deblind(y1, rInv1, deblinded2);

    TEST_ASSERT_EQUAL_INT(gt_cmp(deblinded1, deblinded2), CMP_EQ);

    g1_t p1; g1_new(p1);
    bn_t c1; bn_new(c1);
    bn_t u1; bn_new(u1);

    pythia_prove(y1, blinded1, tTilde1, kw1, p1, c1, u1);

    TEST_ASSERT_EQUAL_INT(g1_cmp(p1, pPrime), CMP_EQ);

    pythia_deinit();
}

int main() {
    UNITY_BEGIN();

    conf_print();

    RUN_TEST(test1_DeblindStability);
    RUN_TEST(test2_BlindEvalProveVerify);
    RUN_TEST(test3_UpdateDelta);

    return UNITY_END();
}
