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

#include <memory.h>
#include "pythia.h"
#include "unity.h"

static const char deblinded_hex[769] = "0687AC42F1B4B1C1B8427267041F6F723B57845FF537F1F7290A1897FAA9767C175CD7F612BA53DEF7B2A2DEA93B55580782D8E1A4FD00231D642ABF792A9AEB870C258CA645E8C719EBFBF96F8713EB9D118A944665C7CE475B8C0EA7AA5B3E0C2C7BC16439DB5ADB730AAD872404EBBB947278E27CD1C0358CF410E97CE460738D778D6C7C6A9CA055296B91C4CBDB0C2FC0F4C2933B82FB53F742409D8B9F819A8436993164FA721AA69E626CF52AB71FE5213EF7B0CB1D1B742AE6000E740716929E7A00A5855D1556208215F8793D288D089370CB8A67C18DACFF0C63706DD61A0D8F09CBBB0C12E64F133640CB1239F36AE48DDC72CFCDACA6F5383D8D4BDCDCAA8C13EE809D4FA850C76A81965916AFDE6CDB8E4BD41EADAC9D91E084161D917B6A9268C6A991A217ED0F4E75738F53607FA23E20D8B184A4DDAC3F36ABB4248B900ED9DCD320FDDCD943151E0C6F2C509364C02F401CB67545E3F730FF7DD31AF3E729ADAB669BDF09F65EBC5114FA35ECE725AA9658960F361234AD";
static const uint8_t password[9] = "password";
static const uint8_t w[11] = "virgil.com";
static const uint8_t t[6] = "alice";
static const uint8_t msk[14] = "master secret";
static const uint8_t ssk[14] = "server secret";

void blind_eval_deblind(pythia_buf_t *deblinded_password) {
    pythia_buf_t blinded_password, blinding_secret, transformed_password,
            transformation_private_key, transformed_tweak,
            transformation_key_id_buf, tweak_buf, pythia_secret_buf,
            pythia_scope_secret_buf, password_buf;

    blinded_password.p = (uint8_t *)malloc(PYTHIA_G1_BUF_SIZE);
    blinded_password.allocated = PYTHIA_G1_BUF_SIZE;

    blinding_secret.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    blinding_secret.allocated = PYTHIA_BN_BUF_SIZE;

    transformed_password.p = (uint8_t *)malloc(PYTHIA_GT_BUF_SIZE);
    transformed_password.allocated = PYTHIA_GT_BUF_SIZE;

    transformation_private_key.p = (uint8_t *)malloc(PYTHIA_BN_BUF_SIZE);
    transformation_private_key.allocated = PYTHIA_BN_BUF_SIZE;

    transformed_tweak.p = (uint8_t *)malloc(PYTHIA_G2_BUF_SIZE);
    transformed_tweak.allocated = PYTHIA_G2_BUF_SIZE;

    transformation_key_id_buf.p = (uint8_t *)w;
    transformation_key_id_buf.allocated = 10;

    tweak_buf.p = (uint8_t *)t;
    tweak_buf.allocated = 5;

    pythia_secret_buf.p = (uint8_t *)msk;
    pythia_secret_buf.allocated = 13;

    pythia_scope_secret_buf.p = (uint8_t *)ssk;
    pythia_scope_secret_buf.allocated = 13;

    password_buf.p = (uint8_t *)password;
    password_buf.allocated = 8;

    if (pythia_w_blind(&blinded_password, &blinding_secret, &password_buf))
        TEST_FAIL();

    if (pythia_w_transform(&transformed_password, &transformation_private_key, &transformed_tweak, &blinded_password,
                       &transformation_key_id_buf, &tweak_buf, &pythia_secret_buf, &pythia_scope_secret_buf))
        TEST_FAIL();

    if (pythia_w_deblind(deblinded_password, &transformed_password, &blinding_secret))
        TEST_FAIL();

    free(blinded_password.p);
    free(blinding_secret.p);
    free(transformed_password.p);
    free(transformation_private_key.p);
    free(transformed_tweak.p);
}

void test1_DeblindStability() {
    TEST_ASSERT_EQUAL_INT(pythia_init(NULL), 0);

    pythia_init(NULL);

    uint8_t deblinded_bin[384];
    const char *pos = deblinded_hex;
    for (size_t count = 0; count < 384; count++) {
        sscanf(pos, "%2hhx", &deblinded_bin[count]);
        pos += 2;
    }

    const int iterations = 10;

    pythia_buf_t deblinded_password;

    for (int i = 0; i < iterations; i++) {
        deblinded_password.p = (uint8_t *)malloc(PYTHIA_GT_BUF_SIZE);
        deblinded_password.allocated = PYTHIA_GT_BUF_SIZE;

        blind_eval_deblind(&deblinded_password);

        if (memcmp(deblinded_bin, deblinded_password.p, 384))
            TEST_FAIL();

        free(deblinded_password.p);
        deblinded_password.allocated = 0;
    }

    pythia_deinit();
}

int main() {
    UNITY_BEGIN();

    RUN_TEST(test1_DeblindStability);

    return UNITY_END();
}