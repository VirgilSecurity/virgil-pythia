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

#include "unity.h"
#include "pythia.h"
#include <relic/relic.h>
#include <pthread.h>
#include <unistd.h>
#include <memory.h>
#include <pythia_init_c.h>

static int finished = 0;

static const char deblinded_hex[769] = "13273238e3119262f86d3213b8eb6b99c093ef48737dfcfae96210f7350e096cbc7e6b992e4e6f705ac3f0a915d1622c1644596408e3d16126ddfa9ce594e9f361b21ef9c82309e5714c09bcd7f7ec5c2666591134c645d45ed8c9703e718ee005fe4b97fc40f69b424728831d0a889cd39be04683dd380daa0df67c38279e3b9fe32f6c40780311f2dfbb6e89fc90ef15fb2c7958e387182dc7ef57f716fdd152a58ac1d3f0d19bfa2f789024333976c69fbe9e24b58d6cd8fa49c5f4d642b00f8e390c199f37f7b3125758ef284ae10fd9c2da7ea280550baccd55dadd70873a063bcfc9cac9079042af88a543a6cc09aaed6ba4954d6ee8ccc6e1145944328266616cd00f8a616f0e79e52ddd2ef970c8ba8f8ffce35505dc643c8e2b6e430a1474a6d043a4daf9b62af87c1d45ca994d23f908f7898a3f44ca7bb642122087ca819308b3d8afad17ca1f6148e8750870336ca68eb783c89b0dc9d92392f453c650e9f09232b9fcffd1c2cad24b14d2b4952b7f54552295ce0e854996913c";
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
    transformation_key_id_buf.len = 10;

    tweak_buf.p = (uint8_t *)t;
    tweak_buf.len = 5;

    pythia_secret_buf.p = (uint8_t *)msk;
    pythia_secret_buf.len = 13;

    pythia_scope_secret_buf.p = (uint8_t *)ssk;
    pythia_scope_secret_buf.len = 13;

    password_buf.p = (uint8_t *)password;
    password_buf.len = 8;

    if (pythia_w_blind(&password_buf, &blinded_password, &blinding_secret))
        TEST_FAIL();

    if (pythia_w_transform(&blinded_password, &transformation_key_id_buf, &tweak_buf, &pythia_secret_buf,
                           &pythia_scope_secret_buf, &transformed_password, &transformation_private_key,
                           &transformed_tweak))
        TEST_FAIL();

    if (pythia_w_deblind(&transformed_password, &blinding_secret, deblinded_password))
        TEST_FAIL();

    free(blinded_password.p);
    free(blinding_secret.p);
    free(transformed_password.p);
    free(transformation_private_key.p);
    free(transformed_tweak.p);
}

void deblind_stability() {
    uint8_t deblinded_bin[384];
    const char *pos = deblinded_hex;
    for (size_t count = 0; count < 384; count++) {
        sscanf(pos, "%2hhx", &deblinded_bin[count]);
        pos += 2;
    }

    pythia_buf_t deblinded_password;

    deblinded_password.p = (uint8_t *)malloc(PYTHIA_GT_BUF_SIZE);
    deblinded_password.allocated = PYTHIA_GT_BUF_SIZE;

    blind_eval_deblind(&deblinded_password);

    TEST_ASSERT_EQUAL_MEMORY(deblinded_bin, deblinded_password.p, 384);

    free(deblinded_password.p);
    deblinded_password.allocated = 0;
}

void *pythia_succ(void *ptr) {
    while (!finished) {
        deblind_stability();
    }

    return NULL;
}

void *pythia_err(void *ptr) {
    while (!finished) {
        int caught = 0;

        pythia_err_init();

        TRY {
            THROW(ERR_NO_BUFFER);
        }
        CATCH_ANY {
            caught = 1;
        }
        FINALLY {};

        TEST_ASSERT_NOT_EQUAL(0, caught);
    }

    return NULL;
}

void test() {
    TEST_ASSERT_EQUAL_INT(pythia_init(NULL), 0);

    pthread_t t1, t2;

    pthread_create(&t1, NULL, pythia_succ, NULL);

    printf("Stage 1\n"); fflush(stdout);
    sleep(2);

    printf("Stage 2\n"); fflush(stdout);
    pthread_create(&t2, NULL, pythia_err, NULL);

    sleep(2);

    printf("Stage 3\n"); fflush(stdout);
    finished = 1;

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    pythia_deinit();
}

int main() {
    UNITY_BEGIN();

    conf_print();

    RUN_TEST(test);

    return UNITY_END();
}