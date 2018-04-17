/**
 * Copyright (C) 2015-2018 Virgil Security Inc.

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "unity.h"
#include <relic/relic.h>
#include "pythia_init.h"
#include "pythia_init_c.h"
#include "pythia_c.h"

void bench1_BlindEvalProveVerify() {
    TEST_ASSERT_EQUAL_INT(pythia_init(NULL), 0);
    pythia_err_init();
    const int iterations = 100;

    for (int i = 0; i < iterations; i++) {
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

            pythia_eval(blinded, w, 10, t, 5, msk, 13, ssk, 13, y, kw, tTilde);

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
    }

    pythia_deinit();
}

int main() {
    UNITY_BEGIN();

    conf_print();

    RUN_TEST(bench1_BlindEvalProveVerify);

    return UNITY_END();
}