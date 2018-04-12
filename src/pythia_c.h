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

#ifndef PYTHIA_PYTHIA_C_H
#define PYTHIA_PYTHIA_C_H

#include <stdint.h>
#include <relic/relic.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Blinds password. Turns password into a pseudo-random string. This step is necessary to prevent 3rd-parties from knowledge of end user's password.
/// \param [in] m end user's password.
/// \param [in] m_size password size.
/// \param [out] x password obfuscated into a pseudo-random string.
/// \param [out] rInv random value used to blind user's password.
void pythia_blind(const uint8_t *m, size_t m_size, g1_t x, bn_t rInv);

/// Transforms blinded password using the private key, generated from pythia_secret +  pythia_scope_secret.
/// \param [in] x password obfuscated into a pseudo-random string.
/// \param [in] w ensemble key ID used to enclose operations in subsets.
/// \param [in] w_size transformation_key_id size
/// \param [in] t some random value used to transform a password
/// \param [in] t_size tweak size
/// \param [in] msk global common for all secret random Key.
/// \param [in] msk_size pythia_secret size
/// \param [in] s ensemble secret generated and versioned transparently.
/// \param [in] s_size pythia_scope_secret size
/// \param [out] y blinded password, protected using server secret (pythia_secret + pythia_scope_secret + tweak).
/// \param [out] kw Pythia's private key which was generated using pythia_secret and pythia_scope_secret. This key is used to emit proof tokens (proof_value_c, proof_value_u).
/// \param [out] tTilde tweak value turned into an elliptic curve point. This value is used by Prove() operation.
void pythia_eval(g1_t x, const uint8_t *w, size_t w_size, const uint8_t *t, size_t t_size,
                 const uint8_t *msk, size_t msk_size, const uint8_t *s, size_t s_size,
                 gt_t y, bn_t kw, g2_t tTilde);

/// Deblinds transformed_password value with previously returned blinding_secret from pythia_blind.
/// \param [in] y transformed password from pythia_transform.
/// \param [in] rInv value that was generated in pythia_blind.
/// \param [out] u deblinded transformed_password value. This value is not equal to password and is zero-knowledge protected.
void pythia_deblind(gt_t y, bn_t rInv, gt_t u);

/// Generates proof that server possesses secret values that were used to transform password.
/// \param [in] y transformed password from pythia_transform
/// \param [in] x blinded password from pythia_blind.
/// \param [in] tTilde transformed tweak from pythia_transform.
/// \param [in] kw transformation private key from pythia_transform.
/// \param [out] pi_p public key corresponding to transformation_private_key value. This value is exposed to the client so he can verify, that each and every Prove operation returns exactly the same value of transformation_public_key.
/// \param [out] pi_c first part of proof that transformed+password was created using transformation_private_key.
/// \param [out] pi_u second part of proof that transformed+password was created using transformation_private_key.
void pythia_prove(gt_t y, g1_t x, g2_t tTilde, bn_t kw, g1_t pi_p, bn_t pi_c, bn_t pi_u);

/// This operation allows client to verify that the output of pythia_transform is correct, assuming that client has previously stored tweak.
/// \param [in] y transformed password from pythia_transform
/// \param [in] x blinded password from pythia_blind.
/// \param [in] t tweak from pythia_transform
/// \param [in] t_size tweak size
/// \param [in] pi_p transformation public key from pythia_prove
/// \param [in] pi_c proof value C from pythia_prove
/// \param [in] pi_u proof value U from pythia_prove
/// \param [out] verified 0 if verification failed, not 0 - otherwise
void pythia_verify(gt_t y, g1_t x, const uint8_t *t, size_t t_size, g1_t pi_p, bn_t pi_c, bn_t pi_u, int *verified);

/// Rotates old previous_transformation_key_id, previous_pythia_secret, previous_pythia_scope_secret and generates a password_update_token that can update deblinded_passwords. This action should increment version of the pythia_scope_secret.
/// \param [in] w0 previous transformation key id
/// \param [in] w0_size previous transformation key id size
/// \param [in] msk0 previous pythia secret
/// \param [in] msk0_size previous pythia secret size
/// \param [in] s0 previous pythia scope secret
/// \param [in] s0_size previous pythia scope secret size
/// \param [in] w1 new transformation key id
/// \param [in] w1_size new transformation key id size
/// \param [in] msk1 new pythia secret
/// \param [in] msk1_size new pythia secret size
/// \param [in] s1 new pythia scope secret
/// \param [in] s1_size new pythia scope secret size
/// \param [out] password_update_token value that allows to update all deblinded passwords (one by one) after server issued new pythia_secret or pythia_scope_secret.
/// \param [out] updated_transformation_public_key public key corresponding to the new transformation_private_key after issuing password_update_token.
void get_delta(const uint8_t *w0, size_t w0_size, const uint8_t *msk0, size_t msk0_size,
               const uint8_t *s0, size_t s0_size,
               const uint8_t *w1, size_t w1_size, const uint8_t *msk1, size_t msk1_size,
               const uint8_t *s1, size_t s1_size,
               bn_t password_update_token, g1_t updated_transformation_public_key);

/// Updates previously stored deblinded_password with password_update_token. After this call, pythia_transform called with new arguments will return corresponding values.
/// \param [in] u0 previous deblinded password from pythia_deblind.
/// \param [in] delta password update token from pythia_get_password_update_token
/// \param [out] u1 new deblinded password.
void pythia_update_with_delta(gt_t u0, bn_t delta, gt_t u1);

#ifdef __cplusplus
}
#endif

#endif //PYTHIA_PYTHIA_C_H
