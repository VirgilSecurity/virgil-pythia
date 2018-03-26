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

#ifndef PYTHIA_PYTHIA_H
#define PYTHIA_PYTHIA_H

#include <stdint.h>
#include <relic/relic.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Blinds password
/// \param [out] blinded_password password obfuscated into a pseudo-random string. This step is necessary to prevent 3rd-parties from knowledge of end user's password.
/// \param [out] blinding_secret random value used to blind user's password.
/// \param [in] password password to blind
/// \param [in] password_size password size
void pythia_blind(g1_t blinded_password, bn_t blinding_secret, const uint8_t *password, int password_size);

/// Transforms
/// \param [out] transformed_password
/// \param [out] transformation_private_key
/// \param [out] transformed_tweak
/// \param [in] blinded_password
/// \param [in] transformation_key_id
/// \param [in] transformation_key_id_size
/// \param [in] tweak
/// \param [in] tweak_size
/// \param [in] pythia_secret
/// \param [in] pythia_secret_size
/// \param [in] pythia_scope_secret
/// \param [in] pythia_scope_secret_size
void pythia_transform(gt_t transformed_password, bn_t transformation_private_key,
                      g2_t transformed_tweak, g1_t blinded_password,
                      const uint8_t *transformation_key_id, int transformation_key_id_size,
                      const uint8_t *tweak, int tweak_size,
                      const uint8_t *pythia_secret, int pythia_secret_size,
                      const uint8_t *pythia_scope_secret, int pythia_scope_secret_size);

/// Deblinds message
/// \param [out] deblinded_password password, transformed with Pythia PRF but with blinding removed
/// \param [in] transformed_password transformedPassword from pythia_transform
/// \param [in] blinding_secret blindingSecret from pythia_blind
void pythia_deblind(gt_t deblinded_password, gt_t transformed_password, bn_t blinding_secret);

/// Generates proof
/// \param [out] transformation_public_key
/// \param [out] proof_value_c
/// \param [out] proof_value_u
/// \param [in] transformed_password
/// \param [in] blinded_password
/// \param [in] transformed_tweak
/// \param [in] transformation_private_key
void pythia_prove(g1_t transformation_public_key, bn_t proof_value_c, bn_t proof_value_u,
                  gt_t transformed_password, g1_t blinded_password,
                  g2_t transformed_tweak, bn_t transformation_private_key);

/// Verifies proof
/// \param [out] verified 0 if verification failed, not 0 - otherwise
/// \param [in] transformed_password
/// \param [in] blinded_password
/// \param [in] tweak
/// \param [in] tweak_size
/// \param [in] transformation_public_key
/// \param [in] proof_value_c
/// \param [in] proof_value_u
void pythia_verify(int *verified, gt_t transformed_password, g1_t blinded_password,
                   const uint8_t *tweak, int tweak_size,
                   g1_t transformation_public_key,
                   bn_t proof_value_c, bn_t proof_value_u);

/// Generates delta to update
/// \param [out] password_update_token
/// \param [out] updated_transformation_public_key
/// \param [in] previous_transformation_key_id
/// \param [in] previous_transformation_key_id_size
/// \param [in] previous_pythia_secret
/// \param [in] previous_pythia_secret_size
/// \param [in] previous_pythia_scope_secret
/// \param [in] previous_pythia_scope_secret_size
/// \param [in] new_transformation_key_id
/// \param [in] new_transformation_key_id_size
/// \param [in] new_pythia_secret
/// \param [in] new_pythia_secret_size
/// \param [in] new_pythia_scope_secret
/// \param [in] new_pythia_scope_secret_size
void pythia_get_password_update_token(bn_t password_update_token, g1_t updated_transformation_public_key,
                                      const uint8_t *previous_transformation_key_id, int previous_transformation_key_id_size,
                                      const uint8_t *previous_pythia_secret, int previous_pythia_secret_size,
                                      const uint8_t *previous_pythia_scope_secret, int previous_pythia_scope_secret_size,
                                      const uint8_t *new_transformation_key_id, int new_transformation_key_id_size,
                                      const uint8_t *new_pythia_secret, int new_pythia_secret_size,
                                      const uint8_t *new_pythia_scope_secret, int new_pythia_scope_secret_size);

/// Updates
/// \param [out] updated_deblinded_password
/// \param [in] deblinded_password
/// \param [in] password_update_token
void pythia_update_deblinded_with_token(gt_t updated_deblinded_password, gt_t deblinded_password,
                                        bn_t password_update_token);

#ifdef __cplusplus
}
#endif

#endif //PYTHIA_PYTHIA_H
