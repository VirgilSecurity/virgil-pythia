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

#ifndef PYTHIA_PYTHIA_WRAPPER_H
#define PYTHIA_PYTHIA_WRAPPER_H

#include "pythia_buf.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Blinds password
/// \param [out] ep_t blinded_password password obfuscated into a pseudo-random string. This step is necessary to prevent 3rd-parties from knowledge of end user's password.
/// \param [out] bn_t blinding_secret random value used to blind user's password.
/// \param [in] password password to blind
/// \return 0 if succeeded, -1 otherwise
int pythia_w_blind(pythia_buf_t *blinded_password, pythia_buf_t *blinding_secret, const pythia_buf_t *password);

/// Transforms
/// \param [out] gt_t transformed_password
/// \param [out] bn_t ransformation_private_key
/// \param [out] ep2_t transformed_tweak
/// \param [in] ep_t blinded_password
/// \param [in] transformation_key_id
/// \param [in] tweak
/// \param [in] pythia_secret
/// \param [in] pythia_scope_secret
/// \return 0 if succeeded, -1 otherwise
int pythia_w_transform(pythia_buf_t *transformed_password, pythia_buf_t *transformation_private_key,
                       pythia_buf_t *transformed_tweak,
                       const pythia_buf_t *blinded_password, const pythia_buf_t *transformation_key_id,
                       const pythia_buf_t *tweak, const pythia_buf_t *pythia_secret,
                       const pythia_buf_t *pythia_scope_secret);
/// Deblinds message
/// \param [out] gt_t deblinded_password password, transformed with Pythia PRF but with blinding removed
/// \param [in] gt_t transformed_password transformedPassword from pythia_transform
/// \param [in] bn_t blinding_secret blindingSecret from pythia_blind
/// \return 0 if succeeded, -1 otherwise
int pythia_w_deblind(pythia_buf_t *deblinded_password,
                     const pythia_buf_t *transformed_password, const pythia_buf_t *blinding_secret);

/// Generates proof
/// \param [out] g1_t transformation_public_key
/// \param [out] bn_t proof_value_c
/// \param [out] bn_t proof_value_u
/// \param [in] gt_t transformed_password
/// \param [in] g1_t blinded_password
/// \param [in] g2_t transformed_tweak
/// \param [in] bn_t transformation_private_key
/// \return 0 if succeeded, -1 otherwise
int pythia_w_prove(pythia_buf_t *transformation_public_key, pythia_buf_t *proof_value_c, pythia_buf_t *proof_value_u,
                   const pythia_buf_t *transformed_password, const pythia_buf_t *blinded_password,
                   const pythia_buf_t *transformed_tweak, const pythia_buf_t *transformation_private_key);

/// Verifies proof
/// \param [out] verified 0 if verification failed, not 0 - otherwise
/// \param [in] gt_t transformed_password
/// \param [in] g1_t blinded_password
/// \param [in] tweak
/// \param [in] g1_t transformation_public_key
/// \param [in] bn_t proof_value_c
/// \param [in] bn_t proof_value_u
/// \return 0 if succeeded, -1 otherwise
int pythia_w_verify(int *verified, const pythia_buf_t *transformed_password, const pythia_buf_t *blinded_password,
                    const pythia_buf_t *tweak, const pythia_buf_t *transformation_public_key,
                    const pythia_buf_t *proof_value_c, const pythia_buf_t *proof_value_u);

/// Generates delta to update
/// \param [out] bn_t password_update_token
/// \param [out] gt_t updated_transformation_public_key
/// \param [in] previous_transformation_key_id
/// \param [in] previous_pythia_secret
/// \param [in] previous_pythia_scope_secret
/// \param [in] new_transformation_key_id
/// \param [in] new_pythia_secret
/// \param [in] new_pythia_scope_secret
/// \return 0 if succeeded, -1 otherwise
int pythia_w_get_password_update_token(pythia_buf_t *password_update_token,
                                       pythia_buf_t *updated_transformation_public_key,
                                       const pythia_buf_t *previous_transformation_key_id, const pythia_buf_t *previous_pythia_secret, const pythia_buf_t *previous_pythia_scope_secret,
                                       const pythia_buf_t *new_transformation_key_id, const pythia_buf_t *new_pythia_secret, const pythia_buf_t *new_pythia_scope_secret);

/// Updates
/// \param [out] gt_t updated_deblinded_password
/// \param [in] gt_t deblinded_password
/// \param [in] bn_t password_update_token
/// \return 0 if succeeded, -1 otherwise
int pythia_w_update(pythia_buf_t *updated_deblinded_password,
                    const pythia_buf_t *deblinded_password, const pythia_buf_t *password_update_token);

#ifdef __cplusplus
}
#endif

#endif //PYTHIA_PYTHIA_WRAPPER_H
