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
/// \param [in] password end user's password.
/// \param [in] password_size password size.
/// \param [out] blinded_password password obfuscated into a pseudo-random string.
/// \param [out] blinding_secret random value used to blind user's password.
void pythia_blind(const uint8_t *password, size_t password_size, g1_t blinded_password, bn_t blinding_secret);

/// Transforms blinded password using the private key, generated from pythia_secret + pythia_scope_secret.
/// \param [in] blinded_password password obfuscated into a pseudo-random string.
/// \param [in] transformation_key_id ensemble key ID used to enclose operations in subsets.
/// \param [in] transformation_key_id_size transformation_key_id size
/// \param [in] tweak some random value used to transform a password
/// \param [in] tweak_size tweak size
/// \param [in] pythia_secret global common for all secret random Key.
/// \param [in] pythia_secret_size pythia_secret size
/// \param [in] pythia_scope_secret ensemble secret generated and versioned transparently.
/// \param [in] pythia_scope_secret_size pythia_scope_secret size
/// \param [out] transformed_password blinded password, protected using server secret (pythia_secret + pythia_scope_secret + tweak).
/// \param [out] transformation_private_key Pythia's private key which was generated using pythia_secret and pythia_scope_secret. This key is used to emit proof tokens (proof_value_c, proof_value_u).
/// \param [out] transformed_tweak tweak value turned into an elliptic curve point. This value is used by Prove() operation.
void pythia_transform(g1_t blinded_password, const uint8_t *transformation_key_id, size_t transformation_key_id_size,
                      const uint8_t *tweak, size_t tweak_size, const uint8_t *pythia_secret,
                      size_t pythia_secret_size, const uint8_t *pythia_scope_secret,
                      size_t pythia_scope_secret_size,
                      gt_t transformed_password, bn_t transformation_private_key, g2_t transformed_tweak);

/// Deblinds transformed_password value with previously returned blinding_secret from pythia_blind.
/// \param [in] transformed_password transformed password from pythia_transform.
/// \param [in] blinding_secret value that was generated in pythia_blind.
/// \param [out] deblinded_password deblinded transformed_password value. This value is not equal to password and is zero-knowledge protected.
void pythia_deblind(gt_t transformed_password, bn_t blinding_secret, gt_t deblinded_password);

/// Generates proof that server possesses secret values that were used to transform password.
/// \param [in] transformed_password transformed password from pythia_transform
/// \param [in] blinded_password blinded password from pythia_blind.
/// \param [in] transformed_tweak transformed tweak from pythia_transform.
/// \param [in] transformation_private_key transformation private key from pythia_transform.
/// \param [out] transformation_public_key public key corresponding to transformation_private_key value. This value is exposed to the client so he can verify, that each and every Prove operation returns exactly the same value of transformation_public_key.
/// \param [out] proof_value_c first part of proof that transformed+password was created using transformation_private_key.
/// \param [out] proof_value_u second part of proof that transformed+password was created using transformation_private_key.
void pythia_prove(gt_t transformed_password, g1_t blinded_password, g2_t transformed_tweak,
                  bn_t transformation_private_key,
                  g1_t transformation_public_key, bn_t proof_value_c, bn_t proof_value_u);

/// This operation allows client to verify that the output of pythia_transform is correct, assuming that client has previously stored tweak. 
/// \param [in] transformed_password transformed password from pythia_transform
/// \param [in] blinded_password blinded password from pythia_blind.
/// \param [in] tweak tweak from pythia_transform
/// \param [in] tweak_size tweak size
/// \param [in] transformation_public_key transformation public key from pythia_prove
/// \param [in] proof_value_c proof value C from pythia_prove
/// \param [in] proof_value_u proof value U from pythia_prove
/// \param [out] verified 0 if verification failed, not 0 - otherwise
void pythia_verify(gt_t transformed_password, g1_t blinded_password, const uint8_t *tweak, size_t tweak_size,
                   g1_t transformation_public_key, bn_t proof_value_c, bn_t proof_value_u,
                   int *verified);

/// Rotates old previous_transformation_key_id, previous_pythia_secret, previous_pythia_scope_secret and generates a password_update_token that can update deblinded_passwords. This action should increment version of the pythia_scope_secret.
/// \param [in] previous_transformation_key_id previous transformation key id
/// \param [in] previous_transformation_key_id_size previous transformation key id size
/// \param [in] previous_pythia_secret previous pythia secret
/// \param [in] previous_pythia_secret_size previous pythia secret size
/// \param [in] previous_pythia_scope_secret previous pythia scope secret
/// \param [in] previous_pythia_scope_secret_size previous pythia scope secret size
/// \param [in] new_transformation_key_id new transformation key id
/// \param [in] new_transformation_key_id_size new transformation key id size
/// \param [in] new_pythia_secret new pythia secret
/// \param [in] new_pythia_secret_size new pythia secret size
/// \param [in] new_pythia_scope_secret new pythia scope secret
/// \param [in] new_pythia_scope_secret_size new pythia scope secret size
/// \param [out] password_update_token value that allows to update all deblinded passwords (one by one) after server issued new pythia_secret or pythia_scope_secret.
/// \param [out] updated_transformation_public_key public key corresponding to the new transformation_private_key after issuing password_update_token.
void pythia_get_password_update_token(const uint8_t *previous_transformation_key_id,
                                      size_t previous_transformation_key_id_size, const uint8_t *previous_pythia_secret,
                                      size_t previous_pythia_secret_size, const uint8_t *previous_pythia_scope_secret,
                                      size_t previous_pythia_scope_secret_size,
                                      const uint8_t *new_transformation_key_id, size_t new_transformation_key_id_size,
                                      const uint8_t *new_pythia_secret, size_t new_pythia_secret_size,
                                      const uint8_t *new_pythia_scope_secret, size_t new_pythia_scope_secret_size,
                                      bn_t password_update_token, g1_t updated_transformation_public_key);

/// Updates previously stored deblinded_password with password_update_token. After this call, pythia_transform called with new arguments will return corresponding values.
/// \param [in] deblinded_password previous deblinded password from pythia_deblind.
/// \param [in] password_update_token password update token from pythia_get_password_update_token
/// \param [out] updated_deblinded_password new deblinded password.
void pythia_update_deblinded_with_token(gt_t deblinded_password, bn_t password_update_token,
                                        gt_t updated_deblinded_password);

#ifdef __cplusplus
}
#endif

#endif //PYTHIA_PYTHIA_C_H
