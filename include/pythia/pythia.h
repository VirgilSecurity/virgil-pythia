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

/// Blinds message
/// \param [out] blindedPassword password obfuscated into a pseudo-random string. This step is necessary to prevent 3rd-parties from knowledge of end user's password.
/// \param [out] blindingSecret random value used to blind user's password.
/// \param [in] password password to blind
/// \param [in] password_size password size
void pythia_blind(ep_t blindedPassword, bn_t blindingSecret, const uint8_t *password, int password_size);

/// Evaluates
/// \param [out] transformedPassword
/// \param [out] transformationPrivateKey
/// \param [out] transformedTweak
/// \param [in] blindedPassword
/// \param [in] transformationKeyID
/// \param [in] transformationKeyID_size
/// \param [in] tweak
/// \param [in] tweak_size
/// \param [in] pythiaSecret
/// \param [in] pythiaSecret_size
/// \param [in] pythiaScopeSecret
/// \param [in] pythiaScopeSecret_size
void pythia_transform(gt_t transformedPassword, bn_t transformationPrivateKey, ep2_t transformedTweak,
                      ep_t blindedPassword,
                      const uint8_t *transformationKeyID, int transformationKeyID_size,
                      const uint8_t *tweak, int tweak_size,
                      const uint8_t *pythiaSecret, int pythiaSecret_size,
                      const uint8_t *pythiaScopeSecret, int pythiaScopeSecret_size);

/// Deblinds message
/// \param [out] deblindedPassword password, transformed with Pythia PRF but with blinding removed
/// \param [in] transformedPassword transformedPassword from pythia_transform
/// \param [in] blindingSecret blindingSecret from pythia_blind
void pythia_deblind(gt_t deblindedPassword, gt_t transformedPassword, bn_t blindingSecret);

/// Generates proof
/// \param [out] transformationPublicKey
/// \param [out] proofValueC
/// \param [out] proofValueU
/// \param [in] transformedPassword
/// \param [in] blindedPassword
/// \param [in] transformedTweak
/// \param [in] transformationPrivateKey
void pythia_prove(g1_t transformationPublicKey, bn_t proofValueC, bn_t proofValueU,
                  gt_t transformedPassword, g1_t blindedPassword,
                  g2_t transformedTweak, bn_t transformationPrivateKey);

/// Verifies proof
/// \param [in] transformedPassword
/// \param [in] blindedPassword
/// \param [in] tweak
/// \param [in] tweak_size
/// \param [out] transformationPublicKey
/// \param [out] proofValueC
/// \param [out] proofValueU
/// \return 0 if verification failed, not 0 - otherwise
void pythia_verify(int *verified, gt_t transformedPassword, g1_t blindedPassword, const uint8_t *tweak, int tweak_size, g1_t transformationPublicKey, bn_t proofValueC, bn_t proofValueU);

/// Generates delta to update
/// \param [out] passwordUpdateToken
/// \param [out] updatedTransformationPublicKey
/// \param [in] previousTransformationKeyID
/// \param [in] previousTransformationKeyID_size
/// \param [in] previousPythiaSecret
/// \param [in] previousPythiaSecret_size
/// \param [in] previousPythiaScopeSecret
/// \param [in] previousPythiaScopeSecret_size
/// \param [in] newTransformationKeyID
/// \param [in] newTransformationKeyID_size
/// \param [in] newPythiaSecret
/// \param [in] newPythiaSecret_size
/// \param [in] newPythiaScopeSecret
/// \param [in] newPythiaScopeSecret_size
void pythia_get_password_update_token(bn_t passwordUpdateToken, g1_t updatedTransformationPublicKey,
                      const uint8_t *previousTransformationKeyID, int previousTransformationKeyID_size,
                      const uint8_t *previousPythiaSecret, int previousPythiaSecret_size,
                      const uint8_t *previousPythiaScopeSecret, int previousPythiaScopeSecret_size,
                      const uint8_t *newTransformationKeyID, int newTransformationKeyID_size,
                      const uint8_t *newPythiaSecret, int newPythiaSecret_size,
                      const uint8_t *newPythiaScopeSecret, int newPythiaScopeSecret_size);

/// Updates
/// \param [out] updatedDeblindedPassword
/// \param [in] deblindedPassword
/// \param [in] passwordUpdateToken
void pythia_update_deblinded_with_token(/*OUT*/ gt_t updatedDeblindedPassword, /*IN*/ gt_t deblindedPassword, /*IN*/ bn_t passwordUpdateToken);

#ifdef __cplusplus
}
#endif

#endif //PYTHIA_PYTHIA_H
