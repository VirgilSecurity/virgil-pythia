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
/// \param [out] blinded blinded message
/// \param [out] rInv rInv to deblind message
/// \param [in] msg message to blind, e.g. password
/// \param [in] msg_size message size
void pythia_blind(ep_t blinded, bn_t rInv, const uint8_t *msg, int msg_size);

/// Evaluates
/// \param [out] y
/// \param [out] kw
/// \param [out] tTilde
/// \param [in] w
/// \param [in] w_size
/// \param [in] t
/// \param [in] t_size
/// \param [in] x
/// \param [in] msk
/// \param [in] msk_size
/// \param [in] s
/// \param [in] s_size
void pythia_eval(gt_t y, bn_t kw, ep2_t tTilde,
                 const uint8_t *w, int w_size, const uint8_t *t, int t_size, ep_t x,
                 const uint8_t *msk, int msk_size, const uint8_t *s, int s_size);

/// Deblinds message
/// \param [out] a deblinded message
/// \param [in] y y from pythia_eval
/// \param [in] rInv rInv from pythia_blind
void pythia_deblind(gt_t a, gt_t y, bn_t rInv);

/// Generates proof
/// \param [out] p
/// \param [out] c
/// \param [out] u
/// \param [in] x
/// \param [in] tTilde
/// \param [in] kw
/// \param [in] y
void pythia_prove(g1_t p, bn_t c, bn_t u, g1_t x,
                  g2_t tTilde, bn_t kw, gt_t y);

/// Verifies proof
/// \param [in] x
/// \param [in] t
/// \param [in] t_size
/// \param [in] y
/// \param [in] p
/// \param [in] c
/// \param [in] u
/// \return 0 if verification failed, not 0 - otherwise
void pythia_verify(int *verified, g1_t x, const uint8_t *t, int t_size, gt_t y, g1_t p, bn_t c, bn_t u);

/// Generates delta to update
/// \param [out] delta
/// \param [out] pPrime
/// \param [in] w0
/// \param [in] w_size0
/// \param [in] msk0
/// \param [in] msk_size0
/// \param [in] z0
/// \param [in] z_size0
/// \param [in] w1
/// \param [in] w_size1
/// \param [in] msk1
/// \param [in] msk_size1
/// \param [in] z1
/// \param [in] z_size1
void pythia_get_delta(bn_t delta, g1_t pPrime,
                      const uint8_t *w0, int w_size0, const uint8_t *msk0, int msk_size0,
                      const uint8_t *z0, int z_size0,
                      const uint8_t *w1, int w_size1, const uint8_t *msk1, int msk_size1,
                      const uint8_t *z1, int z_size1);

/// Updates
/// \param [out] r
/// \param [in] z
/// \param [in] delta
void pythia_update(/*OUT*/ gt_t r, /*IN*/ gt_t z, /*IN*/ bn_t delta);

#ifdef __cplusplus
}
#endif

#endif //PYTHIA_PYTHIA_H
