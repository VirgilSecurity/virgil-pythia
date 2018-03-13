//
// Created by Oleksandr Deundiak on 3/6/18.
//

#ifndef PYTHIA_PYTHIA_H
#define PYTHIA_PYTHIA_H

#include <stdint.h>
#include <relic/relic.h>

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
int pythia_verify(g1_t x, const uint8_t *t, int t_size, gt_t y, g1_t p, bn_t c, bn_t u);

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

#endif //PYTHIA_PYTHIA_H
