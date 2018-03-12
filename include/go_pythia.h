//
// Created by Oleksandr Deundiak on 3/6/18.
//

#ifndef PYTHIA_GO_PYTHIA_H
#define PYTHIA_GO_PYTHIA_H

#include "pythia_buf.h"

void go_pythia_blind(/*ep_t*/ pythia_buf_t *blinded, /*bn_t*/ pythia_buf_t *rInv, pythia_buf_t msg);

void go_pythia_eval(/*gt_t*/ pythia_buf_t *y, /*bn_t*/ pythia_buf_t *kw, /*ep2_t*/ pythia_buf_t *tTilde,
                             pythia_buf_t w, pythia_buf_t t, /*ep_t*/ pythia_buf_t x, pythia_buf_t msk, pythia_buf_t s);

void go_pythia_deblind(/*gt_t*/ pythia_buf_t *a, /*gt_t*/ pythia_buf_t y, /*bn_t*/ pythia_buf_t rInv);

void go_pythia_prove(/*g1_t*/ pythia_buf_t *p, /*bn_t*/ pythia_buf_t *c, /*bn_t*/ pythia_buf_t *u, /*g1_t*/ pythia_buf_t x,
                     /*g2_t*/ pythia_buf_t tTilde, /*bn_t*/ pythia_buf_t kw, /*gt_t*/ pythia_buf_t y);

int go_pythia_verify(/*g1_t*/ pythia_buf_t x, pythia_buf_t t, /*gt_t*/ pythia_buf_t y, /*g1_t*/ pythia_buf_t p, /*bn_t*/ pythia_buf_t c, /*bn_t*/ pythia_buf_t u);

void go_pythia_get_delta(/*bn_t*/ pythia_buf_t *delta, /*gt_t*/ pythia_buf_t *pPrime,
                                  pythia_buf_t w0, pythia_buf_t msk0, pythia_buf_t z0,
                                  pythia_buf_t w1, pythia_buf_t msk1, pythia_buf_t z1);

void go_pythia_update(/*gt_t*/ pythia_buf_t *r, /*gt_t*/ pythia_buf_t z, /*bn_t*/ pythia_buf_t delta);

#endif //PYTHIA_GO_PYTHIA_H
