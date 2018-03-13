//
// Created by Oleksandr Deundiak on 3/7/18.
//

#include <pythia.h>
#include <stdio.h>
#include <relic/relic_bn.h>
#include "go_pythia.h"

void check_size(int allocated, int size) {
    // TODO: Implement
}

void bn_read_buf(bn_t b, pythia_buf_t buf) {
    bn_read_bin(b, buf.p + 1, buf.allocated - 1);
    b->sign = buf.p[0];
}

void ep_read_buf(ep_t e, pythia_buf_t buf) {
    ep_read_bin(e, buf.p, buf.allocated);
}

void gt_read_buf(gt_t g, pythia_buf_t buf) {
    gt_read_bin(g, buf.p, buf.allocated);
}

void g1_read_buf(g1_t g, pythia_buf_t buf) {
    g1_read_bin(g, buf.p, buf.allocated);
}

void g2_read_buf(g2_t g, pythia_buf_t buf) {
    g2_read_bin(g, buf.p, buf.allocated);
}

void bn_write_buf(pythia_buf_t *buf, bn_t b) {
    int size = bn_size_bin(b) + 1;
    check_size(buf->allocated, size);
    bn_write_bin(buf->p + 1, size - 1, b);
    buf->p[0] = (uint8_t )b->sign;
    buf->len = size;
}

void ep_write_buf(pythia_buf_t *buf, ep_t e) {
    int size = ep_size_bin(e, 1);
    check_size(buf->allocated, size);
    ep_write_bin(buf->p, size, e, 1);
    buf->len = size;
}

void ep2_write_buf(pythia_buf_t *buf, ep2_t e) {
    int size = ep2_size_bin(e, 1);
    check_size(buf->allocated, size);
    ep2_write_bin(buf->p, size, e, 1);
    buf->len = size;
}

void gt_write_buf(pythia_buf_t *buf, gt_t g) {
    int size = gt_size_bin(g, 1);
    check_size(buf->allocated, size);
    gt_write_bin(buf->p, size, g, 1);
    buf->len = size;
}

void g1_write_buf(pythia_buf_t *buf, g1_t g) {
    int size = g1_size_bin(g, 1);
    check_size(buf->allocated, size);
    g1_write_bin(buf->p, size, g, 1);
    buf->len = size;
}


void go_pythia_blind(/*ep_t*/ pythia_buf_t *blinded, /*bn_t*/ pythia_buf_t *rInv, pythia_buf_t msg) {
    ep_t blinded_ep;
    ep_new(blinded_ep);

    bn_t rInv_bn;
    bn_new(rInv_bn);

    pythia_blind(blinded_ep, rInv_bn, msg.p, msg.allocated);

    ep_write_buf(blinded, blinded_ep);
    bn_write_buf(rInv, rInv_bn);

    bn_free(rInv_bn);
    ep_free(blinded_ep);
}

void go_pythia_eval(/*gt_t*/ pythia_buf_t *y, /*bn_t*/ pythia_buf_t *kw, /*ep2_t*/ pythia_buf_t *tTilde,
                             pythia_buf_t w, pythia_buf_t t, /*ep_t*/ pythia_buf_t x, pythia_buf_t msk, pythia_buf_t s) {
    gt_t y_gt; gt_new(y_gt);
    bn_t kw_bn; bn_new(kw_bn);
    ep2_t tTilde_ep2; ep2_new(tTilde_ep2);

    ep_t x_ep; ep_new(x_ep);
    ep_read_buf(x_ep, x);

    pythia_eval(y_gt, kw_bn, tTilde_ep2, w.p, w.allocated, t.p, t.allocated, x_ep, msk.p, msk.allocated, s.p, s.allocated);

    gt_write_buf(y, y_gt);
    bn_write_buf(kw, kw_bn);
    ep2_write_buf(tTilde, tTilde_ep2);

    ep_free(x_ep);
    ep2_free(tTilde_ep2);
    bn_free(kw_bn);
    gt_free(y_gt);
}

void go_pythia_deblind(/*gt_t*/ pythia_buf_t *a, /*gt_t*/ pythia_buf_t y, /*bn_t*/ pythia_buf_t rInv) {
    gt_t a_gt; gt_new(a_gt);

    gt_t y_gt; gt_new(y_gt);
    gt_read_buf(y_gt, y);

    bn_t rInv_bn; bn_new(rInv_bn);
    bn_read_buf(rInv_bn, rInv);

    pythia_deblind(a_gt, y_gt, rInv_bn);

    gt_write_buf(a, a_gt);

    bn_free(rInv_bn);
    gt_free(y_gt);
    gt_free(a_gt);
}

void go_pythia_prove(/*g1_t*/ pythia_buf_t *p, /*bn_t*/ pythia_buf_t *c, /*bn_t*/ pythia_buf_t *u, /*g1_t*/ pythia_buf_t x,
                     /*g2_t*/ pythia_buf_t tTilde, /*bn_t*/ pythia_buf_t kw, /*gt_t*/ pythia_buf_t y) {
    g1_t p_g1; g1_new(p_g1);
    bn_t c_bn; bn_new(c_bn);
    bn_t u_bn; bn_new(u_bn);

    g1_t x_g1; g1_new(x_g1);
    g1_read_buf(x_g1, x);

    g2_t tTilde_g2; g2_new(tTilde_g2);
    g2_read_buf(tTilde_g2, tTilde);

    bn_t kw_bn; bn_new(kw_bn);
    bn_read_buf(kw_bn, kw);

    gt_t y_gt; gt_new(y_gt);
    gt_read_buf(y_gt, y);

    pythia_prove(p_g1, c_bn, u_bn, x_g1, tTilde_g2, kw_bn, y_gt);

    g1_write_buf(p, p_g1);
    bn_write_buf(c, c_bn);
    bn_write_buf(u, u_bn);

    gt_free(y_gt);
    bn_free(kw_bn);
    g2_free(tTilde_g2);
    g1_free(x_g1);
    bn_free(u_bn);
    bn_free(c_bn);
    g1_free(p_g1);
}

int go_pythia_verify(/*g1_t*/ pythia_buf_t x, pythia_buf_t t, /*gt_t*/ pythia_buf_t y, /*g1_t*/ pythia_buf_t p, /*bn_t*/ pythia_buf_t c, /*bn_t*/ pythia_buf_t u) {
    g1_t x_g1; g1_new(x_g1);
    g1_read_buf(x_g1, x);

    gt_t y_gt; gt_new(y_gt);
    gt_read_buf(y_gt, y);

    g1_t p_g1; g1_new(p_g1);
    g1_read_buf(p_g1, p);

    bn_t c_bn; bn_new(c_bn);
    bn_read_buf(c_bn, c);

    bn_t u_bn; bn_new(u_bn);
    bn_read_buf(u_bn, u);

    int res = pythia_verify(x_g1, t.p, t.allocated, y_gt, p_g1, c_bn, u_bn);

    gt_free(y_gt);
    g1_free(x_g1);
    bn_free(u_bn);
    bn_free(c_bn);
    g1_free(p_g1);

    return res;
}

void go_pythia_get_delta(/*bn_t*/ pythia_buf_t *delta, /*gt_t*/ pythia_buf_t *pPrime,
                                  pythia_buf_t w0, pythia_buf_t msk0, pythia_buf_t z0,
                                  pythia_buf_t w1, pythia_buf_t msk1, pythia_buf_t z1) {
    bn_t delta_bn; bn_new(delta_bn);
    g1_t pPrime_g1; g1_new(pPrime_g1);

    pythia_get_delta(delta_bn, pPrime_g1,
                     w0.p, w0.allocated, msk0.p, msk0.allocated, z0.p, z0.allocated,
                     w1.p, w1.allocated, msk1.p, msk1.allocated, z1.p, z1.allocated);

    bn_write_buf(delta, delta_bn);
    g1_write_buf(pPrime, pPrime_g1);

    g1_free(pPrime_g1);
    bn_free(delta_bn);
}

void go_pythia_update(/*gt_t*/ pythia_buf_t *r, /*gt_t*/ pythia_buf_t z, /*bn_t*/ pythia_buf_t delta) {
    gt_t r_gt; gt_new(r_gt);

    gt_t z_gt; gt_new(z_gt);
    gt_read_buf(z_gt, z);

    bn_t delta_bn; bn_new(delta_bn);
    bn_read_buf(delta_bn, delta);

    pythia_update(r_gt, z_gt, delta_bn);

    gt_write_buf(r, r_gt);

    bn_free(delta_bn);
    gt_free(z_gt);
    gt_free(r_gt);
}