//
// Created by Oleksandr Deundiak on 3/7/18.
//

#ifndef PYTHIA_PYTHIA_BUF_H
#define PYTHIA_PYTHIA_BUF_H

#include <stdint.h>
#include <stdlib.h>

struct pythia_buf {
    uint8_t *p;
    int allocated;
    int len;
};

typedef struct pythia_buf pythia_buf_t;

inline pythia_buf_t *pythia_buf_new() {
    pythia_buf_t *buf = malloc(sizeof(pythia_buf_t));
    buf->p = NULL;
    buf->allocated = 0;
    buf->len = 0;

    return buf;
}

inline void pythia_buf_free(pythia_buf_t *buf) {
    free(buf);
}

inline void pythia_buf_setup(pythia_buf_t *buf, uint8_t *p, int allocated, int len) {
    buf->p = p;
    buf->allocated = allocated;
    buf->len = len;
}

#endif //PYTHIA_PYTHIA_BUF_H
