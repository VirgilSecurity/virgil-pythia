# Investigation

## Relic Dependencies

### Libraries

  - Multithread:
      - openmp (optional)
      - pthread (optional)

### Platfrom dependent features

  - when *TIMER* eqals *CYCLE* (optional)
      - intitialization occurs within function `arch_init()`

  - random number generator
      - `CryptGenRandom` on Windows
      - `/dev/random` on Unix/Linux
      - `/dev/urandom`  on Unix/Linux
      - `libc rand()/random()` is crossplatform (insecure!)
      - `zero seed` is a crossplatform (insecure!)
      - `custom` can be defined on a client side for any platform

## Deterministic RNG

MbedTLS provides two RNG modules:

- `CTR_DRBG` - based on block-cipher in counter-mode - **deterministic**

  - can be used in a deterministic mode by implementing custom source entropy

    ```c
    typedef struct {
        unsigned char seed[MBEDTLS_CTR_DRBG_ENTROPY_LEN];
        size_t left;
    } self_entropy_ctx_t;

    int seed_entropy (void *ctx, unsigned char *seed, size_t seed_len) {
        assert (ctx);
        assert (seed);

        self_entropy_ctx_t *entropy_ctx = (self_entropy_ctx_t *)ctx;

        assert (seed_len <= entropy_ctx->left);
        memcpy (seed, entropy_ctx->seed, seed_len);
        entropy_ctx->left -= seed_len;

        return 0;
    }

    int main (void) {
        self_entropy_ctx_t entropy_ctx;
        memset (entropy_ctx.seed, 0xAB, MBEDTLS_CTR_DRBG_ENTROPY_LEN);
        entropy_ctx.left = MBEDTLS_CTR_DRBG_ENTROPY_LEN;

        mbedtls_ctr_drbg_context drbg_ctx;
        mbedtls_ctr_drbg_init (&drbg_ctx);

        unsigned char result_buf[1024];

        mbedtls_ctr_drbg_seed (&drbg_ctx, seed_entropy, &entropy_ctx, NULL, 0));
        mbedtls_ctr_drbg_random (&drbg_ctx, result_buf, sizeof(result_buf)));

        return 0;
    }
    ```

- `HMAC_DRBG` - based on Hash-based message authentication code - **deterministic**

  - can be used by initializing seed with function `mbedtls_hmac_drbg_seed_buf()`
