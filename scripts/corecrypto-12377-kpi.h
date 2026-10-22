/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Adapt the source provider's digest/HMAC entry points to XNU 12377's
 * length-checked KPI suffix. Included only by the generated provider TU.
 */
static const struct ccdigest_info *
cc12377_di(crypto_digest_alg_t alg)
{
    switch (alg) {
    case CRYPTO_DIGEST_ALG_MD5: return ccmd5_di();
    case CRYPTO_DIGEST_ALG_SHA1: return ccsha1_di();
    case CRYPTO_DIGEST_ALG_SHA256: return ccsha256_di();
    case CRYPTO_DIGEST_ALG_SHA384: return ccsha384_di();
    case CRYPTO_DIGEST_ALG_SHA512: return ccsha512_di();
    default: panic("source crypto: unsupported digest %u", (unsigned)alg);
    }
}

static size_t cc12377_digest_size(crypto_digest_alg_t alg)
{
    const struct ccdigest_info *di = cc12377_di(alg);
    return ccdigest_di_size(di);
}

static size_t cc12377_hmac_size(crypto_digest_alg_t alg)
{
    const struct ccdigest_info *di = cc12377_di(alg);
    return cchmac_di_size(di);
}

static void cc12377_context(void *ctx, size_t size, size_t required)
{
    if (!ctx || ((uintptr_t)ctx & 7) || size < required) {
        panic("source crypto: invalid context buffer");
    }
}

static void cc12377_digest_init(crypto_digest_alg_t alg, void *ctx, size_t size)
{
    cc12377_context(ctx, size, cc12377_digest_size(alg));
    ccdigest_init(cc12377_di(alg), ctx);
}

static void cc12377_digest_update(crypto_digest_alg_t alg, void *ctx, size_t size,
                                const void *data, size_t len)
{
    cc12377_context(ctx, size, cc12377_digest_size(alg));
    ccdigest_update(cc12377_di(alg), ctx, len, data);
}

static void cc12377_digest_final(crypto_digest_alg_t alg, void *ctx, size_t size,
                               void *out, size_t out_size)
{
    const struct ccdigest_info *di = cc12377_di(alg);
    cc12377_context(ctx, size, ccdigest_di_size(di));
    if (!out || out_size != di->output_size) {
        panic("source crypto: invalid digest output size");
    }
    ccdigest_final(di, ctx, out);
}

static void cc12377_digest(crypto_digest_alg_t alg, const void *data, size_t len,
                         void *out, size_t out_size)
{
    const struct ccdigest_info *di = cc12377_di(alg);
    if (!out || out_size != di->output_size) {
        panic("source crypto: invalid digest output size");
    }
    ccdigest(di, len, data, out);
}

static void cc12377_hmac_init(crypto_digest_alg_t alg, void *ctx, size_t size,
                            const void *key, size_t key_size)
{
    cc12377_context(ctx, size, cc12377_hmac_size(alg));
    cchmac_init(cc12377_di(alg), ctx, key_size, key);
}

static void cc12377_hmac_update(crypto_digest_alg_t alg, void *ctx, size_t size,
                              const void *data, size_t len)
{
    cc12377_context(ctx, size, cc12377_hmac_size(alg));
    cchmac_update(cc12377_di(alg), ctx, len, data);
}

static void cc12377_hmac_final(crypto_digest_alg_t alg, void *ctx, size_t size,
                             void *tag, size_t tag_size)
{
    const struct ccdigest_info *di = cc12377_di(alg);
    unsigned char full[64];
    cc12377_context(ctx, size, cchmac_di_size(di));
    if (!tag || tag_size == 0 || tag_size > di->output_size || di->output_size > sizeof(full)) {
        panic("source crypto: invalid HMAC output size");
    }
    cchmac_final(di, ctx, full);
    memcpy(tag, full, tag_size);
    cc_clear(sizeof(full), full);
}

static bool cc12377_hmac_final_verify(crypto_digest_alg_t alg, void *ctx, size_t size,
                                    const void *tag, size_t tag_size)
{
    unsigned char computed[64];
    cc12377_hmac_final(alg, ctx, size, computed, tag_size);
    bool equal = cc_cmp_safe(tag_size, computed, tag) == 0;
    cc_clear(sizeof(computed), computed);
    return equal;
}

static void cc12377_hmac(crypto_digest_alg_t alg, const void *key, size_t key_size,
                        const void *data, size_t len, void *tag, size_t tag_size)
{
    const struct ccdigest_info *di = cc12377_di(alg);
    cchmac_di_decl(di, ctx);
    cc12377_hmac_init(alg, ctx, cchmac_di_size(di), key, key_size);
    cc12377_hmac_update(alg, ctx, cchmac_di_size(di), data, len);
    cc12377_hmac_final(alg, ctx, cchmac_di_size(di), tag, tag_size);
    cchmac_di_clear(di, ctx);
}

static bool cc12377_hmac_verify(crypto_digest_alg_t alg, const void *key, size_t key_size,
                               const void *data, size_t len, const void *tag, size_t tag_size)
{
    unsigned char computed[64];
    cc12377_hmac(alg, key, key_size, data, len, computed, tag_size);
    bool equal = cc_cmp_safe(tag_size, computed, tag) == 0;
    cc_clear(sizeof(computed), computed);
    return equal;
}

static void cc12377_ccdigest_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                                  void *digest)
{
    ccdigest_final(di, ctx, digest);
}

static void cc12377_complete_kpis(struct crypto_functions *funcs)
{
    funcs->ccdigest_final_fn = cc12377_ccdigest_final;
    funcs->digest_ctx_size_fn = cc12377_digest_size;
    funcs->digest_init_fn = cc12377_digest_init;
    funcs->digest_update_fn = cc12377_digest_update;
    funcs->digest_final_fn = cc12377_digest_final;
    funcs->digest_fn = cc12377_digest;
    funcs->hmac_ctx_size_fn = cc12377_hmac_size;
    funcs->hmac_init_fn = cc12377_hmac_init;
    funcs->hmac_update_fn = cc12377_hmac_update;
    funcs->hmac_final_generate_fn = cc12377_hmac_final;
    funcs->hmac_final_verify_fn = cc12377_hmac_final_verify;
    funcs->hmac_generate_fn = cc12377_hmac;
    funcs->hmac_verify_fn = cc12377_hmac_verify;
}
