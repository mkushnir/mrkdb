#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/tree.h>

#include "diag.h"
#include "mrkcommon/dumpm.h"
#include "mrkcommon/util.h"
#include "kvp_private.h"
#include "mrkdb/lstore.h"

RB_PROTOTYPE_STATIC(_kvpt, _kvpe, link, kvp_cmp);

static int
kvp_cmp(struct _kvpe *a, struct _kvpe *b)
{
    int res;
    /*
     * Compare keys. The key goes first in a pair, then the value goes.
     */
    res = memcmp(a->key.data, b->key.data, MIN(a->key.sz, b->key.sz));
    if (res == 0) {
        return a->key.sz - b->key.sz;
    }
    return res;
}

RB_GENERATE_STATIC(_kvpt, _kvpe, link, kvp_cmp);


MPSAFE const kvp_item_t *
kvp_get(kvp_ctx_t *ctx, const kvp_item_t *key)
{
    kvpe_t inentry, *outentry;

    inentry.key = *key;

    if ((outentry = RB_FIND(_kvpt, &ctx->index, &inentry)) != NULL) {
        kvp_record_t *val = KVP_VALUE(outentry->rec);
        lstore_take_up_sz(val->data, val->header.sz);
        return &outentry->value;
    }

    return NULL;
}


MPSAFE const kvp_item_t *
kvp_get_from_args(kvp_ctx_t *ctx, size_t sz, const void *data)
{
    kvpe_t inentry, *outentry;

    inentry.key.sz = sz;
    inentry.key.data = data;

    if ((outentry = RB_FIND(_kvpt, &ctx->index, &inentry)) != NULL) {
        kvp_record_t *val = KVP_VALUE(outentry->rec);
        lstore_take_up_sz(val->data, val->header.sz);
        return &outentry->value;
    }

    return NULL;
}


MPSAFE int
kvp_put(kvp_ctx_t *ctx, const kvp_item_t *key, const kvp_item_t *value)
{
    array_iter_t it;
    kvp_store_t *store;
    kvp_record_t *rec = NULL;
    kvpe_t inentry, *outentry;

    inentry.key = *key;

    if ((outentry = RB_FIND(_kvpt, &ctx->index, &inentry)) != NULL) {
        rec = lstore_realloc(outentry->rec,
                             KVP_ITEMSZ(key) + KVP_ITEMSZ(value));
        if (rec == NULL) {
            lstore_free(outentry->rec);
            outentry->rec = NULL;
        } else {
            /*
             * Check for the case if it's already in the store.
             */
            if ((rec->data == key->data) &&
                (KVP_VALUE(rec)->data == value->data)) {
                return 0;
            }
        }
    } else if ((outentry = malloc(sizeof(kvpe_t))) == NULL) {
        FAIL("malloc");
    }

    if (rec == NULL) {
        for (store = array_first(&ctx->stores, &it);
             store != NULL;
             store = array_next(&ctx->stores, &it)) {
            if ((rec = lstore_alloc(store->lstore_ctx,
                    KVP_ITEMSZ(key) + KVP_ITEMSZ(value))) != NULL) {
                break;

            }
        }
    }

    if (rec == NULL) {
        TRRET(KVP_PUT + 1);
    }

    outentry->rec = rec;
    rec->header.sz = key->sz;
    memcpy(rec->data, key->data, key->sz);
    outentry->key.sz = rec->header.sz;
    outentry->key.data = rec->data;
    rec = KVP_VALUE(rec);
    rec->header.sz = value->sz;
    memcpy(rec->data, value->data, value->sz);
    lstore_put_down_sz(rec->data, value->sz);
    outentry->value.sz = rec->header.sz;
    outentry->value.data = rec->data;

    RB_INSERT(_kvpt, &ctx->index, outentry);
    return 0;
}


MPSAFE int
kvp_put_from_args(kvp_ctx_t *ctx, size_t keysz, const void *keydata,
                  size_t valuesz, const void *valuedata)
{
    array_iter_t it;
    kvp_store_t *store;
    kvp_record_t *rec = NULL;
    kvpe_t inentry, *outentry;

    inentry.key.sz = keysz;
    inentry.key.data = keydata;

    if ((outentry = RB_FIND(_kvpt, &ctx->index, &inentry)) != NULL) {
        rec = lstore_realloc(outentry->rec,
                             KVP_ITEMSZ_ARG(keysz) + KVP_ITEMSZ_ARG(valuesz));
        if (rec == NULL) {
            lstore_free(outentry->rec);
            outentry->rec = NULL;
        }
    } else if ((outentry = malloc(sizeof(kvpe_t))) == NULL) {
        FAIL("malloc");
    }

    if (rec == NULL) {
        for (store = array_first(&ctx->stores, &it);
             store != NULL;
             store = array_next(&ctx->stores, &it)) {
            if ((rec = lstore_alloc(store->lstore_ctx,
                                    KVP_ITEMSZ_ARG(keysz) +
                                    KVP_ITEMSZ_ARG(valuesz))) != NULL) {
                break;

            }
        }
    }

    if (rec == NULL) {
        TRRET(KVP_PUT_FROM_ARGS + 1);
    }

    outentry->rec = rec;
    rec->header.sz = keysz;
    memcpy(rec->data, keydata, keysz);
    outentry->key.sz = rec->header.sz;
    outentry->key.data = rec->data;
    rec = KVP_VALUE(rec);
    rec->header.sz = valuesz;
    memcpy(rec->data, valuedata, valuesz);
    lstore_put_down_sz(rec->data, valuesz);
    outentry->value.sz = rec->header.sz;
    outentry->value.data = rec->data;

    RB_INSERT(_kvpt, &ctx->index, outentry);
    return 0;
}

static int
readfd(void *dst, int fd, size_t sz)
{
    //off_t offset = 0;
    //int rdblock = 4096*512;

    //while (offset < sz) {
    //    if ((offset + rdblock) > sz) {
    //        rdblock -= ((offset + rdblock) - sz);
    //    }
    //    if (read(fd, dst + offset, rdblock) == -1) {
    //        TRRET(READFD + 1);
    //    }
    //    offset += rdblock;
    //}
    //return 0;
    return ! (read(fd, dst, sz) >= 0);
}

MPSAFE int
kvp_put_from_args_fd(kvp_ctx_t *ctx, size_t keysz, const void *keydata,
                  size_t valuesz, int valuefd)
{
    array_iter_t it;
    kvp_store_t *store;
    kvp_record_t *rec = NULL;
    kvpe_t inentry, *outentry;

    inentry.key.sz = keysz;
    inentry.key.data = keydata;

    if ((outentry = RB_FIND(_kvpt, &ctx->index, &inentry)) != NULL) {
        rec = lstore_realloc(outentry->rec,
                             KVP_ITEMSZ_ARG(keysz) + KVP_ITEMSZ_ARG(valuesz));
        if (rec == NULL) {
            lstore_free(outentry->rec);
            outentry->rec = NULL;
        }
    } else if ((outentry = malloc(sizeof(kvpe_t))) == NULL) {
        FAIL("malloc");
    }

    if (rec == NULL) {
        for (store = array_first(&ctx->stores, &it);
             store != NULL;
             store = array_next(&ctx->stores, &it)) {
            if ((rec = lstore_alloc(store->lstore_ctx,
                                    KVP_ITEMSZ_ARG(keysz) +
                                    KVP_ITEMSZ_ARG(valuesz))) != NULL) {
                break;

            }
        }
    }

    if (rec == NULL) {
        TRRET(KVP_PUT_FROM_ARGS_FD + 1);
    }

    outentry->rec = rec;
    rec->header.sz = keysz;
    memcpy(rec->data, keydata, keysz);
    outentry->key.sz = rec->header.sz;
    outentry->key.data = rec->data;
    rec = KVP_VALUE(rec);
    rec->header.sz = valuesz;
    if (readfd(rec->data, valuefd, valuesz) != 0) {
        TRACE("data=%p fd=%d sz=%016lx", rec->data, valuefd, valuesz);
        perror("read");
        lstore_dump(store->lstore_ctx);
        lstore_free(rec);
        TRRET(KVP_PUT_FROM_ARGS_FD + 1);
    }
    lstore_put_down_sz(rec->data, valuesz);
    outentry->value.sz = rec->header.sz;
    outentry->value.data = rec->data;

    RB_INSERT(_kvpt, &ctx->index, outentry);
    return 0;
}


MPSAFE int
kvp_delete(kvp_ctx_t *ctx, const kvp_item_t *key)
{
    kvpe_t inentry, *outentry;

    inentry.key = *key;

    if ((outentry = RB_FIND(_kvpt, &ctx->index, &inentry)) != NULL) {
        RB_REMOVE(_kvpt, &ctx->index, outentry);
        lstore_free(outentry->rec);
        free(outentry);
        return 0;
    }

    TRRET(KVP_DELETE + 1);
}


MPSAFE int
kvp_delete_from_args(kvp_ctx_t *ctx, size_t sz, const void *data)
{
    kvpe_t inentry, *outentry;

    inentry.key.sz = sz;
    inentry.key.data = data;

    if ((outentry = RB_FIND(_kvpt, &ctx->index, &inentry)) != NULL) {
        RB_REMOVE(_kvpt, &ctx->index, outentry);
        lstore_free(outentry->rec);
        free(outentry);
        return 0;
    }

    TRRET(KVP_DELETE_FROM_ARGS + 1);
}


MPUNSAFE static void
kvp_cb(UNUSED lstore_ctx_t *ctx, void *data, void *uctx)
{
    kvp_store_t *kvp_store = (kvp_store_t *)uctx;
    kvp_record_t *rec = (kvp_record_t *)data;

    if (rec->header.sz == KVP_META) {
        /*
         * not a kvp:
         *  - uint32_t version and flags;
         *
         */
        kvp_meta_t *meta = (kvp_meta_t *)rec;
        kvp_store->version = meta->version;
    } else {
        /*
         * Add to kvp_store->kvp_ctx->index
         */
        kvpe_t *entry;

        if ((entry = malloc(sizeof(kvpe_t))) == NULL) {
            FAIL("malloc");
        }
        entry->rec = rec;
        entry->key.sz = rec->header.sz;
        entry->key.data = rec->data;
        /* advance to value */
        rec = KVP_VALUE(rec);
        entry->value.sz = rec->header.sz;
        entry->value.data = rec->data;
        RB_INSERT(_kvpt, &kvp_store->kvp_ctx->index, entry);
    }
}

MPUNSAFE static int
kvp_store_fini(kvp_store_t *store)
{
    lstore_fini(store->lstore_ctx);
    store->lstore_ctx = NULL;
    store->kvp_ctx = NULL;
    return 0;
}

MPUNSAFE kvp_ctx_t *
kvp_new(void)
{
    kvp_ctx_t *ctx;
    if ((ctx = malloc(sizeof(kvp_ctx_t))) == NULL) {
        FAIL("malloc");
    }

    if (array_init(&ctx->stores, sizeof(kvp_store_t), 0,
                   NULL,
                   (array_finalizer_t)kvp_store_fini) != 0) {
        FAIL("array_init");
    }
    RB_INIT(&ctx->index);
    return ctx;
}

/**
 * XXX check for dups
 */
MPUNSAFE int
kvp_load(kvp_ctx_t *ctx, const char *path)
{
    kvp_store_t *store;

    if ((store = array_incr(&ctx->stores)) == NULL) {
        FAIL("array_incr");
    }
    store->kvp_ctx = ctx;

    if ((store->lstore_ctx = lstore_init(path, kvp_cb, store, 0)) == NULL) {
        TRRET(KVP_LOAD + 1);
    }

    return 0;
}

/**
 * XXX check for dups
 */
MPUNSAFE int
kvp_extend(kvp_ctx_t *ctx, const char *path)
{
    kvp_store_t *store;
    kvp_meta_t *meta;

    if ((store = array_incr(&ctx->stores)) == NULL) {
        FAIL("array_incr");
    }

    store->version = KVP_VERSION;
    if ((store->lstore_ctx = lstore_init(path, NULL, NULL,
                                         LSTORE_INIT_FORCE)) == NULL) {
        TRRET(KVP_EXTEND + 1);
    }

    if ((meta = lstore_alloc_at(store->lstore_ctx,
                                0ul, sizeof(kvp_meta_t))) == NULL) {
        TRRET(KVP_EXTEND + 2);
    }
    meta->header.sz = KVP_META;
    meta->version = KVP_VERSION;

    return 0;
}

MPUNSAFE void
kvp_fini(kvp_ctx_t *ctx)
{
    kvpe_t *n = NULL, *next = NULL;

    for (n = RB_MIN(_kvpt, &ctx->index); n != NULL; n = next) {
        next = RB_NEXT(_kvpt, &ctx->index, n);
        n = RB_REMOVE(_kvpt, &ctx->index, n);
        free(n);
    }

    if (array_fini(&ctx->stores) != 0) {
        FAIL("array_fini");
    }
    free(ctx);
}

MPUNSAFE static int
kvp_store_dump(kvp_store_t *store, size_t *nblocks_used)
{
    lstore_stats_t stats;

    lstore_get_stats(store->lstore_ctx, &stats);
    *nblocks_used += stats.nblocks_used;
    lstore_dump(store->lstore_ctx);
    return 0;
}

MPUNSAFE void
kvp_stores_dump(kvp_ctx_t *ctx)
{
    size_t nblocks_used = 0;
    array_traverse(&ctx->stores,
                   (array_traverser_t)kvp_store_dump,
                   &nblocks_used);
    TRACE("Total blocks used: %ld", nblocks_used);
}

MPUNSAFE void
kvp_get_stats(kvp_ctx_t *ctx, kvp_stats_t *stats)
{
    lstore_stats_t lst;
    kvp_store_t *store;
    array_iter_t it;

    stats->sz = 0;
    stats->nbytes_used = 0;
    stats->nblocks_used = 0;

    for (store = array_first(&ctx->stores, &it);
         store != NULL;
         store = array_next(&ctx->stores, &it)) {
        lstore_get_stats(store->lstore_ctx, &lst);
        stats->sz += lst.store_sz;
        stats->nbytes_used += lst.nbytes_used;
        stats->nblocks_used += lst.nblocks_used;
    }
}

// vim:list
