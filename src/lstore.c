#include <sys/types.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "diag.h"
#include "mrkcommon/dumpm.h"
#include "mrkcommon/util.h"
#include "lstore_private.h"
#include "mrkcommon/btrie.h"


static int block_check(lstore_ctx_t *, lstore_header_t *);

static void
block_dump(lstore_ctx_t *ctx, lstore_header_t *block)
{
    TRACE("block=%p(%016lx) offt=%016lx sz=%08lx prev=%016lx "
          "flags=%016lx data=%p",
          block, ADDR2OFFT(ctx, block), block->offt, block->sz, block->prev,
          block->flags, block->data);
}

void
lstore_dump(lstore_ctx_t *ctx)
{
    lstore_header_t *block;

    TRACE("path=%s store_sz=%016lx(%ld)",
          ctx->path, ctx->store_sz, ctx->store_sz);

    for (block = (lstore_header_t *)ctx->store;
         ADDR2OFFT(ctx, block) < ctx->store_sz;
         block = BLOCKNEXT(block)) {

        if (!block_check(ctx, block)) {
            FAIL("block_check");
        }
        block_dump(ctx, block);
    }
}


static int
block_init(lstore_ctx_t *ctx, lstore_header_t *block, size_t sz, uint64_t prev, uint64_t flags)
{
    lstore_header_t *next;
    uint64_t nextofft;

    block->offt = (((uintptr_t)block) - ((uintptr_t)ctx->store));
    block->magic = block->offt ^ ctx->magic;
    block->sz = sz;
    block->prev = prev;
    block->flags = flags;
    *BLOCKANTIMAGIC(block) = block->magic;

    next = BLOCKNEXT(block);
    /*
     * No block check here because it's OK here for next be not
     * initialized.
     * */
    nextofft = (((uintptr_t)next) - ((uintptr_t)ctx->store));
    if (nextofft < ctx->store_sz) {
        next->prev = block->offt;
    }

    return 0;
}

static void
block_fini(lstore_header_t *block)
{
    block->offt = 0xfffffffffffffffful;
    block->magic = 0xfffffffffffffffful;
    block->sz = 0;
    block->prev = 0xfffffffffffffffful;
    block->flags = 0;
}

static int
block_check(lstore_ctx_t *ctx, lstore_header_t *block)
{
    return
        ((block->offt - (((uintptr_t)block) - ((uintptr_t)ctx->store))) == 0) &&
        ((block->magic ^ ctx->magic) == block->offt) &&
        (block->magic == *BLOCKANTIMAGIC(block));
}

static void
count_used_bytes(lstore_ctx_t *ctx, size_t sz)
{
    ctx->nbytes_used += sz;
}

static void
uncount_used_bytes(lstore_ctx_t *ctx, size_t sz)
{
    ctx->nbytes_used -= sz;
}

static void
count_used(lstore_ctx_t *ctx, lstore_header_t *block)
{
    ctx->nblocks_used++;
    ctx->nbytes_used += block->sz;
}

static void
uncount_used(lstore_ctx_t *ctx, lstore_header_t *block)
{
    ctx->nblocks_used--;
    ctx->nbytes_used -= block->sz;
}

void
lstore_get_stats(lstore_ctx_t *ctx, lstore_stats_t *stats)
{
    stats->store_sz = ctx->store_sz;
    stats->nblocks_used = ctx->nblocks_used;
    stats->nbytes_used = ctx->nbytes_used;
}

static void
note_block_fast(mnbtrie_t *list, uintptr_t key, lstore_header_t *block)
{
    mnbtrie_node_t *n;
    n = btrie_add_node(list, key);
    n->value = block;
}

static void
unnote_block_fast(mnbtrie_t *list, uintptr_t key)
{
    mnbtrie_node_t *n;

    n = btrie_find_exact(list, key);

    if (n == NULL || n->value == NULL) {
        return;
    }

    n->value = NULL;
    btrie_remove_node(list, n);
}

static void
note_block(mnbtrie_t *list, uintptr_t key, lstore_header_t *block)
{
    mnbtrie_node_t *n;
    block_list_t *blst;
    block_list_entry_t *ble;

    n = btrie_add_node(list, key);
    //TRACE("n=%p", n);

    if (n->value == NULL) {
        if ((n->value = malloc(sizeof(block_list_t))) == NULL) {
            FAIL("malloc");
        }

        blst = (block_list_t *)n->value;
        blst->key = key;

        SLIST_INIT(&blst->head);

    } else {
        blst = (block_list_t *)n->value;
    }

    SLIST_FOREACH(ble, &blst->head, link) {
        if (ble->block == block) {
            //TRACE("duplicate entry in free list");
            //block_dump(block);
            return;
        }
    }

    if ((ble = malloc(sizeof(block_list_entry_t))) == NULL) {
        FAIL("malloc");
    }

    ble->block = block;
    SLIST_INSERT_HEAD(&blst->head, ble, link);
    //TRACE();
    //btrie_traverse(list, btrie_node_dump_cb, 0);
}

static void
unnote_block(mnbtrie_t *list, uintptr_t key, lstore_header_t *block)
{
    mnbtrie_node_t *n;
    block_list_t *blst;
    block_list_entry_t *ble;

    n = btrie_find_exact(list, key);

    if (n == NULL || n->value == NULL) {
        return;
    }

    blst = (block_list_t *)n->value;

    SLIST_FOREACH(ble, &blst->head, link) {
        if (ble->block == block) {
            SLIST_REMOVE(&blst->head, ble, _block_list_entry, link);
            ble->block = NULL;
            free(ble);
            ble = NULL;
            break;
        }
    }

    if (SLIST_EMPTY(&blst->head)) {
        free(blst);
        n->value = NULL;
        btrie_remove_node(list, n);
    }
    //TRACE();
    //btrie_traverse(list, btrie_node_dump_cb, 0);
}

static lstore_header_t *
unnote_one(mnbtrie_t *list, uintptr_t key)
{
    mnbtrie_node_t *n;
    block_list_t *blst;
    block_list_entry_t *ble;
    lstore_header_t *block = NULL;

    //TRACE("key=%016lx", key);
    //btrie_traverse(list, btrie_node_dump_cb, 0);
    n = btrie_find_closest(list, key, 1);

    if (n == NULL || n->value == NULL) {
        TRRETNULL(UNNOTE_ONE + 1);
    }

    blst = (block_list_t *)n->value;

    ble = SLIST_FIRST(&blst->head);
    if (ble != NULL) {
        SLIST_REMOVE_HEAD(&blst->head, link);
        block = ble->block;
        free(ble);
        ble = NULL;
    }
    if (SLIST_EMPTY(&blst->head)) {
        free(blst);
        n->value = NULL;
        btrie_remove_node(list, n);
    }
    return block;
}

static lstore_header_t *
block_new_used(lstore_ctx_t *ctx, size_t sz)
{
    lstore_header_t *block;
    ssize_t hisz;
    uintptr_t safesz;

    /* optimize it to find exact free holes if possible */
    safesz = sz + METASZ + ALIGNED(1);
    if ((block = unnote_one(&ctx->free_list, safesz)) == NULL) {
        TRRETNULL(BLOCK_NEW_USED + 1);
    }

    hisz = block->sz - sz;

    if (hisz > 0) {
        lstore_header_t *hi;
        /* there is a high slice of the block to put in the free list */
        assert(hisz >= MINIMALBLOCKSZ);
        if (madvise(block, sz, MADV_NORMAL) != 0) {
            perror("madvise");
        }
        block_init(ctx, block, sz, block->prev, USED);
        note_block_fast(&ctx->used_list, ADDR2OFFT(ctx, block), block);
        count_used(ctx, block);
        /*
         * No hi block check here.
         */
        hi = BLOCKNEXT(block);
        if (madvise(hi, sizeof(lstore_header_t), MADV_NORMAL) != 0) {
            perror("madvise");
        }
        block_init(ctx, hi, hisz, ADDR2OFFT(ctx, block), 0);
        note_block(&ctx->free_list, hisz,  hi);
    } else if (hisz < 0) {
        /* note it back */
        note_block(&ctx->free_list, block->sz, block);
        TRRETNULL(BLOCK_NEW_USED + 2);
    }

    return block;
}

/*
 * Join block -> target. block disappears, target extends at the cost of
 * block.
 */
static void
block_join(lstore_ctx_t *ctx, lstore_header_t *block, lstore_header_t *target)
{
    if (BLOCKNEXT(target) == block) {
        block_init(ctx, target, target->sz + block->sz, target->prev,
                   target->flags);
        block_fini(block);
        return;

    } else {
        FAIL("block_join");
    }
}

static void
block_spread_free(lstore_ctx_t *ctx, lstore_header_t *block)
{
    unnote_block_fast(&ctx->used_list, ADDR2OFFT(ctx, block));
    block->flags &= ~USED;
    uncount_used(ctx, block);

    while (BLOCKNEXT2OFFT(block) < ctx->store_sz) {
        lstore_header_t *next;

        next = BLOCKNEXT(block);

        if (!block_check(ctx, next)) {
            FAIL("block_check");
        }

        if (next->flags & USED) {
            break;
        } else {
            unnote_block(&ctx->free_list, next->sz, next);
            block_join(ctx, next, block);
        }
    }

    while (((int64_t)block->prev) >= 0) {
        lstore_header_t *prev;

        prev = OFFT2BLOCK(ctx, block->prev);

        if (!block_check(ctx, prev)) {
            FAIL("block_check");
        }

        if (prev->flags & USED) {
            break;
        } else {
            unnote_block(&ctx->free_list, prev->sz, prev);
            block_join(ctx, block, prev);
            block = prev;
        }
    }

    note_block(&ctx->free_list, block->sz, block);
    if (madvise(block->data, DATASZ(block->sz), MADV_FREE) != 0) {
        perror("madvise");
    }
}

static void
note_all_blocks(lstore_ctx_t *ctx,
                void (*cb)(lstore_ctx_t *, void *, void *), void *uctx)
{
    lstore_header_t *block;

    for (block = (lstore_header_t *)ctx->store;
         ADDR2OFFT(ctx, block) < ctx->store_sz;
         block = BLOCKNEXT(block)) {

        if (!block_check(ctx, block)) {
            FAIL("block_check");
        }

        if (!(block->flags & USED)) {
            note_block(&ctx->free_list, block->sz, block);
            if (madvise(block->data, DATASZ(block->sz), MADV_FREE) != 0) {
                perror("madvise");
            }
        } else {
            note_block_fast(&ctx->used_list, ADDR2OFFT(ctx, block), block);
            count_used(ctx, block);
            // madvise ? no ...
            if (cb != NULL) {
                cb(ctx, &block->data, uctx);
            }
        }
    }
}

void *
lstore_alloc(lstore_ctx_t *ctx, size_t datasz)
{
    lstore_header_t *block;

    if (datasz == 0) {
        TRRETNULL(LSTORE_ALLOC + 1);
    }

    if ((block = block_new_used(ctx, BLOCKSZ(ALIGNED(datasz)))) == NULL) {
        TRRETNULL(LSTORE_ALLOC + 2);
    }

    memset(block->data, PADCHAR, datasz);

    return block->data;
}

/**
 *
 * The offset argumet here is assumed the intended offset of the block
 * holding the returned data. So the returned address will be offset
 * at sizeof(lstore_header_t). The offset must be previously aligned and
 * made sure it fits into a free block.
 *
 * Typical usage is to initialize a storage at known locations before
 * doing anything else.
 */
void *
lstore_alloc_at(lstore_ctx_t *ctx, uint64_t offset, size_t datasz)
{
    mnbtrie_node_t *n;
    lstore_header_t *block = NULL;
    size_t sz;
    intptr_t window_below, window_above;

    if (datasz == 0) {
        TRRETNULL(LSTORE_ALLOC_AT + 1);
    }

    if (ALIGNED(offset) != offset) {
        TRRETNULL(LSTORE_ALLOC_AT + 2);
    }

    sz = BLOCKSZ(ALIGNED(datasz));

    if ((offset + sz) > ctx->store_sz) {
        TRRETNULL(LSTORE_ALLOC_AT + 3);
    }

    /*
     * First see if there is a used block covering the given offset.
     */
    //TRACE("offset=%lx", offset);
    n = btrie_find_closest(&ctx->used_list, offset, 0);
    //TRACE();
    //btrie_traverse(&ctx->used_list, btrie_node_dump_cb, 0);
    if (n != NULL) {

        block = (lstore_header_t *)n->value;
        /*
         * now set it to the next to it.  BLOCKNEXT(block) must be a free
         * block
         */
        //TRACE("before");
        //block_dump(ctx, block);
        block = BLOCKNEXT(block);

        //TRACE("after");
        //block_dump(ctx, block);

        if (!block_check(ctx, block)) {
            FAIL("block_check");
        }

        assert((!block->flags & USED));

        window_below = offset - ADDR2OFFT(ctx, block);
        if (window_below < 0) {
            /* the in-use block (the previous one) covers the given offset */
            TRRETNULL(LSTORE_ALLOC_AT + 4);
        } else {
            window_above = BLOCKNEXT2OFFT(block) - (offset + sz);
            if (window_above != 0 && window_above < MINIMALBLOCKSZ) {
                /* the block won't fit upside */
                //TRACE("nextoffset=%lx offset=%lx sz=%lx window_above=%lx MINIMALBLOCKSZ=%lx", BLOCKNEXT2OFFT(block), offset, sz, window_above, MINIMALBLOCKSZ);
                TRRETNULL(LSTORE_ALLOC_AT + 5);
            }
            if (window_below > 0 && window_below < MINIMALBLOCKSZ) {
                /* the block won't fit downside */
                TRRETNULL(LSTORE_ALLOC_AT + 6);
            }
        }
    } else {
        /* must be the zero-th offset block */
        block = (lstore_header_t *)ctx->store;

        if (!block_check(ctx, block)) {
            FAIL("block_check");
        }

        assert(ADDR2OFFT(ctx, block) == 0);
        window_above = BLOCKNEXT2OFFT(block) - (offset + sz);
        if (window_above != 0 && window_above < MINIMALBLOCKSZ) {
            /* the block won't fit upside */
            TRRETNULL(LSTORE_ALLOC_AT + 7);
        }
        window_below = offset - ADDR2OFFT(ctx, block);
        if (window_below > 0 && window_below < MINIMALBLOCKSZ) {
            /* the block won't fit downside */
            TRRETNULL(LSTORE_ALLOC_AT + 8);
        }
    }

    if (block == NULL) {
        TRRETNULL(LSTORE_ALLOC_AT + 9);
    } else {
        lstore_header_t *res, *hi;
        uint64_t hisz = block->sz;
        /* carve off the requested block from this free one. */
        unnote_block(&ctx->free_list, block->sz, block);
        if ((offset - ADDR2OFFT(ctx, block)) > 0) {
            block_init(ctx, block, offset - ADDR2OFFT(ctx, block),
                       block->prev, 0);
            note_block(&ctx->free_list, block->sz, block);
            // madvise ? no ...
            hisz -= block->sz;
            res = OFFT2BLOCK(ctx, offset);
            if (madvise(res, sz, MADV_NORMAL) != 0) {
                perror("madvise");
            }
            block_init(ctx, res, sz, ADDR2OFFT(ctx, block), USED);
            note_block_fast(&ctx->used_list, offset, res);
            count_used(ctx, res);
            hisz -= res->sz;
        } else {
            if (madvise(block, sz, MADV_NORMAL) != 0) {
                perror("madvise");
            }
            block_init(ctx, block, sz, block->prev, USED);
            note_block_fast(&ctx->used_list, offset, block);
            count_used(ctx, block);
            hisz -= block->sz;
            res = block;
        }

        if (hisz > 0) {
            hi = OFFT2BLOCK(ctx, offset + sz);
            if (madvise(hi, sizeof(lstore_header_t), MADV_NORMAL) != 0) {
                perror("madvise");
            }
            block_init(ctx, hi, hisz, offset, 0);
            note_block(&ctx->free_list, hisz, hi);
        }
        memset(res->data, PADCHAR, datasz);
        return res->data;
    }

}

void *
lstore_realloc(void *data, size_t newdatasz)
{
    lstore_header_t *block = BLOCK(data);
    lstore_ctx_t *ctx = BLOCK2CTX(block);
    newdatasz = ALIGNED(newdatasz);
    uint64_t sz = BLOCKSZ(newdatasz);
    uint64_t diff;
    lstore_header_t *next, *nextfree;

    if (!block_check(ctx, block)) {
        FAIL("block_check");
    }

    if (newdatasz == 0) {
        return NULL;
    }

    if (block->sz >= sz) {
        /* shrinking */
        diff = block->sz - sz;

        if (diff < MINIMALBLOCKSZ) {
            return data;
        }

        nextfree = BLOCKNEXT(block);

        if (!block_check(ctx, nextfree)) {
            FAIL("block_check");
        }

        block_init(ctx, block, sz, block->prev, USED);
        next = BLOCKNEXT(block);
        block_init(ctx, next, diff, ADDR2OFFT(ctx, block), 0);
        uncount_used_bytes(ctx, diff);

        unnote_block(&ctx->free_list, nextfree->sz, nextfree);
        block_join(ctx, nextfree, next);
        note_block(&ctx->free_list, next->sz, next);
        if (madvise(next->data, DATASZ(next->sz), MADV_FREE) != 0) {
            perror("madvise");
        }
        return data;

    } else {
        /* extending */
        diff = sz - block->sz;
        next = BLOCKNEXT(block);

        if (!block_check(ctx, next)) {
            FAIL("block_check");
        }

        if (!(next->flags & USED)) {
            uintptr_t nextsz;

            nextsz = next->sz;

            if (diff == nextsz) {
                /* exact fit,  forget about next */
                unnote_block(&ctx->free_list, nextsz, next);
                if (madvise(next, nextsz, MADV_NORMAL) != 0) {
                    perror("madvise");
                }
                block_join(ctx, next, block);
                count_used_bytes(ctx, nextsz);
                memset(next, PADCHAR, nextsz);
                return data;

            } else if ((diff + MINIMALBLOCKSZ) <= nextsz) {
                /* forget about next */
                unnote_block(&ctx->free_list, nextsz, next);
                if (madvise(next, nextsz, MADV_NORMAL) != 0) {
                    perror("madvise");
                }
                block_init(ctx, block, block->sz + diff, block->prev, USED);
                count_used_bytes(ctx, diff);
                memset(next, PADCHAR, diff);
                /* advance to next free and make note of it */
                next = BLOCKNEXT(block);
                block_init(ctx, next, nextsz - diff, ADDR2OFFT(ctx, block), 0);
                note_block(&ctx->free_list, next->sz, next);
                return data;

            } else {
                goto relocate;

            }

        } else {
            /* relocate */
            size_t datasz;
            void *newdata;

relocate:
            datasz = DATASZ(block->sz);
            if ((newdata = lstore_alloc(ctx, newdatasz)) == NULL) {
                return NULL;
            }
            memcpy(newdata, data, datasz);
            memset((void *)((uintptr_t)newdata + datasz), PADCHAR,
                   newdatasz - datasz);
            lstore_free(data);
            return newdata;
        }
    }

    return NULL;
}

void
lstore_put_down(void *data)
{
    lstore_header_t *block = BLOCK(data);
    lstore_ctx_t *ctx = BLOCK2CTX(block);

    if (data == NULL) {
        return;
    }

    if (!block_check(ctx, block)) {
        FAIL("block_check");
    }

    return lstore_put_down_sz(data, DATASZ(block->sz));
}

void
lstore_put_down_sz(void *data, size_t sz)
{
    uintptr_t lowtail;
    void *adata;

    lowtail = (PAGE_SIZE - (((uintptr_t)data) % PAGE_SIZE));
    if (lowtail == PAGE_SIZE) {
        lowtail = 0;
    }

    if (sz <= lowtail) {
        return;
    }
    sz = DATASZ_FULLPAGES(sz - lowtail);

    if (sz == 0) {
        return;
    }

    adata = (void *)(((uintptr_t)data) + lowtail);
    if (madvise(adata, sz, MADV_DONTNEED) != 0) {
        perror("madvise");
    }
}

void
lstore_take_up(void *data)
{
    lstore_header_t *block = BLOCK(data);
    lstore_ctx_t *ctx = BLOCK2CTX(block);

    if (data == NULL) {
        return;
    }

    if (!block_check(ctx, block)) {
        FAIL("block_check");
    }

    return lstore_take_up_sz(data, DATASZ(block->sz));
}

void
lstore_take_up_sz(void *data, size_t sz)
{
    uintptr_t lowtail;
    void *adata;

    lowtail = (PAGE_SIZE - (((uintptr_t)data) % PAGE_SIZE));
    if (lowtail == PAGE_SIZE) {
        lowtail = 0;
    }

    if (sz <= lowtail) {
        return;
    }

    sz = DATASZ_FULLPAGES(sz - lowtail);
    if (sz == 0) {
        return;
    }

    adata = (void *)(((uintptr_t)data) + lowtail);
    if (madvise(adata, sz, MADV_NORMAL) != 0) {
        perror("madvise");
    }
}

void
lstore_free(void *data)
{
    lstore_header_t *block = BLOCK(data);
    lstore_ctx_t *ctx;

    if (data == NULL) {
        return;
    }

    ctx = BLOCK2CTX(block);

    if (!block_check(ctx, block)) {
        FAIL("block_check");
    }

    if (!(block->flags & USED)) {
        return;
    }

    block_spread_free(ctx, block);
}

uint64_t
lstore_offset(void *data)
{
    lstore_header_t *block = BLOCK(data);
    lstore_ctx_t *ctx = BLOCK2CTX(block);

    if (!block_check(ctx, block)) {
        FAIL("block_check");
    }

    return block->offt;
}

uint64_t
lstore_elen(void *data)
{
    lstore_header_t *block = BLOCK(data);
    lstore_ctx_t *ctx = BLOCK2CTX(block);

    if (!block_check(ctx, block)) {
        FAIL("block_check");
    }

    return DATASZ(block->sz);
}

lstore_ctx_t *
lstore_init_fd(int fd, void (*cb)(lstore_ctx_t *, void *, void *),
               void *uctx, int flags)
{
    size_t store_sz;
    lstore_ctx_t *ctx;
    struct stat sb;

    if (fstat(fd, &sb) == -1) {
        TRRETNULL(LSTORE_INIT_FD + 1);
    }

    /* align store_sz to our alignment */
    store_sz = ALIGNED(sb.st_size - ALIGNMENT);
    //TRACE("store_sz=%ld st_size=%ld", store_sz, sb.st_size);

    if ((ctx = mmap(NULL, store_sz, PROT_READ|PROT_WRITE,
                      MAP_NOCORE|MAP_SHARED, fd, 0)) == MAP_FAILED) {
        TRRETNULL(LSTORE_INIT_FD + 2);
    }

    ctx->fd = fd;

    btrie_init(&ctx->free_list);
    btrie_init(&ctx->used_list);

    ctx->store = (void *)(((uintptr_t)ctx) + sizeof(lstore_ctx_t));

    if (! (flags & LSTORE_INIT_FORCE)) {
        /* check the store */
        if (ctx->store_sz != store_sz - sizeof(lstore_ctx_t)) {
            TRRETNULL(STORE_INIT_FD + 3);
        }
        if (!block_check(ctx, ctx->store)) {
            /* store_recover, not block_init */
            TRRETNULL(STORE_INIT_FD + 4);
            //block_init(ctx, ctx->store, ctx->store_sz, 0 - ((uintptr_t)ctx->store), 0);
        }
    } else {
        //ctx->magic = 0x1122334455667788;
        ctx->magic = (uint64_t)random();
        ctx->store_sz = store_sz - sizeof(lstore_ctx_t);
        block_init(ctx, ctx->store, ctx->store_sz,
                   0 - ((uintptr_t)ctx->store), 0);
        ctx->nblocks_used = 0;
        ctx->nbytes_used = 0;
    }

    note_all_blocks(ctx, cb, uctx);
    return ctx;
}

lstore_ctx_t *
lstore_init(const char *path,
            void (*cb)(lstore_ctx_t *, void *, void *), void *uctx, int flags)
{
    int fd;
    lstore_ctx_t *ctx;

    if ((fd = open(path, O_RDWR|O_EXLOCK)) == -1) {
        TRRETNULL(LSTORE_INIT + 2);
    }

    if ((ctx = lstore_init_fd(fd, cb, uctx, flags)) == NULL) {
        close(fd);
        return NULL;
    }

    ctx->path = path;

    return ctx;
}

void
lstore_fini(lstore_ctx_t *ctx)
{
    btrie_fini(&ctx->free_list);
    btrie_fini(&ctx->used_list);

    if (msync(ctx->store, 0, MS_SYNC) == -1) {
        perror("msync");
    }

    if (ctx->path != NULL) {
        close(ctx->fd);
        ctx->path = NULL;
    }
    ctx->fd = -1;
    if (munmap(ctx, ctx->store_sz + sizeof(lstore_ctx_t)) == -1) {
        perror("munmap");
    }
}

// vim:list
