#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "unittest.h"
#include "mrkcommon/dumpm.h"
#include "mrkcommon/util.h"

#include "mrkdb/lstore.h"

static void
mycb(UNUSED lstore_ctx_t *ctx, void *data, UNUSED void *uctx)
{
    TRACE("offt=%016lx len=%lu", lstore_offset(data), lstore_elen(data));
}

UNUSED static void
test_alloc_free(void)
{
    lstore_ctx_t *ctx;
    struct {
        long rnd;
        void *addr;
        int sz;
    } data[] = {
        {0, NULL, 255},
        {0, NULL, 1},
        {0, NULL, 2},
        {0, NULL, 3},
        {0, NULL, 8},
        {0, NULL, 16},
        {0, NULL, 31},
        {0, NULL, 310},
        {0, NULL, 3100},
        {0, NULL, 31000},
    };
    UNITTEST_PROLOG_RAND;

    ctx = lstore_init("/tmp/test-lstore.db.00", mycb, NULL, LSTORE_INIT_FORCE);

    for (i = 0; i < countof(data); ++i) {
        RDATA(i).addr = lstore_alloc(ctx, RDATA(i).sz);
        assert(RDATA(i).addr != NULL);
    }

    //lstore_dump(ctx);

    SHUFFLE;

    for (i = 0; i < countof(data); ++i) {
        //TRACE("freeing %p", RDATA(i).addr);
        lstore_free(RDATA(i).addr);
    }

    lstore_fini(ctx);
}

UNUSED static void
test_alloc_at(void)
{
    lstore_ctx_t *ctx;
    struct {
        long rnd;
        uint64_t offset;
        size_t sz;
        void *block;
        int expected;

    } data[] = {
        {0, 0x000ul, 0x100, NULL, 0},
        {0, 0x200ul, 0x100, NULL, 0},
        {0, 0x400ul, 0x100, NULL, 0},
        {0, 0x530ul, 0x10,  NULL, 0},
        {0, 0x600ul, 0x100, NULL, 0},
    };
    //UNITTEST_PROLOG;
    UNITTEST_PROLOG_RAND;

    ctx = lstore_init("/tmp/test-lstore.db.00", mycb, NULL, LSTORE_INIT_FORCE);
    //lstore_dump(ctx);

    FOREACHDATA {
        CDATA.block = lstore_alloc_at(ctx, CDATA.offset, CDATA.sz);
        //lstore_dump(ctx);
    }

    //lstore_dump(ctx);

    SHUFFLE;

    FOREACHDATA {
        assert((CDATA.block == NULL) == CDATA.expected);
        //TRACE("Freeing %p", CDATA.block);
        if (CDATA.block != NULL) {
            lstore_free(CDATA.block);
        }
    }
    //lstore_dump(ctx);

    lstore_fini(ctx);
}

UNUSED static void
test_full(void)
{
    lstore_ctx_t *ctx;
    struct {
        long rnd;
        size_t sz;
        void *block;
        int expected;
    } data[] = {
        {0, 131072, NULL, 0},
        {0, 131072, NULL, 0},
        {0, 131072, NULL, 0},
        {0, 131072, NULL, 0},
        {0, 131072, NULL, 0},
        {0, 131072, NULL, 0},
        {0, 131072, NULL, 0},
        {0, 131072, NULL, 1},
    };
    UNITTEST_PROLOG;

    ctx = lstore_init("/tmp/test-lstore.db.00", mycb, NULL, LSTORE_INIT_FORCE);

    FOREACHDATA {
        CDATA.block = lstore_alloc(ctx, CDATA.sz);
        //TRACE("i=%d block=%p", i, CDATA.block);
    }
    FOREACHDATA {
        assert((CDATA.block == NULL) == CDATA.expected);
        //TRACE("Freeing %p", CDATA.block);
        if (CDATA.block != NULL) {
            lstore_free(CDATA.block);
        }
    }
    //lstore_dump(ctx);
    lstore_fini(ctx);
}


int
main(void)
{
    test_alloc_free();
    test_alloc_at();
    test_full();
    return 0;
}

// vim:list
