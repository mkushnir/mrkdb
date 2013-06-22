#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "unittest.h"
#include "mrkcommon/dumpm.h"
#include "mrkcommon/util.h"

#include "mrkdb/kvp.h"
#include "mrkdb/lstore.h"

const char *stores[] = {
    "/tmp/test-lstore.db.00",
    "/tmp/test-lstore.db.01",
    "/tmp/test-lstore.db.02",
    "/tmp/test-lstore.db.03",
    "/tmp/test-lstore.db.04",
    "/tmp/test-lstore.db.05",
    "/tmp/test-lstore.db.06",
    "/tmp/test-lstore.db.07",
};
UNUSED static void
test0(void)
{
    kvp_ctx_t *ctx;
    struct {
        long rnd;
        const char *key;
        int value;
    } data[] = {
        {0, "This is the test 1", 1},
        {0, "This is another test 2", 2},
        {0, "This is another test qwe 3", 3},
        {0, "This is another test qwe asd 4", 4},
        {0, "This is another test qwe asd asd 5", 5},
        {0, "This is another test qwe asd asd 6", 6},
    };
    UNITTEST_PROLOG_RAND;

    ctx = kvp_new();
    for (i = 0; i < countof(stores); ++i) {
        kvp_extend(ctx, stores[i]);
    }

    FOREACHDATA {
        //TRACE("Put %s", CDATA.key);
        kvp_put_from_args(ctx,
                          strlen(CDATA.key), CDATA.key,
                          sizeof(CDATA.value), &(CDATA.value));
    }

    SHUFFLE;

    FOREACHDATA {
        const kvp_item_t *it;

        it = kvp_get_from_args(ctx, strlen(CDATA.key), CDATA.key);
        //TRACE("Got item %s", CDATA.key);
        assert(it != NULL);
        //D8(it->data, it->sz);
    }

    SHUFFLE;

    FOREACHDATA {
        kvp_delete_from_args(ctx, strlen(CDATA.key), CDATA.key);
    }

    SHUFFLE;

    FOREACHDATA {
        const kvp_item_t *it;

        it = kvp_get_from_args(ctx, strlen(CDATA.key), CDATA.key);
        //TRACE("Got item %s", CDATA.key);
        assert(it == NULL);
    }

    kvp_fini(ctx);

}

int
main(void)
{
    test0();
    return 0;
}

// vim:list
