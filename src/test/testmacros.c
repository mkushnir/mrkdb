#include <assert.h>
#include "lstore_private.h"
#include "mrkcommon/dumpm.h"
#include "mrkcommon/util.h"

int
main(void)
{
    unsigned i;
    struct {
        int in;
        int expected;
    } data[] = {
        {0, 0},
        {1, 8},
        {7, 8},
        {8, 8},
        {9, 16},
    };
    for (i = 0; i < countof(data); ++i) {
        //TRACE("ALIGNED(%d) = %d", data[i].in, (int)ALIGNED(data[i].in));
        assert(ALIGNED(data[i].in) == data[i].expected);
    }
    return 0;
}
