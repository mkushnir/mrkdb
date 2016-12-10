#include <assert.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "unittest.h"
#include "diag.h"
#include "mrkcommon/dumpm.h"
#include "mrkcommon/util.h"
#include "mrkcommon/array.h"
#include "mrkcommon/traversedir.h"
#include "mrkdb/kvp.h"


typedef struct _file_info {
    long rnd;
    char *path;
    size_t sz;
    unsigned int flags;
} file_info_t;

typedef struct _file_info2 {
    long rnd;
    file_info_t *fi;
} file_info2_t;

static mnarray_t files;
#define TSF_INITIALIZED 0x01
#define TSF_SHUTDOWN    0x02
static int test_suite_flags;
#define TS_SHUTDOWN     (test_suite_flags & TSF_SHUTDOWN)
#define TS_INITIALIZED  (test_suite_flags & TSF_INITIALIZED)

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

static void
set_shutdown(UNUSED int sig)
{
    test_suite_flags |= TSF_SHUTDOWN;
}

static int
mycb(const char *path, struct dirent *de, void *ctx)
{
    mnarray_t *files = (mnarray_t *)ctx;
    file_info_t *fi;
    UNUSED struct stat sb;

    if (TS_SHUTDOWN) {
        return 1;
    }
    //TRACE("de=%p", de);
    if (de == NULL) {
        return 0;
    }
    //TRACE("path=%p fileno=%d reclen=%hd type=%hhd namelen=%hhd name=%p",
    //       path, de->d_fileno, de->d_reclen, de->d_type, de->d_namlen,
    //       de->d_name);

    if ((fi = array_incr(files)) == NULL) {
        return 1;
    }
    if ((fi->path = path_join(path, de->d_name)) == NULL) {
        return 1;
    }
    fi->sz = strlen(fi->path);
    fi->flags = 0;
    //if (stat(fi->path, &sb) == 0) {
    //    //TRACE("S_ISDIR=%d", S_ISDIR(sb.st_mode));
    //}
    return 0;
}

static int
file_info_fini(file_info_t *fi)
{
    if (fi->path != NULL) {
        free(fi->path);
        fi->path = NULL;
    }
    fi->flags = 0;
    return 0;
}

UNUSED static int
file_info_print(file_info_t *fi)
{
    TRACE("%s", fi->path);
    return 0;
}

static void
ts_initialize(void)
{
    struct {
        long rnd;
        const char *path;
    } data[] = {
        //{0, "/usr"},
        //{0, "/usr/local"},
        {0, "/usr/local/bin"},
        {0, "/usr/local/lib"},
        //{0, "/home/mkushnir/music"},
        //{0, "/usr/data"},
        //{0, "/usr/data/amule-temp"},
        //{0, "/skyrta/data/music/bach"},
        //{0, "/skyrta/data/music/bruckner"},
        //{0, "/skyrta/data/music/beethowen"},
        //{0, "/skyrta/data/music/wagner"},
    };
    UNITTEST_PROLOG;

    if (TS_INITIALIZED) {
        return;
    }

    array_init(&files, sizeof(file_info_t), 0,
               NULL, (array_finalizer_t)file_info_fini);
    FOREACHDATA {
        if (traverse_dir(CDATA.path, mycb, &files) != 0) {
            //perror("opendir");
            //return;
            //assert(0);
            //break;
        }
        //array_traverse(&files, (array_traverser_t)file_info_print);
    }

    test_suite_flags |= TSF_INITIALIZED;

}


#define SZLIMIT ((long)(1024ul*1024ul*128ul))
//#define SZLIMIT (1024ul*1024ul*1024ul*5ul)
static void
run_put(kvp_ctx_t *ctx, file_info_t *fi)
{
    int fd;
    struct stat sb;

    //TRACE("Trying %s", fi->path);
    if ((fd = open(fi->path, O_RDONLY)) == -1) {
        //TRACE("Put skipped %s open failed", fi->path);
        fprintf(stderr, FRED("o"));
        fflush(stderr);
        return;
    }

    if (fstat(fd, &sb) != 0) {
        FAIL("stat");
    }

    if (sb.st_size > SZLIMIT) {
        close(fd);
        //TRACE("Put skipped %s sz=%ld", fi->path, sb.st_size);
        fprintf(stderr, FBLUE("s"));
        fflush(stderr);
        return;
    }

    if (kvp_put_from_args_fd(ctx, fi->sz,
                             fi->path, sb.st_size, fd) != 0) {
        //TRACE("Put failed %s (size %ld)", fi->path, sb.st_size);
        fprintf(stderr, FYELLOW("%s"), "p");
        fflush(stderr);

    } else {
        fi->flags = 1;
        //TRACE("Put succeeded %s", fi->path);
        fprintf(stderr, "+");
        fflush(stderr);
    }

    close(fd);
}


#define DELETE_RATIO 3
static void
run_delete(kvp_ctx_t *ctx, int delete_step)
{
    mnarray_iter_t it;
    file_info_t *fi;
    file_info2_t *dfiles;
    int i, ndelete = delete_step / DELETE_RATIO;

    if ((dfiles = malloc(sizeof(file_info2_t) * delete_step)) == NULL) {
        FAIL("malloc");
    }

    for (fi = array_first(&files, &it), i = 0;
         fi != NULL && i < delete_step;
         fi = array_next(&files, &it)) {

        //TRACE("before SHUFFLE: %s %d", fi->path, fi->flags);
        if (fi->flags) {
            dfiles[i].fi = fi;
            _R(dfiles, i) = i;
            ++i;
        }
    }
    //for (i = 0; i < delete_step; ++i) {
    //    fi = dfiles[i].fi;
    //    TRACE(">>>path=%s flags=%d rnd=%ld", fi->path, fi->flags, fi->rnd);
    //}

    _DSHUFFLE(dfiles, i, delete_step);

    //for (i = 0; i < delete_step; ++i) {
    //    fi = dfiles[i].fi;
    //    TRACE("<<<path=%s flags=%d rnd=%ld", fi->path, fi->flags, fi->rnd);
    //}

    for (i = 0; i < ndelete; ++i) {
        fi = _CD(dfiles).fi;
        //TRACE("Trying to delete %s flags=%d", fi->path, fi->flags);
        if (fi->flags == 0) {
            continue;
        }
        if (kvp_delete_from_args(ctx, fi->sz, fi->path)) {
            //TRACE("Delete failed %s", fi->path);
            fprintf(stderr, "|");
            fflush(stderr);
        } else {
            fi->flags = 0;
            //TRACE("Delete succeeded %s", fi->path);
            fprintf(stderr, "-");
            fflush(stderr);
        }
        //usleep(10000);
    }

    free(dfiles);
    dfiles = NULL;
}


UNUSED static void
test_put_delete(unsigned delete_step)
{
    unsigned i;
    file_info_t *fi;
    mnarray_iter_t it;
    kvp_ctx_t *ctx;
    kvp_stats_t stats;

    ts_initialize();

    ctx = kvp_new();
    kvp_extend(ctx, "/usr/data/test-lstore.db");
    for (i = 0; i < countof(stores); ++i) {
        kvp_extend(ctx, stores[i]);
    }

    for (fi = array_first(&files, &it);
         fi != NULL && !TS_SHUTDOWN;
         fi = array_next(&files, &it)) {

        run_put(ctx, fi);

        if (delete_step && (it.iter % delete_step) == (delete_step - 1)) {
            run_delete(ctx, delete_step);
        }
        //usleep(100000);
    }

    //kvp_stores_dump(ctx);
    kvp_get_stats(ctx, &stats);
    fprintf(stderr, "\n");
    TRACE("Used %ld blocks, %ld bytes out of %ld (%d%%)",
            stats.nblocks_used, stats.nbytes_used, stats.sz,
            (int)(((double)stats.nbytes_used / (double)stats.sz) * 100.));

    array_fini(&files);

    kvp_fini(ctx);
}


int
main(void)
{
    signal(SIGTERM, set_shutdown);
    signal(SIGINT, set_shutdown);
    test_put_delete(100);
    return 0;
}

// vim:list
