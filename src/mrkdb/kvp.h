#ifndef KVP_H
#define KVP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *mrkdb_diag_str(int);

#ifndef KVP_ITEM_DEFINED
typedef struct _kvp_item {
    size_t sz;
    const void *data;
} kvp_item_t;
#define KVP_ITEM_DEFINED
#endif

typedef struct _kvp {
    const kvp_item_t *key;
    const kvp_item_t *value;
} kvp_t;

#ifndef KVP_CTX_T_DEFINED
typedef struct _kvp_ctx kvp_ctx_t;
#define KVP_CTX_T_DEFINED
#endif

typedef struct _kvp_stats {
    size_t sz;
    size_t nbytes_used;
    size_t nblocks_used;
} kvp_stats_t;

kvp_ctx_t *kvp_new(void);
int kvp_load(kvp_ctx_t *, const char *);
int kvp_extend(kvp_ctx_t *, const char *);
void kvp_fini(kvp_ctx_t *);

int kvp_put(kvp_ctx_t *, const kvp_item_t *, const kvp_item_t *);
int kvp_put_from_args(kvp_ctx_t *, size_t, const void *, size_t, const void *);
int kvp_put_from_args_fd(kvp_ctx_t *, size_t, const void *, size_t, int);

int kvp_delete(kvp_ctx_t *, const kvp_item_t *);
int kvp_delete_from_args(kvp_ctx_t *, size_t, const void *);

const kvp_item_t *kvp_get(kvp_ctx_t *, const kvp_item_t *);
const kvp_item_t *kvp_get_from_args(kvp_ctx_t *, size_t, const void *);

void kvp_get_stats(kvp_ctx_t *, kvp_stats_t *);
void kvp_stores_dump(kvp_ctx_t *);

#ifdef __cplusplus
}
#endif

#endif

// vim:list
