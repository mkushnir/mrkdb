#ifndef KVP_PRIVATE_H
#define KVP_PRIVATE_H

#include <stdint.h>
#include <sys/tree.h>

#include "mrkdb/lstore.h"
#include "mrkcommon/array.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Multi-Processor labels
 */
#define MPSAFE
#define MPUNSAFE


/*
 * lstore interface.
 */

#define ALIGNMENT (sizeof(uint32_t))
#define ALIGN_MASK (ALIGNMENT - 1)
#define ALIGNED(sz) \
    ((((sz) & ALIGN_MASK) == 0) ? \
     (sz) : ((sz) + ALIGNMENT - ((sz) & ALIGN_MASK)))

typedef struct _kvp_header {
#   define KVP_META (0xfffffffffffffffful)
    /* the size of the data without alignment padding */
    uint64_t sz;
} kvp_header_t;

#define KVP_ITEMSZ_ARG(sz) \
    (sizeof(kvp_header_t) + ALIGNED(sz))

#define KVP_ITEMSZ(it) \
    (sizeof(kvp_header_t) + ALIGNED(((kvp_item_t *)(it))->sz))

#define KVP_KEY(pair) ((kvp_record_t *)pair)

#define KVP_RECORDSZ(rec) \
    (sizeof(kvp_header_t) + ALIGNED(((kvp_record_t *)(rec))->header.sz))

#define KVP_VALUE(pair) \
    ((kvp_record_t *)((uintptr_t)(pair) + KVP_RECORDSZ(pair)))

typedef struct _kvp_meta {
    kvp_header_t header;
    uint32_t version;
} kvp_meta_t;

typedef struct _kvp_record {
    kvp_header_t header;
    char data[];
} kvp_record_t;


#define KVP_VERSION 0x11111111

#ifndef KVP_ITEM_DEFINED
typedef struct _kvp_item {
    size_t sz;
    const void *data;
} kvp_item_t;
#define KVP_ITEM_DEFINED
#endif

typedef struct _kvpe {
    RB_ENTRY(_kvpe) link;
    kvp_record_t *rec;
    kvp_item_t key;
    kvp_item_t value;
} kvpe_t;

RB_HEAD(_kvpt, _kvpe);

typedef struct _kvp_ctx {
    struct _kvpt index;
    mnarray_t stores;
} kvp_ctx_t;

typedef struct _kvp_store {
    lstore_ctx_t *lstore_ctx;
    kvp_ctx_t *kvp_ctx;
    /* back-reference to the mother ctx. Ugly ... */
    uint32_t version;
} kvp_store_t;

#define KVP_CTX_T_DEFINED

#ifdef __cplusplus
}
#endif

#include "mrkdb/kvp.h"

#endif

// vim:list
