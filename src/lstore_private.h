#ifndef LSTORE_PRIVATE_H
#define LSTORE_PRIVATE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/param.h>

#include "mrkcommon/btrie.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Storage interface.
 *
 */

#define ALIGNMENT (sizeof(uint64_t))
#define ALIGN_MASK (ALIGNMENT - 1)
#define ALIGNED(sz) \
    ((((sz) & ALIGN_MASK) == 0) ? \
     (sz) : ((sz) + ALIGNMENT - ((sz) & ALIGN_MASK)))

typedef struct _lstore_header {
    uint64_t offt;
    uint64_t magic;

    /* the size of the entire block starting from offt */
    uint64_t sz;

    uint64_t prev;

    /* TODO: merge with sz */
#   define USED 0x01ul
#   define LOCKED 0x02ul
    uint64_t flags;

    char data[];

} lstore_header_t;

#define MINIMALBLOCKSZ ((ssize_t)(sizeof(lstore_header_t) + ALIGNED(1)))

#define METASZ (sizeof(lstore_header_t) + sizeof(uint64_t))

#define DATASZ(sz) ((size_t)((sz) - METASZ))

#define PAGE_SIZE_MASK (~((size_t)(PAGE_SIZE - 1)))

#define DATASZ_FULLPAGES(sz) ((size_t)((sz) & PAGE_SIZE_MASK))

#define BLOCKSZ(datasz) ((size_t)((datasz) + METASZ))

#define BLOCK(data) \
    ((lstore_header_t *)(((uintptr_t)(data)) - sizeof(lstore_header_t)))

/* ADDR2OFFT doesn't access memory location pointed to by addr */
#define ADDR2OFFT(ctx, addr) ((uint64_t)(((uintptr_t)(addr)) - ((uintptr_t)((ctx)->store))))

#define BLOCK2CTX(block) \
    ((lstore_ctx_t *)(((uintptr_t) (block)) - (block)->offt         - sizeof(lstore_ctx_t)))
#define ADDR2CTX(ctx, addr) \
    ((lstore_ctx_t *)(((uintptr_t) (addr))  - ADDR2OFFT(ctx, block) - sizeof(lstore_ctx_t)))

#define OFFT2BLOCK(ctx, offt) \
    ((lstore_header_t *)(((uintptr_t)(ctx)->store) + ((uintptr_t)(offt))))

#define BLOCKNEXT(block) \
    ((lstore_header_t *)(((uintptr_t)(block)) + (block)->sz))

#define BLOCKANTIMAGIC(block) \
    ((uint64_t *)(((uintptr_t)(block)) + (block)->sz - sizeof(uint64_t)))

#define BLOCKNEXT2OFFT(block) ((block)->offt + (block)->sz)


/*
 * Management interface.
 *
 */

#define PADCHAR 0x00

typedef struct _block_list_entry {
    lstore_header_t *block;
    SLIST_ENTRY(_block_list_entry) link;
} block_list_entry_t;

typedef struct _block_list {
    uint64_t key;
    SLIST_HEAD(,_block_list_entry) head;
} block_list_t;

typedef struct _lstore_ctx {
    const char *path;
    int fd;
    void *store;
    uint64_t magic;
    size_t store_sz;
    /* indexed by size */
    btrie_t free_list;
    /* indexed by address */
    btrie_t used_list;
    size_t nblocks_used;
    size_t nbytes_used;

} lstore_ctx_t;
#define LSTORE_CTX_T_DEFINED

#ifdef __cplusplus
}
#endif

#include "mrkdb/lstore.h"
#endif
