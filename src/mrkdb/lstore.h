#ifndef LSTORE_H
#define LSTORE_H

#include <stddef.h>
#include <stdint.h>

#ifndef LSTORE_CTX_T_DEFINED
#define LSTORE_CTX_T_DEFINED
typedef struct _lstore_ctx lstore_ctx_t;
#endif

typedef struct _lstore_stats {
    size_t store_sz;
    size_t nblocks_used;
    size_t nbytes_used;
} lstore_stats_t;

#define LSTORE_INIT_FORCE 0x01
lstore_ctx_t *lstore_init_fd(int, void (*)(lstore_ctx_t *, void *, void *), void *,  int);
lstore_ctx_t *lstore_init(const char *, void (*)(lstore_ctx_t *, void *, void *), void *,  int);
void lstore_fini(lstore_ctx_t *);
void lstore_dump(lstore_ctx_t *);

void *lstore_alloc(lstore_ctx_t *, size_t);
void *lstore_alloc_at(lstore_ctx_t *, uint64_t, size_t);
void *lstore_realloc(void *, size_t);
void lstore_free(void *);
void lstore_put_down(void *);
void lstore_take_up(void *);
void lstore_put_down_sz(void *, size_t);
void lstore_take_up_sz(void *, size_t);
uint64_t lstore_offset(void *);
uint64_t lstore_elen(void *);

void lstore_get_stats(lstore_ctx_t *, lstore_stats_t *);
#endif
