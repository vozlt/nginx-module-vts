/*
 * @file:    ngx_http_vhost_traffic_status_module.c
 * @brief:   Nginx virtual host traffic status module
 * @author:  YoungJoo.Kim <vozlt@vozlt.com>
 * @version:
 * @date:
 *
 * Compile:
 *           shell> ./configure --add-module=/path/to/nginx-module-vts
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include "ngx_http_vhost_traffic_status_module_html.h"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO 0
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA 1
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG 2
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC 3
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG 4

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_NONE 0
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON 1
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML 2

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_NAME "vhost_traffic_status"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_SIZE 0xfffff

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S "{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_S "\"%V\":{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S "\"%V\":["

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E "]"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_E "}"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E "}"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT ","

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_MAIN "\"nginxVersion\":\"%s\"," \
    "\"loadMsec\":%M,"                                                         \
    "\"nowMsec\":%M,"                                                          \
    "\"connections\":{"                                                        \
    "\"active\":%uA,"                                                          \
    "\"reading\":%uA,"                                                         \
    "\"writing\":%uA,"                                                         \
    "\"waiting\":%uA,"                                                         \
    "\"accepted\":%uA,"                                                        \
    "\"handled\":%uA,"                                                         \
    "\"requests\":%uA"                                                         \
    "},"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S "\"serverZones\":{"
#if (NGX_HTTP_CACHE)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER "\"%s\":{"               \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"                                                           \
    "},"                                                                       \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%uA,"                                                  \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"                                                           \
    "}"                                                                        \
    "},"
#else
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER "\"%s\":{"               \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "},"                                                                       \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%uA,"                                                  \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "}"                                                                        \
    "},"
#endif

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER_S "\"filterZones\":{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER "\"%s\":{"               \
    "%s"                                                                       \
    "},"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S "\"upstreamZones\":{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM "{\"server\":\"%V\","  \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "},"                                                                       \
    "\"responseMsec\":%M,"                                                      \
    "\"weight\":%ui,"                                                          \
    "\"maxFails\":%ui,"                                                        \
    "\"failTimeout\":%T,"                                                      \
    "\"backup\":%s,"                                                           \
    "\"down\":%s,"                                                             \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%uA,"                                                  \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "}"                                                                        \
    "},"

#if (NGX_HTTP_CACHE)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE_S "\"cacheZones\":{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE "\"%s\":{"                \
    "\"maxSize\":%uA,"                                                         \
    "\"usedSize\":%uA,"                                                        \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"                                                           \
    "},"                                                                       \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"                                                           \
    "}"                                                                        \
    "},"
#endif

#define ngx_vhost_traffic_status_add_rc(s, n) {                                \
    if(s < 200) {n->stat_1xx_counter++;}                                       \
    else if(s < 300) {n->stat_2xx_counter++;}                                  \
    else if(s < 400) {n->stat_3xx_counter++;}                                  \
    else if(s < 500) {n->stat_4xx_counter++;}                                  \
    else {n->stat_5xx_counter++;}                                              \
}

#if (NGX_HTTP_CACHE)
#if !defined(nginx_version) || nginx_version < 1005007
#define ngx_vhost_traffic_status_add_cc(s, n) {                                \
    if(s == NGX_HTTP_CACHE_MISS) {n->stat_cache_miss_counter++;}               \
    else if(s == NGX_HTTP_CACHE_BYPASS) {n->stat_cache_bypass_counter++;}      \
    else if(s == NGX_HTTP_CACHE_EXPIRED) {n->stat_cache_expired_counter++;}    \
    else if(s == NGX_HTTP_CACHE_STALE) {n->stat_cache_stale_counter++;}        \
    else if(s == NGX_HTTP_CACHE_UPDATING) {n->stat_cache_updating_counter++;}  \
    else if(s == NGX_HTTP_CACHE_HIT) {n->stat_cache_hit_counter++;}            \
    else if(s == NGX_HTTP_CACHE_SCARCE) {n->stat_cache_scarce_counter++;}      \
}
#else
#define ngx_vhost_traffic_status_add_cc(s, n) {                                \
    if(s == NGX_HTTP_CACHE_MISS) {                                             \
        n->stat_cache_miss_counter++;                                          \
    }                                                                          \
    else if(s == NGX_HTTP_CACHE_BYPASS) {                                      \
        n->stat_cache_bypass_counter++;                                        \
    }                                                                          \
    else if(s == NGX_HTTP_CACHE_EXPIRED) {                                     \
        n->stat_cache_expired_counter++;                                       \
    }                                                                          \
    else if(s == NGX_HTTP_CACHE_STALE) {                                       \
        n->stat_cache_stale_counter++;                                         \
    }                                                                          \
    else if(s == NGX_HTTP_CACHE_UPDATING) {                                    \
        n->stat_cache_updating_counter++;                                      \
    }                                                                          \
    else if(s == NGX_HTTP_CACHE_REVALIDATED) {                                 \
        n->stat_cache_revalidated_counter++;                                   \
    }                                                                          \
    else if(s == NGX_HTTP_CACHE_HIT) {                                         \
        n->stat_cache_hit_counter++;                                           \
    }                                                                          \
    else if(s == NGX_HTTP_CACHE_SCARCE) {                                      \
        n->stat_cache_scarce_counter++;                                        \
    }                                                                          \
}
#endif
#endif

#if (NGX_HTTP_CACHE)
#define ngx_vhost_traffic_status_add_oc(o, c) {                                \
    if (o->stat_request_counter > c->stat_request_counter) {                   \
        c->stat_request_counter_oc++;                                          \
    }                                                                          \
    if (o->stat_in_bytes > c->stat_in_bytes) {                                 \
        c->stat_in_bytes_oc++;                                                 \
    }                                                                          \
    if (o->stat_out_bytes > c->stat_out_bytes) {                               \
        c->stat_out_bytes_oc++;                                                \
    }                                                                          \
    if (o->stat_1xx_counter > c->stat_1xx_counter) {                           \
        c->stat_1xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_2xx_counter > c->stat_2xx_counter) {                           \
        c->stat_2xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_3xx_counter > c->stat_3xx_counter) {                           \
        c->stat_3xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_4xx_counter > c->stat_4xx_counter) {                           \
        c->stat_4xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_5xx_counter > c->stat_5xx_counter) {                           \
        c->stat_5xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_cache_miss_counter > c->stat_cache_miss_counter) {             \
        c->stat_cache_miss_counter_oc++;                                       \
    }                                                                          \
    if (o->stat_cache_bypass_counter > c->stat_cache_bypass_counter) {         \
        c->stat_cache_bypass_counter_oc++;                                     \
    }                                                                          \
    if (o->stat_cache_expired_counter > c->stat_cache_expired_counter) {       \
        c->stat_cache_expired_counter_oc++;                                    \
    }                                                                          \
    if (o->stat_cache_stale_counter > c->stat_cache_stale_counter) {           \
        c->stat_cache_stale_counter_oc++;                                      \
    }                                                                          \
    if (o->stat_cache_updating_counter > c->stat_cache_updating_counter) {     \
        c->stat_cache_updating_counter_oc++;                                   \
    }                                                                          \
    if (o->stat_cache_revalidated_counter > c->stat_cache_revalidated_counter) \
    {                                                                          \
        c->stat_cache_revalidated_counter_oc++;                                \
    }                                                                          \
    if (o->stat_cache_hit_counter > c->stat_cache_hit_counter) {               \
        c->stat_cache_hit_counter_oc++;                                        \
    }                                                                          \
    if (o->stat_cache_scarce_counter > c->stat_cache_scarce_counter) {         \
        c->stat_cache_scarce_counter_oc++;                                     \
    }                                                                          \
}
#else
#define ngx_vhost_traffic_status_add_oc(o, c) {                                \
    if (o->stat_request_counter > c->stat_request_counter) {                   \
        c->stat_request_counter_oc++;                                          \
    }                                                                          \
    if (o->stat_in_bytes > c->stat_in_bytes) {                                 \
        c->stat_in_bytes_oc++;                                                 \
    }                                                                          \
    if (o->stat_out_bytes > c->stat_out_bytes) {                               \
        c->stat_out_bytes_oc++;                                                \
    }                                                                          \
    if (o->stat_1xx_counter > c->stat_1xx_counter) {                           \
        c->stat_1xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_2xx_counter > c->stat_2xx_counter) {                           \
        c->stat_2xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_3xx_counter > c->stat_3xx_counter) {                           \
        c->stat_3xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_4xx_counter > c->stat_4xx_counter) {                           \
        c->stat_4xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_5xx_counter > c->stat_5xx_counter) {                           \
        c->stat_5xx_counter_oc++;                                              \
    }                                                                          \
}
#endif

#define ngx_vhost_traffic_status_max_integer (NGX_ATOMIC_T_LEN < 12)           \
    ? 0xffffffff                                                               \
    : 0xffffffffffffffff

#define ngx_vhost_traffic_status_boolean_to_string(b) (b) ? "true" : "false"


typedef struct {
    ngx_http_complex_value_t     filter_key;
    ngx_http_complex_value_t     filter_name;
} ngx_http_vhost_traffic_status_filter_t;


typedef struct {
    ngx_str_t                    key;
} ngx_http_vhost_traffic_status_filter_key_t;


typedef struct {
    uint32_t                     hash;
    ngx_uint_t                   index;
} ngx_http_vhost_traffic_status_filter_uniq_t;


typedef struct {
    ngx_rbtree_t                *rbtree;
    ngx_array_t                 *filter_keys; /* array of ngx_http_vhost_traffic_status_filter_t */
    ngx_flag_t                   enable;
    ngx_flag_t                   filter_check_duplicate;
    ngx_str_t                    shm_name;
    ssize_t                      shm_size;
} ngx_http_vhost_traffic_status_ctx_t;


typedef struct {
    unsigned                     type;        /* unsigned  type:5; */
    ngx_msec_t                   rtms;
} ngx_http_vhost_traffic_status_node_upstream_t;


typedef struct {
    u_char                                           color;
    ngx_atomic_t                                     stat_request_counter;
    ngx_atomic_t                                     stat_in_bytes;
    ngx_atomic_t                                     stat_out_bytes;
    ngx_atomic_t                                     stat_1xx_counter;
    ngx_atomic_t                                     stat_2xx_counter;
    ngx_atomic_t                                     stat_3xx_counter;
    ngx_atomic_t                                     stat_4xx_counter;
    ngx_atomic_t                                     stat_5xx_counter;

    /* deals with the overflow of variables */
    ngx_atomic_t                                     stat_request_counter_oc;
    ngx_atomic_t                                     stat_in_bytes_oc;
    ngx_atomic_t                                     stat_out_bytes_oc;
    ngx_atomic_t                                     stat_1xx_counter_oc;
    ngx_atomic_t                                     stat_2xx_counter_oc;
    ngx_atomic_t                                     stat_3xx_counter_oc;
    ngx_atomic_t                                     stat_4xx_counter_oc;
    ngx_atomic_t                                     stat_5xx_counter_oc;

#if (NGX_HTTP_CACHE)
    ngx_atomic_t                                     stat_cache_max_size;
    ngx_atomic_t                                     stat_cache_used_size;
    ngx_atomic_t                                     stat_cache_miss_counter;
    ngx_atomic_t                                     stat_cache_bypass_counter;
    ngx_atomic_t                                     stat_cache_expired_counter;
    ngx_atomic_t                                     stat_cache_stale_counter;
    ngx_atomic_t                                     stat_cache_updating_counter;
    ngx_atomic_t                                     stat_cache_revalidated_counter;
    ngx_atomic_t                                     stat_cache_hit_counter;
    ngx_atomic_t                                     stat_cache_scarce_counter;

    /* deals with the overflow of variables */
    ngx_atomic_t                                     stat_cache_miss_counter_oc;
    ngx_atomic_t                                     stat_cache_bypass_counter_oc;
    ngx_atomic_t                                     stat_cache_expired_counter_oc;
    ngx_atomic_t                                     stat_cache_stale_counter_oc;
    ngx_atomic_t                                     stat_cache_updating_counter_oc;
    ngx_atomic_t                                     stat_cache_revalidated_counter_oc;
    ngx_atomic_t                                     stat_cache_hit_counter_oc;
    ngx_atomic_t                                     stat_cache_scarce_counter_oc;
#endif
    ngx_http_vhost_traffic_status_node_upstream_t    stat_upstream;
    u_short                                          len;
    u_char                                           data[1];
} ngx_http_vhost_traffic_status_node_t;


typedef struct {
    ngx_shm_zone_t                                  *shm_zone;
    ngx_flag_t                                       enable;
    ngx_flag_t                                       filter;
    ngx_flag_t                                       filter_host;
    ngx_flag_t                                       filter_check_duplicate;

    /* array of ngx_http_vhost_traffic_status_filter_t */
    ngx_array_t                                     *filter_keys;
    /* array of ngx_http_vhost_traffic_status_filter_key_t */
    ngx_array_t                                     *keys;
    /* array of ngx_http_vhost_traffic_status_filter_node_t */
    ngx_array_t                                     *nodes;

    ngx_str_t                                        shm_name;
    ngx_http_vhost_traffic_status_node_t             stats;
    ngx_msec_t                                       start_msec;
    ngx_str_t                                        display;
    ngx_flag_t                                       format;
    ngx_http_vhost_traffic_status_node_t            *vtsn_server;
    ngx_http_vhost_traffic_status_node_t            *vtsn_upstream;
#if (NGX_HTTP_CACHE)
    ngx_http_vhost_traffic_status_node_t            *vtsn_cache;
#endif
    uint32_t                                         vtsn_hash;
} ngx_http_vhost_traffic_status_loc_conf_t;


typedef struct {
    ngx_http_vhost_traffic_status_node_t  *node;
} ngx_http_vhost_traffic_status_filter_node_t;

#if !defined(nginx_version) || nginx_version < 1007009
uintptr_t ngx_http_vhost_traffic_status_escape_json(u_char *dst, u_char *src, size_t size);
#endif

static ngx_int_t ngx_http_vhost_traffic_status_shm_add_node(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx, ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf,
    ngx_str_t *key, unsigned type);
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_filter_node(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx, ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf,
    ngx_array_t *filter_keys);
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_server(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx, ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_filter(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx, ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_upstream(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx, ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_cache(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx, ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
#endif

static ngx_rbtree_node_t *ngx_http_vhost_traffic_status_node_lookup(ngx_rbtree_t *rbtree,
    ngx_str_t *key, uint32_t hash);
static void ngx_vhost_traffic_status_node_init(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn);
static void ngx_vhost_traffic_status_node_set(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn);

static int ngx_libc_cdecl ngx_http_traffic_status_filter_cmp_hashs(const void *one,
    const void *two);
static int ngx_libc_cdecl ngx_http_traffic_status_filter_cmp_keys(const void *one,
    const void *two);
static ngx_int_t ngx_http_vhost_traffic_status_filter_unique(ngx_pool_t *pool,
    ngx_array_t **keys);
static ngx_int_t ngx_http_vhost_traffic_status_filter_get_keys(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static ngx_int_t ngx_http_vhost_traffic_status_filter_get_nodes(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf, ngx_str_t *name);

static u_char *ngx_http_vhost_traffic_status_display_set_main(const char *fmt,
    u_char *buf, ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static u_char *ngx_http_vhost_traffic_status_display_set_server(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static u_char *ngx_http_vhost_traffic_status_display_set_filter_node(ngx_http_request_t *r,
    const char *fmt, u_char *buf, ngx_http_vhost_traffic_status_loc_conf_t *vtscf,
    ngx_http_vhost_traffic_status_node_t  *vtsn);
static u_char *ngx_http_vhost_traffic_status_display_set_filter(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static u_char *ngx_http_vhost_traffic_status_display_set_upstream_alone(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static u_char *ngx_http_vhost_traffic_status_display_set_upstream_group(ngx_http_request_t *r,
    ngx_rbtree_t *rbtree, const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
#if (NGX_HTTP_CACHE)
static u_char *ngx_http_vhost_traffic_status_display_set_cache(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
#endif
static u_char *ngx_http_vhost_traffic_status_display_set(ngx_http_request_t *r,
    ngx_rbtree_t *rbtree, u_char *buf, ngx_http_vhost_traffic_status_loc_conf_t *vtscf);

static void ngx_http_vhost_traffic_status_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_vhost_traffic_status_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static char *ngx_http_vhost_traffic_status_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_vhost_traffic_status_filter_by_set_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_vhost_traffic_status_display(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_http_vhost_traffic_status_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_vhost_traffic_status_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_vhost_traffic_status_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_vhost_traffic_status_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_vhost_traffic_status_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_vhost_traffic_status_display_format[] = {
    { ngx_string("json"), NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON },
    { ngx_string("html"), NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML },
    { ngx_null_string, 0 }
};


static ngx_command_t ngx_http_vhost_traffic_status_commands[] = {

    { ngx_string("vhost_traffic_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, enable),
      NULL },

    { ngx_string("vhost_traffic_status_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, filter),
      NULL },

    { ngx_string("vhost_traffic_status_filter_by_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, filter_host),
      NULL },

    { ngx_string("vhost_traffic_status_filter_check_duplicate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, filter_check_duplicate),
      NULL },

    { ngx_string("vhost_traffic_status_filter_by_set_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_vhost_traffic_status_filter_by_set_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("vhost_traffic_status_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_vhost_traffic_status_zone,
      0,
      0,
      NULL },

    { ngx_string("vhost_traffic_status_display"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_vhost_traffic_status_display,
      0,
      0,
      NULL },

    { ngx_string("vhost_traffic_status_display_format"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, format),
      &ngx_http_vhost_traffic_status_display_format },

    ngx_null_command
};


static ngx_http_module_t ngx_http_vhost_traffic_status_module_ctx = {
    NULL,                                           /* preconfiguration */
    ngx_http_vhost_traffic_status_init,             /* postconfiguration */

    ngx_http_vhost_traffic_status_create_main_conf, /* create main configuration */
    ngx_http_vhost_traffic_status_init_main_conf,   /* init main configuration */

    NULL,                                           /* create server configuration */
    NULL,                                           /* merge server configuration */

    ngx_http_vhost_traffic_status_create_loc_conf,  /* create location configuration */
    ngx_http_vhost_traffic_status_merge_loc_conf,   /* merge location configuration */
};


ngx_module_t ngx_http_vhost_traffic_status_module = {
    NGX_MODULE_V1,
    &ngx_http_vhost_traffic_status_module_ctx,   /* module context */
    ngx_http_vhost_traffic_status_commands,      /* module directives */
    NGX_HTTP_MODULE,                             /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};


#if !defined(nginx_version) || nginx_version < 1007009

/* from src/core/ngx_string.c in v1.7.9 */
uintptr_t
ngx_http_vhost_traffic_status_escape_json(u_char *dst, u_char *src, size_t size)
{
    u_char      ch;
    ngx_uint_t  len;

    if (dst == NULL) {
        len = 0;

        while (size) {
            ch = *src++;

            if (ch == '\\' || ch == '"') {
                len++;

            } else if (ch <= 0x1f) {
                len += sizeof("\\u001F") - 2;
            }

            size--;
        }

        return (uintptr_t) len;
    }

    while (size) {
        ch = *src++;

        if (ch > 0x1f) {

            if (ch == '\\' || ch == '"') {
                *dst++ = '\\';
            }

            *dst++ = ch;

        } else {
            *dst++ = '\\'; *dst++ = 'u'; *dst++ = '0'; *dst++ = '0';
            *dst++ = '0' + (ch >> 4);

            ch &= 0xf;

            *dst++ = (ch < 10) ? ('0' + ch) : ('A' + ch - 10);
        }

        size--;
    }

    return (uintptr_t) dst;
}

#endif


static ngx_int_t
ngx_http_vhost_traffic_status_handler(ngx_http_request_t *r)
{
    ngx_int_t                                  rc;
    ngx_http_core_srv_conf_t                  *cscf;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (!ctx->enable || !vtscf->enable) {
        return NGX_DECLINED;
    }
    if (vtscf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    rc = ngx_http_vhost_traffic_status_shm_add_server(r, ctx, cscf, vtscf);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_server failed");
    }

    rc = ngx_http_vhost_traffic_status_shm_add_upstream(r, ctx, cscf, vtscf);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_upstream failed");
    }

    rc = ngx_http_vhost_traffic_status_shm_add_filter(r, ctx, cscf, vtscf);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_filter failed");
    }

#if (NGX_HTTP_CACHE)
    rc = ngx_http_vhost_traffic_status_shm_add_cache(r, ctx, cscf, vtscf);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_cache failed");
    }
#endif

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_node(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx,
    ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf,
    ngx_str_t *key, unsigned type)
{
    size_t                                 size;
    uint32_t                               hash;
    ngx_slab_pool_t                       *shpool;
    ngx_rbtree_node_t                     *node;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    if (key->len == 0) {
        return NGX_ERROR;
    }

    if (vtscf->vtsn_server) {
        if (ngx_memn2cmp(key->data, vtscf->vtsn_server->data,
                         key->len, (size_t) vtscf->vtsn_server->len)
                != 0)
        {
            goto again;
        }

        ngx_shmtx_lock(&shpool->mutex);

        ngx_vhost_traffic_status_node_set(r, vtscf->vtsn_server);

        goto done;
    }

again:

    hash = ngx_crc32_short(key->data, key->len);

    ngx_shmtx_lock(&shpool->mutex);

    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, key, hash);
    if (node == NULL) {
        size = offsetof(ngx_rbtree_node_t, color)
               + offsetof(ngx_http_vhost_traffic_status_node_t, data)
               + key->len;

        node = ngx_slab_alloc_locked(shpool, size);
        if (node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        node->key = hash;
        vtsn->len = (u_char) key->len;
        ngx_vhost_traffic_status_node_init(r, vtsn);
        vtsn->stat_upstream.type = type;
        ngx_memcpy(vtsn->data, key->data, key->len);

        ngx_rbtree_insert(ctx->rbtree, node);
    } else {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
        ngx_vhost_traffic_status_node_set(r, vtsn);
    }

    vtscf->vtsn_server = vtsn;

done:

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_filter_node(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx,
    ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf,
    ngx_array_t *filter_keys)
{
    u_char                                  *p;
    unsigned                                 type;
    ngx_int_t                                rc;
    ngx_str_t                                key, filter_key, filter_name;
    ngx_uint_t                               i, n;
    ngx_http_vhost_traffic_status_filter_t  *filters;

    if (filter_keys == NULL) {
        return NGX_OK;
    }

    filters = filter_keys->elts;
    n = filter_keys->nelts;

    for (i = 0; i < n; i++) {
        if (&filters[i].filter_key == NULL || &filters[i].filter_name == NULL) {
            continue;
        }

        if (ngx_http_complex_value(r, &filters[i].filter_key, &filter_key) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &filters[i].filter_name, &filter_name) != NGX_OK) {
            return NGX_ERROR;
        }

        if (filter_key.len == 0) {
            continue;
        }

        if (filter_name.len == 0) {
            key = filter_key;
            type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;
        } else {
            key.len = filter_name.len + sizeof("@") - 1 + filter_key.len;
            key.data = ngx_pnalloc(r->pool, key.len);
            if (key.data == NULL) {
                return NGX_ERROR;
            }

            type = filter_name.len
                   ? NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG
                   : NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

            p = key.data;

            p = ngx_cpymem(p, filter_name.data, filter_name.len);
            *p++ = '@';
            p = ngx_cpymem(p, filter_key.data, filter_key.len);

        }

        rc = ngx_http_vhost_traffic_status_shm_add_node(r, ctx, cscf, vtscf, &key, type);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter_node(\"%V\") failed", &key);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_server(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx,
    ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    ngx_str_t  key;

    if (vtscf->filter && vtscf->filter_host && r->headers_in.server.len) {
        /* set the key by host header */
        key = r->headers_in.server;
    } else {
        /* set the key by server_name variable */
        key = cscf->server_name;
        if (key.len == 0) {
            key.len = 1;
            key.data = (u_char *) "_";
        }
    }

    return ngx_http_vhost_traffic_status_shm_add_node(
               r, ctx, cscf, vtscf, &key,
               NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO);
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_filter(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx,
    ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    ngx_int_t  rc;

    if (!vtscf->filter) {
        return NGX_OK;
    }

    if (ctx->filter_keys != NULL) {
        rc = ngx_http_vhost_traffic_status_shm_add_filter_node(
                 r, ctx, cscf, vtscf, ctx->filter_keys);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter(\"http\") failed");
        }
    }

    if (vtscf->filter_keys != NULL) {
        rc = ngx_http_vhost_traffic_status_shm_add_filter_node(
                 r, ctx, cscf, vtscf, vtscf->filter_keys);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter(\"server\") failed");
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_upstream(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx,
    ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    u_char                                *p;
    size_t                                 size;
    uint32_t                               hash;
    ngx_str_t                             *host, key;
    ngx_uint_t                             i;
    ngx_msec_int_t                         ms;
    ngx_slab_pool_t                       *shpool;
    ngx_rbtree_node_t                     *node;
    ngx_http_upstream_t                   *u;
    ngx_http_upstream_state_t             *state;
    ngx_http_upstream_srv_conf_t          *uscf, **uscfp;
    ngx_http_upstream_main_conf_t         *umcf;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        return NGX_OK;
    }

    u = r->upstream;

    if (u->resolved == NULL) {
        uscf = u->conf->upstream;
    } else {
        host = &u->resolved->host;

        umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        return NGX_ERROR;
    }

found:

    state = r->upstream_states->elts;

    i = 0;
    ms = 0;
    for ( ;; ) {
        if (state[i].status) {
#if !defined(nginx_version) || nginx_version < 1009001
            ms += (ngx_msec_int_t)
                  (state[i].response_sec * 1000 + state[i].response_msec);
#else
            ms += state[i].response_time;
#endif
        }
        if (++i == r->upstream_states->nelts) {
            break;
        }
    }
    ms = ngx_max(ms, 0);

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    key.len = (uscf->port ? 0 : uscf->host.len) + sizeof("@") - 1 + state[0].peer->len;
    key.data = ngx_pnalloc(r->pool, key.len);
    if (key.data == NULL) {
        return NGX_ERROR;
    }

    p = key.data;
    if (uscf->port) {
        *p++ = '@';
        p = ngx_cpymem(p, state[0].peer->data, state[0].peer->len);
    } else {
        p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
        *p++ = '@';
        p = ngx_cpymem(p, state[0].peer->data, state[0].peer->len);
    }

    hash = ngx_crc32_short(key.data, key.len);

    if (vtscf->vtsn_upstream && vtscf->vtsn_hash == hash) {
        ngx_shmtx_lock(&shpool->mutex);

        ngx_vhost_traffic_status_node_set(r, vtscf->vtsn_upstream);

        vtscf->vtsn_upstream->stat_upstream.rtms = (ngx_msec_t)
                         (vtscf->vtsn_upstream->stat_upstream.rtms + ms) / 2
                         + (vtscf->vtsn_upstream->stat_upstream.rtms + ms) % 2;

        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;
    }

    ngx_shmtx_lock(&shpool->mutex);

    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);
    if (node == NULL) {
        size = offsetof(ngx_rbtree_node_t, color)
               + offsetof(ngx_http_vhost_traffic_status_node_t, data)
               + key.len;

        node = ngx_slab_alloc_locked(shpool, size);
        if (node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        node->key = hash;
        vtsn->len = (u_char) key.len;
        ngx_vhost_traffic_status_node_init(r, vtsn);
        vtsn->stat_upstream.rtms = ms;
        vtsn->stat_upstream.type = uscf->port
                                   ? NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA
                                   : NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;
        ngx_memcpy(vtsn->data, key.data, key.len);

        ngx_rbtree_insert(ctx->rbtree, node);
    } else {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        ngx_vhost_traffic_status_node_set(r, vtsn);

        vtsn->stat_upstream.rtms = (ngx_msec_t)
                                   (vtsn->stat_upstream.rtms + ms) / 2
                                   + (vtsn->stat_upstream.rtms + ms) % 2;
    }

    vtscf->vtsn_upstream = vtsn;
    vtscf->vtsn_hash = hash;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_cache(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_ctx_t *ctx,
    ngx_http_core_srv_conf_t *cscf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    size_t                                 size;
    uint32_t                               hash;
    ngx_str_t                              key;
    ngx_slab_pool_t                       *shpool;
    ngx_http_cache_t                      *c;
    ngx_rbtree_node_t                     *node;
    ngx_http_upstream_t                   *u;
    ngx_http_file_cache_t                 *cache;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    u = r->upstream;

    if (u != NULL && u->cache_status != 0 && r->cache != NULL) {
        c = r->cache;
        cache = c->file_cache;
    } else {
        return NGX_OK;
    }

    if (vtscf->vtsn_cache) {
        ngx_shmtx_lock(&shpool->mutex);

        ngx_vhost_traffic_status_node_set(r, vtscf->vtsn_cache);

        ngx_shmtx_lock(&cache->shpool->mutex);

        vtscf->vtsn_cache->stat_cache_used_size = (ngx_atomic_uint_t)
                                                  (cache->sh->size * cache->bsize);

        ngx_shmtx_unlock(&cache->shpool->mutex);

        ngx_shmtx_unlock(&shpool->mutex);

        return NGX_OK;
    }

    key = cache->shm_zone->shm.name;
    if (key.len == 0) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&shpool->mutex);

    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);
    if (node == NULL) {
        size = offsetof(ngx_rbtree_node_t, color)
               + offsetof(ngx_http_vhost_traffic_status_node_t, data)
               + key.len;

        node = ngx_slab_alloc_locked(shpool, size);
        if (node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        node->key = hash;
        vtsn->len = (u_char) key.len;
        ngx_vhost_traffic_status_node_init(r, vtsn);
        vtsn->stat_upstream.type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC;
        vtsn->stat_cache_max_size = (ngx_atomic_uint_t) (cache->max_size * cache->bsize);
        ngx_memcpy(vtsn->data, key.data, key.len);

        ngx_rbtree_insert(ctx->rbtree, node);
    } else {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        ngx_vhost_traffic_status_node_set(r, vtsn);

        ngx_shmtx_lock(&cache->shpool->mutex);

        vtsn->stat_cache_used_size = (ngx_atomic_uint_t) (cache->sh->size * cache->bsize);

        ngx_shmtx_unlock(&cache->shpool->mutex);
    }

    vtscf->vtsn_cache = vtsn;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_vhost_traffic_status_display_handler(ngx_http_request_t *r)
{
    size_t                                     size, len;
    u_char                                    *o, *s;
    ngx_str_t                                  uri, type;
    ngx_int_t                                  format, rc;
    ngx_buf_t                                 *b;
    ngx_chain_t                                out;
    ngx_slab_pool_t                           *shpool;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (!ctx->enable) {
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    uri = r->uri;

    format = NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_NONE;

    if (uri.len == 1) {
        if (ngx_strncmp(uri.data, "/", 1) == 0) {
            uri.len = 0;
        }
    }

    o = (u_char *) r->uri.data;
    s = o;

    len = r->uri.len;

    while(sizeof("/format/type") - 1 <= len) {
        if (ngx_strncasecmp(s, (u_char *) "/format/", sizeof("/format/") - 1) == 0) {
            uri.data = o;
            uri.len = (o == s) ? 0 : (size_t) (s - o);

            s += sizeof("/format/") - 1;

            if (ngx_strncasecmp(s, (u_char *) "json", sizeof("json") - 1) == 0) {
                format = NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON;
            } else if (ngx_strncasecmp(s, (u_char *) "html", sizeof("html") - 1) == 0) {
                format = NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML;
            } else {
                s -= 2;
            }

            if (format != NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_NONE) {
                break;
            }
        }

        if ((s = (u_char *) ngx_strchr(++s, '/')) == NULL) {
            break;
        }

        if (r->uri.len <= (size_t) (s - o)) {
            break;
        }

        len = r->uri.len - (size_t) (s - o);
    }

    format = (format == NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_NONE) ? vtscf->format : format;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    if (format == NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON) {
        size = ctx->shm_size;
        ngx_str_set(&type, "application/json");
    } else {
        size = sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_HTML_DATA) + ngx_pagesize ;
        ngx_str_set(&type, "text/html");
    }

    r->headers_out.content_type_len = type.len;
    r->headers_out.content_type = type;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (format == NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON) {
        shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;
        ngx_shmtx_lock(&shpool->mutex);
        b->last = ngx_http_vhost_traffic_status_display_set(r, ctx->rbtree, b->last, vtscf);
        ngx_shmtx_unlock(&shpool->mutex);

        if (b->last == b->pos) {
            b->last = ngx_sprintf(b->last, "{}");
        }
    } else {
        b->last = ngx_sprintf(b->last, NGX_HTTP_VHOST_TRAFFIC_STATUS_HTML_DATA, &uri);
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0; /* if subrequest 0 else 1 */
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static ngx_rbtree_node_t *
ngx_http_vhost_traffic_status_node_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key,
    uint32_t hash)
{
    ngx_int_t                              rc;
    ngx_rbtree_node_t                     *node, *sentinel;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, vtsn->data, key->len, (size_t) vtsn->len);
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void ngx_vhost_traffic_status_node_init(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_uint_t status = r->headers_out.status;

    vtsn->stat_upstream.type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;
    vtsn->stat_request_counter = 1;
    vtsn->stat_in_bytes = (ngx_atomic_uint_t) r->request_length;
    vtsn->stat_out_bytes = (ngx_atomic_uint_t) r->connection->sent;
    vtsn->stat_1xx_counter = 0;
    vtsn->stat_2xx_counter = 0;
    vtsn->stat_3xx_counter = 0;
    vtsn->stat_4xx_counter = 0;
    vtsn->stat_5xx_counter = 0;

    vtsn->stat_request_counter_oc = 0;
    vtsn->stat_in_bytes_oc = 0;
    vtsn->stat_out_bytes_oc = 0;
    vtsn->stat_1xx_counter_oc = 0;
    vtsn->stat_2xx_counter_oc = 0;
    vtsn->stat_3xx_counter_oc = 0;
    vtsn->stat_4xx_counter_oc = 0;
    vtsn->stat_5xx_counter_oc = 0;

    ngx_vhost_traffic_status_add_rc(status, vtsn);
#if (NGX_HTTP_CACHE)
    vtsn->stat_cache_miss_counter = 0;
    vtsn->stat_cache_bypass_counter = 0;
    vtsn->stat_cache_expired_counter = 0;
    vtsn->stat_cache_stale_counter = 0;
    vtsn->stat_cache_updating_counter = 0;
    vtsn->stat_cache_revalidated_counter = 0;
    vtsn->stat_cache_hit_counter = 0;
    vtsn->stat_cache_scarce_counter = 0;

    vtsn->stat_cache_miss_counter_oc = 0;
    vtsn->stat_cache_bypass_counter_oc = 0;
    vtsn->stat_cache_expired_counter_oc = 0;
    vtsn->stat_cache_stale_counter_oc = 0;
    vtsn->stat_cache_updating_counter_oc = 0;
    vtsn->stat_cache_revalidated_counter_oc = 0;
    vtsn->stat_cache_hit_counter_oc = 0;
    vtsn->stat_cache_scarce_counter_oc = 0;

    if (r->upstream != NULL && r->upstream->cache_status != 0) {
        ngx_vhost_traffic_status_add_cc(r->upstream->cache_status, vtsn);
    }
#endif
}


static void ngx_vhost_traffic_status_node_set(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_uint_t                            status;
    ngx_http_vhost_traffic_status_node_t  ovtsn;

    status = r->headers_out.status;
    ovtsn = *vtsn;

    vtsn->stat_request_counter++;
    vtsn->stat_in_bytes += (ngx_atomic_uint_t) r->request_length;
    vtsn->stat_out_bytes += (ngx_atomic_uint_t) r->connection->sent;

    ngx_vhost_traffic_status_add_rc(status, vtsn);
#if (NGX_HTTP_CACHE)
    if (r->upstream != NULL && r->upstream->cache_status != 0) {
        ngx_vhost_traffic_status_add_cc(r->upstream->cache_status, vtsn);
    }
#endif
    ngx_vhost_traffic_status_add_oc((&ovtsn), vtsn);
}


static int ngx_libc_cdecl
ngx_http_traffic_status_filter_cmp_hashs(const void *one, const void *two)
{
    ngx_http_vhost_traffic_status_filter_uniq_t *first =
                           (ngx_http_vhost_traffic_status_filter_uniq_t *) one;
    ngx_http_vhost_traffic_status_filter_uniq_t *second =
                           (ngx_http_vhost_traffic_status_filter_uniq_t *) two;

    return (first->hash - second->hash);
}


static int ngx_libc_cdecl
ngx_http_traffic_status_filter_cmp_keys(const void *one, const void *two)
{
    ngx_http_vhost_traffic_status_filter_key_t *first =
                            (ngx_http_vhost_traffic_status_filter_key_t *) one;
    ngx_http_vhost_traffic_status_filter_key_t *second =
                            (ngx_http_vhost_traffic_status_filter_key_t *) two;

    return (int) ngx_strcmp(first->key.data, second->key.data);
}


static ngx_int_t
ngx_http_vhost_traffic_status_filter_unique(ngx_pool_t *pool, ngx_array_t **keys)
{
    uint32_t                                      hash;
    u_char                                       *p;
    ngx_str_t                                     key;
    ngx_uint_t                                    i, n;
    ngx_array_t                                  *uniqs, *filter_keys;
    ngx_http_vhost_traffic_status_filter_t       *filter, *filters;
    ngx_http_vhost_traffic_status_filter_uniq_t  *filter_uniqs;

    if (*keys == NULL) {
        return NGX_OK;
    }

    uniqs = ngx_array_create(pool, 1,
                             sizeof(ngx_http_vhost_traffic_status_filter_uniq_t));
    if (uniqs == NULL) {
        return NGX_ERROR;
    }

    /* init array */
    filter_keys = NULL;
    filter_uniqs = NULL;

    filters = (*keys)->elts;
    n = (*keys)->nelts;

    for (i = 0; i < n; i++) {
        key.len = filters[i].filter_key.value.len
                  + filters[i].filter_name.value.len;
        key.data = ngx_pcalloc(pool, key.len);
        if (key.data == NULL) {
            return NGX_ERROR;
        }

        p = key.data;
        p = ngx_cpymem(p, filters[i].filter_key.value.data,
                       filters[i].filter_key.value.len);
        ngx_memcpy(p, filters[i].filter_name.value.data,
                   filters[i].filter_name.value.len);
        hash = ngx_crc32_short(key.data, key.len);

        filter_uniqs = ngx_array_push(uniqs);
        if (filter_uniqs == NULL) {
            return NGX_ERROR;
        }

        filter_uniqs->hash = hash;
        filter_uniqs->index = i;

        if (p != NULL) {
            ngx_pfree(pool, key.data);
        }
    }

    filter_uniqs = uniqs->elts;
    n = uniqs->nelts;

    ngx_qsort(filter_uniqs, (size_t) n,
              sizeof(ngx_http_vhost_traffic_status_filter_uniq_t),
              ngx_http_traffic_status_filter_cmp_hashs);

    hash = 0;
    for (i = 0; i < n; i++) {
        if (filter_uniqs[i].hash == hash) {
            continue;
        }

        hash = filter_uniqs[i].hash;

        if (filter_keys == NULL) {
            filter_keys = ngx_array_create(pool, 1,
                                           sizeof(ngx_http_vhost_traffic_status_filter_t));
            if (filter_keys == NULL) {
                return NGX_ERROR;
            }
        }

        filter = ngx_array_push(filter_keys);
        if (filter == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(filter, &filters[filter_uniqs[i].index],
                   sizeof(ngx_http_vhost_traffic_status_filter_t));

    }

    if ((*keys)->nelts != filter_keys->nelts) {
        *keys = filter_keys;
    } else {
        ngx_array_destroy(filter_keys);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_filter_get_keys(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    u_char                                      *p;
    ngx_int_t                                    rc;
    ngx_str_t                                    key;
    ngx_http_vhost_traffic_status_node_t        *vtsn;
    ngx_http_vhost_traffic_status_filter_key_t  *keys;

    if (node != sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            key.data = vtsn->data;

            p = (u_char *) ngx_strchr(vtsn->data, '@');
            if (p == NULL) {
                goto next;
            }

            key.len = p - vtsn->data;

            if (vtscf->keys == NULL) {
                vtscf->keys = ngx_array_create(r->pool, 1,
                                  sizeof(ngx_http_vhost_traffic_status_filter_key_t));

                if (vtscf->keys == NULL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "filter_get_keys::ngx_array_create() failed");
                    return NGX_ERROR;
                }
            }

            keys = ngx_array_push(vtscf->keys);
            if (keys == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "filter_get_keys::ngx_array_push() failed");
                return NGX_ERROR;
            }

            keys->key.len = key.len;
            /* 1 byte for terminating '\0' for ngx_strcmp() */
            keys->key.data = ngx_pnalloc(r->pool, key.len + 1);
            if (keys->key.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "filter_get_keys::ngx_pcalloc() failed");
            }

            ngx_memcpy(keys->key.data, key.data, key.len);
        }
next:
        rc = ngx_http_vhost_traffic_status_filter_get_keys(r, node->left, sentinel, vtscf);
        rc = ngx_http_vhost_traffic_status_filter_get_keys(r, node->right, sentinel, vtscf);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_filter_get_nodes(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf,
    ngx_str_t *name)
{
    u_char                                       *p;
    ngx_int_t                                     rc;
    ngx_str_t                                     key;
    ngx_http_vhost_traffic_status_node_t         *vtsn;
    ngx_http_vhost_traffic_status_filter_node_t  *nodes;

    if (node != sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            key.data = vtsn->data;

            p = (u_char *) ngx_strchr(vtsn->data, '@');
            if (p == NULL) {
                goto next;
            }

            key.len = p - vtsn->data;
            if (name->len != key.len) {
                goto next;
            }

            if (ngx_strncmp(name->data, key.data, key.len) != 0) {
                goto next;
            }

            if (vtscf->nodes == NULL) {
                vtscf->nodes = ngx_array_create(r->pool, 1,
                                   sizeof(ngx_http_vhost_traffic_status_filter_node_t));

                if (vtscf->nodes == NULL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "filter_get_nodes::ngx_array_create() failed");
                    return NGX_ERROR;
                }
            }

            nodes = ngx_array_push(vtscf->nodes);
            if (nodes == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "filter_get_nodes::ngx_array_push() failed");
                return NGX_ERROR;
            }

            nodes->node = vtsn;
        }
next:
        rc = ngx_http_vhost_traffic_status_filter_get_nodes(r, node->left, sentinel, vtscf, name);
        rc = ngx_http_vhost_traffic_status_filter_get_nodes(r, node->right, sentinel, vtscf, name);
    }

    return NGX_OK;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_main(const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    ngx_time_t        *tp;
    ngx_msec_t         now;
    ngx_atomic_int_t   ap, hn, ac, rq, rd, wr, wa;

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;
    wa = *ngx_stat_waiting;

    buf = ngx_sprintf(buf, fmt, NGINX_VERSION, vtscf->start_msec, now, ac, rd, wr, wa, ap, hn, rq);

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_server(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    u_char                                *p;
    ngx_str_t                              key;
    ngx_http_vhost_traffic_status_node_t  *vtsn, ovtsn;

    if (node != sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO) {
            key.len = vtsn->len * 6;
            key.data = ngx_pcalloc(r->pool, key.len);
            if (key.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_set_server::ngx_pcalloc() failed");
                key.len = vtsn->len;
                key.data = vtsn->data;
                p = NULL;
                goto just_start;
            }
            p = key.data;

#if !defined(nginx_version) || nginx_version < 1007009
            p = (u_char *) ngx_http_vhost_traffic_status_escape_json(p, vtsn->data, vtsn->len);
#else
            p = (u_char *) ngx_escape_json(p, vtsn->data, vtsn->len);
#endif

just_start:

            ovtsn = vtscf->stats;

#if (NGX_HTTP_CACHE)
            buf = ngx_sprintf(buf, fmt,
                              key.data, vtsn->stat_request_counter,
                              vtsn->stat_in_bytes,
                              vtsn->stat_out_bytes,
                              vtsn->stat_1xx_counter,
                              vtsn->stat_2xx_counter,
                              vtsn->stat_3xx_counter,
                              vtsn->stat_4xx_counter,
                              vtsn->stat_5xx_counter,
                              vtsn->stat_cache_miss_counter,
                              vtsn->stat_cache_bypass_counter,
                              vtsn->stat_cache_expired_counter,
                              vtsn->stat_cache_stale_counter,
                              vtsn->stat_cache_updating_counter,
                              vtsn->stat_cache_revalidated_counter,
                              vtsn->stat_cache_hit_counter,
                              vtsn->stat_cache_scarce_counter,
                              ngx_vhost_traffic_status_max_integer,
                              vtsn->stat_request_counter_oc,
                              vtsn->stat_in_bytes_oc,
                              vtsn->stat_out_bytes_oc,
                              vtsn->stat_1xx_counter_oc,
                              vtsn->stat_2xx_counter_oc,
                              vtsn->stat_3xx_counter_oc,
                              vtsn->stat_4xx_counter_oc,
                              vtsn->stat_5xx_counter_oc,
                              vtsn->stat_cache_miss_counter_oc,
                              vtsn->stat_cache_bypass_counter_oc,
                              vtsn->stat_cache_expired_counter_oc,
                              vtsn->stat_cache_stale_counter_oc,
                              vtsn->stat_cache_updating_counter_oc,
                              vtsn->stat_cache_revalidated_counter_oc,
                              vtsn->stat_cache_hit_counter_oc,
                              vtsn->stat_cache_scarce_counter_oc);
#else
            buf = ngx_sprintf(buf, fmt,
                              key.data, vtsn->stat_request_counter,
                              vtsn->stat_in_bytes,
                              vtsn->stat_out_bytes,
                              vtsn->stat_1xx_counter,
                              vtsn->stat_2xx_counter,
                              vtsn->stat_3xx_counter,
                              vtsn->stat_4xx_counter,
                              vtsn->stat_5xx_counter,
                              ngx_vhost_traffic_status_max_integer,
                              vtsn->stat_request_counter_oc,
                              vtsn->stat_in_bytes_oc,
                              vtsn->stat_out_bytes_oc,
                              vtsn->stat_1xx_counter_oc,
                              vtsn->stat_2xx_counter_oc,
                              vtsn->stat_3xx_counter_oc,
                              vtsn->stat_4xx_counter_oc,
                              vtsn->stat_5xx_counter_oc);
#endif
            /* calculates the sum */
            vtscf->stats.stat_request_counter +=vtsn->stat_request_counter;
            vtscf->stats.stat_in_bytes += vtsn->stat_in_bytes;
            vtscf->stats.stat_out_bytes += vtsn->stat_out_bytes;
            vtscf->stats.stat_1xx_counter += vtsn->stat_1xx_counter;
            vtscf->stats.stat_2xx_counter += vtsn->stat_2xx_counter;
            vtscf->stats.stat_3xx_counter += vtsn->stat_3xx_counter;
            vtscf->stats.stat_4xx_counter += vtsn->stat_4xx_counter;
            vtscf->stats.stat_5xx_counter += vtsn->stat_5xx_counter;

            vtscf->stats.stat_request_counter_oc += vtsn->stat_request_counter_oc;
            vtscf->stats.stat_in_bytes_oc += vtsn->stat_in_bytes_oc;
            vtscf->stats.stat_out_bytes_oc += vtsn->stat_out_bytes_oc;
            vtscf->stats.stat_1xx_counter_oc += vtsn->stat_1xx_counter_oc;
            vtscf->stats.stat_2xx_counter_oc += vtsn->stat_2xx_counter_oc;
            vtscf->stats.stat_3xx_counter_oc += vtsn->stat_3xx_counter_oc;
            vtscf->stats.stat_4xx_counter_oc += vtsn->stat_4xx_counter_oc;
            vtscf->stats.stat_5xx_counter_oc += vtsn->stat_5xx_counter_oc;

#if (NGX_HTTP_CACHE)
            vtscf->stats.stat_cache_miss_counter +=
                                       vtsn->stat_cache_miss_counter;
            vtscf->stats.stat_cache_bypass_counter +=
                                       vtsn->stat_cache_bypass_counter;
            vtscf->stats.stat_cache_expired_counter +=
                                       vtsn->stat_cache_expired_counter;
            vtscf->stats.stat_cache_stale_counter +=
                                       vtsn->stat_cache_stale_counter;
            vtscf->stats.stat_cache_updating_counter +=
                                       vtsn->stat_cache_updating_counter;
            vtscf->stats.stat_cache_revalidated_counter +=
                                       vtsn->stat_cache_revalidated_counter;
            vtscf->stats.stat_cache_hit_counter +=
                                       vtsn->stat_cache_hit_counter;
            vtscf->stats.stat_cache_scarce_counter +=
                                       vtsn->stat_cache_scarce_counter;

            vtscf->stats.stat_cache_miss_counter_oc +=
                                       vtsn->stat_cache_miss_counter_oc;
            vtscf->stats.stat_cache_bypass_counter_oc +=
                                       vtsn->stat_cache_bypass_counter_oc;
            vtscf->stats.stat_cache_expired_counter_oc +=
                                       vtsn->stat_cache_expired_counter_oc;
            vtscf->stats.stat_cache_stale_counter_oc +=
                                       vtsn->stat_cache_stale_counter_oc;
            vtscf->stats.stat_cache_updating_counter_oc +=
                                       vtsn->stat_cache_updating_counter_oc;
            vtscf->stats.stat_cache_revalidated_counter_oc +=
                                       vtsn->stat_cache_revalidated_counter_oc;
            vtscf->stats.stat_cache_hit_counter_oc +=
                                       vtsn->stat_cache_hit_counter_oc;
            vtscf->stats.stat_cache_scarce_counter_oc +=
                                       vtsn->stat_cache_scarce_counter_oc;
#endif
            ngx_vhost_traffic_status_add_oc((&ovtsn), (&vtscf->stats));

            if (p != NULL) {
                ngx_pfree(r->pool, key.data);
            }
        }

        buf = ngx_http_vhost_traffic_status_display_set_server(
                  r, node->left, sentinel, fmt, buf, vtscf);
        buf = ngx_http_vhost_traffic_status_display_set_server(
                  r, node->right, sentinel, fmt, buf, vtscf);
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_filter_node(ngx_http_request_t *r,
    const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf,
    ngx_http_vhost_traffic_status_node_t  *vtsn)
{
    u_char     *p;
    ngx_str_t   key;

    key.len = vtsn->len * 6;
    key.data = ngx_pcalloc(r->pool, key.len);
    if (key.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_set_filter_node::ngx_pcalloc() failed");
        key.len = vtsn->len;
        key.data = vtsn->data;
        p = NULL;
        goto just_start;
    }

    p = key.data;

#if !defined(nginx_version) || nginx_version < 1007009
    p = (u_char *) ngx_http_vhost_traffic_status_escape_json(p, vtsn->data, vtsn->len);
#else
    p = (u_char *) ngx_escape_json(p, vtsn->data, vtsn->len);
#endif

just_start:

    key.data = vtsn->data;
    p = (u_char *) ngx_strchr(key.data, '@');

    if (p != NULL) {
        key.len =  ngx_strlen(vtsn->data) - (p - vtsn->data) - 1;
        key.data = p + 1;
    }

#if (NGX_HTTP_CACHE)
    buf = ngx_sprintf(buf, fmt,
                      key.data, vtsn->stat_request_counter,
                      vtsn->stat_in_bytes,
                      vtsn->stat_out_bytes,
                      vtsn->stat_1xx_counter,
                      vtsn->stat_2xx_counter,
                      vtsn->stat_3xx_counter,
                      vtsn->stat_4xx_counter,
                      vtsn->stat_5xx_counter,
                      vtsn->stat_cache_miss_counter,
                      vtsn->stat_cache_bypass_counter,
                      vtsn->stat_cache_expired_counter,
                      vtsn->stat_cache_stale_counter,
                      vtsn->stat_cache_updating_counter,
                      vtsn->stat_cache_revalidated_counter,
                      vtsn->stat_cache_hit_counter,
                      vtsn->stat_cache_scarce_counter,
                      ngx_vhost_traffic_status_max_integer,
                      vtsn->stat_request_counter_oc,
                      vtsn->stat_in_bytes_oc,
                      vtsn->stat_out_bytes_oc,
                      vtsn->stat_1xx_counter_oc,
                      vtsn->stat_2xx_counter_oc,
                      vtsn->stat_3xx_counter_oc,
                      vtsn->stat_4xx_counter_oc,
                      vtsn->stat_5xx_counter_oc,
                      vtsn->stat_cache_miss_counter_oc,
                      vtsn->stat_cache_bypass_counter_oc,
                      vtsn->stat_cache_expired_counter_oc,
                      vtsn->stat_cache_stale_counter_oc,
                      vtsn->stat_cache_updating_counter_oc,
                      vtsn->stat_cache_revalidated_counter_oc,
                      vtsn->stat_cache_hit_counter_oc,
                      vtsn->stat_cache_scarce_counter_oc);
#else
    buf = ngx_sprintf(buf, fmt,
                      key.data, vtsn->stat_request_counter,
                      vtsn->stat_in_bytes,
                      vtsn->stat_out_bytes,
                      vtsn->stat_1xx_counter,
                      vtsn->stat_2xx_counter,
                      vtsn->stat_3xx_counter,
                      vtsn->stat_4xx_counter,
                      vtsn->stat_5xx_counter,
                      ngx_vhost_traffic_status_max_integer,
                      vtsn->stat_request_counter_oc,
                      vtsn->stat_in_bytes_oc,
                      vtsn->stat_out_bytes_oc,
                      vtsn->stat_1xx_counter_oc,
                      vtsn->stat_2xx_counter_oc,
                      vtsn->stat_3xx_counter_oc,
                      vtsn->stat_4xx_counter_oc,
                      vtsn->stat_5xx_counter_oc);
#endif

    if (p != NULL) {
        ngx_pfree(r->pool, key.data);
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_filter(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    ngx_str_t                                     key, node_key;
    ngx_uint_t                                    i, j, n, rc;
    ngx_http_vhost_traffic_status_filter_key_t   *keys;
    ngx_http_vhost_traffic_status_filter_node_t  *nodes;

    /* init array */
    vtscf->keys = NULL;
    vtscf->nodes = NULL;

    rc = ngx_http_vhost_traffic_status_filter_get_keys(r, node, sentinel, vtscf);

    if (vtscf->keys != NULL && rc == NGX_OK) {
        keys = vtscf->keys->elts;
        n = vtscf->keys->nelts;

        if (n > 1) {
            ngx_qsort(keys, (size_t) n,
                      sizeof(ngx_http_vhost_traffic_status_filter_key_t),
                      ngx_http_traffic_status_filter_cmp_keys);
        }

        key.len = 0;
        for (i = 0; i < n; i++) {
            if (keys[i].key.len == key.len) {
                if (ngx_strncmp(keys[i].key.data, key.data, key.len) == 0) {
                    continue;
                }
            }
            key = keys[i].key;

            rc = ngx_http_vhost_traffic_status_filter_get_nodes(r, node, sentinel, vtscf, &key);
            if (vtscf->nodes != NULL && rc == NGX_OK) {
                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_S,
                                  &keys[i].key);

                nodes = vtscf->nodes->elts;
                for (j = 0; j < vtscf->nodes->nelts; j++) {
                    node_key.len = nodes[j].node->len;
                    node_key.data = nodes[j].node->data;
                    buf = ngx_http_vhost_traffic_status_display_set_filter_node(r,
                              NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER, buf,
                              vtscf, nodes[j].node);
                }

                buf--;
                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_E);
                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);

                /* destory array to prevent duplication */
                ngx_array_destroy(vtscf->nodes);
                vtscf->nodes = NULL;
            }

        }

        /* destory array */
        for (i = 0; i < n; i++) {
             if (keys[i].key.data != NULL) {
                 ngx_pfree(r->pool, keys[i].key.data);
             }
        }
        ngx_array_destroy(vtscf->keys);
        vtscf->keys = NULL;
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_upstream_alone(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    ngx_str_t                              key;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    if (node != sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA) {
            key.len = vtsn->len - 1;
            key.data = vtsn->data + 1;
            buf = ngx_sprintf(buf, fmt,
                              &key, vtsn->stat_request_counter,
                              vtsn->stat_in_bytes, vtsn->stat_out_bytes,
                              vtsn->stat_1xx_counter, vtsn->stat_2xx_counter,
                              vtsn->stat_3xx_counter, vtsn->stat_4xx_counter,
                              vtsn->stat_5xx_counter, vtsn->stat_upstream.rtms,
                              (ngx_uint_t) 0, (ngx_uint_t) 0,
                              (time_t) 0, ngx_vhost_traffic_status_boolean_to_string(0),
                              ngx_vhost_traffic_status_boolean_to_string(0),
                              ngx_vhost_traffic_status_max_integer,
                              vtsn->stat_request_counter_oc, vtsn->stat_in_bytes_oc,
                              vtsn->stat_out_bytes_oc, vtsn->stat_1xx_counter_oc,
                              vtsn->stat_2xx_counter_oc, vtsn->stat_3xx_counter_oc,
                              vtsn->stat_4xx_counter_oc, vtsn->stat_5xx_counter_oc);
        }

        buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(
                  r, node->left, sentinel, fmt,  buf, vtscf);
        buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(
                  r, node->right, sentinel, fmt, buf, vtscf);
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_upstream_group(ngx_http_request_t *r,
    ngx_rbtree_t *rbtree, const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    size_t                                 len;
    u_char                                *p, *o, *s;
    uint32_t                               hash;
    ngx_str_t                              key;
    ngx_uint_t                             i, j;
    ngx_rbtree_node_t                     *node;
    ngx_http_upstream_server_t            *us;
    ngx_http_upstream_srv_conf_t          *uscf, **uscfp;
    ngx_http_upstream_main_conf_t         *umcf;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    len = 0;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];
        len = ngx_max(uscf->host.len, len);
    }

    key.len = len + sizeof("@[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535") - 1;
    key.data = ngx_pnalloc(r->pool, key.len);
    if (key.data == NULL) {
        return buf;
    }

    p = key.data;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        /* groups */
        if (uscf->servers && !uscf->port) {
            us = uscf->servers->elts;

            o = buf;

            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S,
                              &uscf->host);
            s = buf;

            for (j = 0; j < uscf->servers->nelts; j++) {

                p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
                *p++ = '@';
                p = ngx_cpymem(p, us[j].addrs->name.data, us[j].addrs->name.len);
                key.len = uscf->host.len + sizeof("@") - 1 + us[j].addrs->name.len;
                hash = ngx_crc32_short(key.data, key.len);
                node = ngx_http_vhost_traffic_status_node_lookup(rbtree, &key, hash);

                if (node != NULL) {
                    vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
                    buf = ngx_sprintf(buf, fmt,
                                      &us[j].addrs->name, vtsn->stat_request_counter,
                                      vtsn->stat_in_bytes, vtsn->stat_out_bytes,
                                      vtsn->stat_1xx_counter, vtsn->stat_2xx_counter,
                                      vtsn->stat_3xx_counter, vtsn->stat_4xx_counter,
                                      vtsn->stat_5xx_counter, vtsn->stat_upstream.rtms,
                                      us[j].weight, us[j].max_fails,
                                      us[j].fail_timeout,
                                      ngx_vhost_traffic_status_boolean_to_string(us[j].backup),
                                      ngx_vhost_traffic_status_boolean_to_string(us[j].down),
                                      ngx_vhost_traffic_status_max_integer,
                                      vtsn->stat_request_counter_oc, vtsn->stat_in_bytes_oc,
                                      vtsn->stat_out_bytes_oc, vtsn->stat_1xx_counter_oc,
                                      vtsn->stat_2xx_counter_oc, vtsn->stat_3xx_counter_oc,
                                      vtsn->stat_4xx_counter_oc, vtsn->stat_5xx_counter_oc);
                } else {
                    buf = ngx_sprintf(buf, fmt,
                                      &us[j].addrs->name, (ngx_atomic_uint_t) 0,
                                      (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                                      (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                                      (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                                      (ngx_atomic_uint_t) 0, (ngx_msec_t) 0,
                                      us[j].weight, us[j].max_fails,
                                      us[j].fail_timeout,
                                      ngx_vhost_traffic_status_boolean_to_string(us[j].backup),
                                      ngx_vhost_traffic_status_boolean_to_string(us[j].down),
                                      ngx_vhost_traffic_status_max_integer,
                                      (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                                      (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                                      (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                                      (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0);
                }

                p = key.data;
            }

            if (s == buf) {
                buf = o;
            } else {
                buf--;
                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);
                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
            }
        }
    }

    /* alones */
    o = buf;

    ngx_str_set(&key, "::nogroups");

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S, &key);

    s = buf;

    buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(
              r, rbtree->root, rbtree->sentinel, fmt, buf, vtscf);

    if (s == buf) {
        buf = o;
    } else {
        buf--;
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    return buf;
}


#if (NGX_HTTP_CACHE)

static u_char *
ngx_http_vhost_traffic_status_display_set_cache(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    const char *fmt, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    u_char                                *p;
    ngx_str_t                              key;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    if (node != sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC) {
            key.len = vtsn->len * 6;
            key.data = ngx_pcalloc(r->pool, key.len);
            if (key.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "ngx_pcalloc() failed");
                key.len = vtsn->len;
                key.data = vtsn->data;
                p = NULL;
                goto just_start;
            }

            p = key.data;

#if !defined(nginx_version) || nginx_version < 1007009
            p = (u_char *) ngx_http_vhost_traffic_status_escape_json(p, vtsn->data, vtsn->len);
#else
            p = (u_char *) ngx_escape_json(p, vtsn->data, vtsn->len);
#endif

just_start:

            buf = ngx_sprintf(buf, fmt,
                              key.data, vtsn->stat_cache_max_size,
                              vtsn->stat_cache_used_size,
                              vtsn->stat_in_bytes,
                              vtsn->stat_out_bytes,
                              vtsn->stat_cache_miss_counter,
                              vtsn->stat_cache_bypass_counter,
                              vtsn->stat_cache_expired_counter,
                              vtsn->stat_cache_stale_counter,
                              vtsn->stat_cache_updating_counter,
                              vtsn->stat_cache_revalidated_counter,
                              vtsn->stat_cache_hit_counter,
                              vtsn->stat_cache_scarce_counter,
                              ngx_vhost_traffic_status_max_integer,
                              vtsn->stat_request_counter_oc,
                              vtsn->stat_in_bytes_oc,
                              vtsn->stat_out_bytes_oc,
                              vtsn->stat_1xx_counter_oc,
                              vtsn->stat_2xx_counter_oc,
                              vtsn->stat_3xx_counter_oc,
                              vtsn->stat_4xx_counter_oc,
                              vtsn->stat_5xx_counter_oc,
                              vtsn->stat_cache_miss_counter_oc,
                              vtsn->stat_cache_bypass_counter_oc,
                              vtsn->stat_cache_expired_counter_oc,
                              vtsn->stat_cache_stale_counter_oc,
                              vtsn->stat_cache_updating_counter_oc,
                              vtsn->stat_cache_revalidated_counter_oc,
                              vtsn->stat_cache_hit_counter_oc,
                              vtsn->stat_cache_scarce_counter_oc);

            if (p != NULL) {
                ngx_pfree(r->pool, key.data);
            }
        }

        buf = ngx_http_vhost_traffic_status_display_set_cache(
                  r, node->left, sentinel, fmt, buf, vtscf);
        buf = ngx_http_vhost_traffic_status_display_set_cache(
                  r, node->right, sentinel, fmt, buf, vtscf);
    }

    return buf;
}

#endif


static u_char *
ngx_http_vhost_traffic_status_display_set(ngx_http_request_t *r,
    ngx_rbtree_t *rbtree, u_char *buf,
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    u_char             *o, *s;
    ngx_rbtree_node_t  *node, *sentinel;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    ngx_memzero(&vtscf->stats, sizeof(vtscf->stats));

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);

    /* main & connections */
    buf = ngx_http_vhost_traffic_status_display_set_main(
              NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_MAIN, buf, vtscf);

    /* serverZones */
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S);

    buf = ngx_http_vhost_traffic_status_display_set_server(r, node, sentinel,
              NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER, buf, vtscf);

#if (NGX_HTTP_CACHE)
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER,
                      "*", vtscf->stats.stat_request_counter,
                      vtscf->stats.stat_in_bytes,
                      vtscf->stats.stat_out_bytes,
                      vtscf->stats.stat_1xx_counter,
                      vtscf->stats.stat_2xx_counter,
                      vtscf->stats.stat_3xx_counter,
                      vtscf->stats.stat_4xx_counter,
                      vtscf->stats.stat_5xx_counter,
                      vtscf->stats.stat_cache_miss_counter,
                      vtscf->stats.stat_cache_bypass_counter,
                      vtscf->stats.stat_cache_expired_counter,
                      vtscf->stats.stat_cache_stale_counter,
                      vtscf->stats.stat_cache_updating_counter,
                      vtscf->stats.stat_cache_revalidated_counter,
                      vtscf->stats.stat_cache_hit_counter,
                      vtscf->stats.stat_cache_scarce_counter,
                      ngx_vhost_traffic_status_max_integer,
                      vtscf->stats.stat_request_counter_oc,
                      vtscf->stats.stat_in_bytes_oc,
                      vtscf->stats.stat_out_bytes_oc,
                      vtscf->stats.stat_1xx_counter_oc,
                      vtscf->stats.stat_2xx_counter_oc,
                      vtscf->stats.stat_3xx_counter_oc,
                      vtscf->stats.stat_4xx_counter_oc,
                      vtscf->stats.stat_5xx_counter_oc,
                      vtscf->stats.stat_cache_miss_counter_oc,
                      vtscf->stats.stat_cache_bypass_counter_oc,
                      vtscf->stats.stat_cache_expired_counter_oc,
                      vtscf->stats.stat_cache_stale_counter_oc,
                      vtscf->stats.stat_cache_updating_counter_oc,
                      vtscf->stats.stat_cache_revalidated_counter_oc,
                      vtscf->stats.stat_cache_hit_counter_oc,
                      vtscf->stats.stat_cache_scarce_counter_oc);
#else
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER,
                      "*", vtscf->stats.stat_request_counter,
                      vtscf->stats.stat_in_bytes,
                      vtscf->stats.stat_out_bytes,
                      vtscf->stats.stat_1xx_counter,
                      vtscf->stats.stat_2xx_counter,
                      vtscf->stats.stat_3xx_counter,
                      vtscf->stats.stat_4xx_counter,
                      vtscf->stats.stat_5xx_counter,
                      ngx_vhost_traffic_status_max_integer,
                      vtscf->stats.stat_request_counter_oc,
                      vtscf->stats.stat_in_bytes_oc,
                      vtscf->stats.stat_out_bytes_oc,
                      vtscf->stats.stat_1xx_counter_oc,
                      vtscf->stats.stat_2xx_counter_oc,
                      vtscf->stats.stat_3xx_counter_oc,
                      vtscf->stats.stat_4xx_counter_oc,
                      vtscf->stats.stat_5xx_counter_oc);
#endif
    buf--;
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);

    /* filterZones */
    ngx_memzero(&vtscf->stats, sizeof(vtscf->stats));

    o = buf;

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER_S);

    s = buf;

    buf = ngx_http_vhost_traffic_status_display_set_filter(r, node, sentinel,
              NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER, buf, vtscf);

    if (s == buf) {
        buf = o;
    } else {
        buf--;
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    /* upstreamZones */
    o = buf;

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S);

    s = buf;

    buf = ngx_http_vhost_traffic_status_display_set_upstream_group(r, rbtree,
              NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM, buf, vtscf);

    if (s == buf) {
        buf = o;
        buf--;
    } else {
        buf--;
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
    }

#if (NGX_HTTP_CACHE)
    /* cacheZones */
    o = buf;

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE_S);

    s = buf;

    buf = ngx_http_vhost_traffic_status_display_set_cache(r, node, sentinel,
              NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE, buf, vtscf);

    if (s == buf) {
        buf = o;
    } else {
        buf--;
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
    }
#endif

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);

    return buf;
}


static void
ngx_http_vhost_traffic_status_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t                     **p;
    ngx_http_vhost_traffic_status_node_t   *vtsn, *vtsnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
            vtsnt = (ngx_http_vhost_traffic_status_node_t *) &temp->color;

            p = (ngx_memn2cmp(vtsn->data, vtsnt->data, vtsn->len, vtsnt->len) < 0)
                ? &temp->left
                : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_http_vhost_traffic_status_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_vhost_traffic_status_ctx_t  *octx = data;

    size_t                                len;
    ngx_slab_pool_t                      *shpool;
    ngx_rbtree_node_t                    *sentinel;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->rbtree = octx->rbtree;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;
        return NGX_OK;
    }

    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel,
                    ngx_http_vhost_traffic_status_rbtree_insert_value);

    len = sizeof(" in vhost_traffic_status_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in vhost_traffic_status_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static char *
ngx_http_vhost_traffic_status_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                               *p;
    ssize_t                               size;
    ngx_str_t                            *value, name, s;
    ngx_uint_t                            i;
    ngx_shm_zone_t                       *shm_zone;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    value = cf->args->elts;

    ctx = ngx_http_conf_get_module_main_conf(cf, ngx_http_vhost_traffic_status_module);
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->enable = 1;

    ngx_str_set(&name, NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_NAME);

    size = NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_SIZE;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "shared:", 7) == 0) {

            name.data = value[i].data + 7;

            p = (u_char *) ngx_strchr(name.data, ':');
            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid shared size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);
            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid shared size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "shared \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_vhost_traffic_status_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "vhost_traffic_status: \"%V\" is already bound to key",
                           &name);

        return NGX_CONF_ERROR;
    }

    ctx->shm_name = name;
    ctx->shm_size = size;
    shm_zone->init = ngx_http_vhost_traffic_status_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_vhost_traffic_status_filter_by_set_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    ngx_str_t                               *value;
    ngx_array_t                             *filter_keys;
    ngx_http_compile_complex_value_t         ccv;
    ngx_http_vhost_traffic_status_ctx_t     *ctx;
    ngx_http_vhost_traffic_status_filter_t  *filter;

    ctx = ngx_http_conf_get_module_main_conf(cf, ngx_http_vhost_traffic_status_module);
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty key pattern");
        return NGX_CONF_ERROR;
    }

    filter_keys = (cf->cmd_type == NGX_HTTP_MAIN_CONF) ? ctx->filter_keys : vtscf->filter_keys;
    if (filter_keys == NULL) {
        filter_keys = ngx_array_create(cf->pool, 1,
                                       sizeof(ngx_http_vhost_traffic_status_filter_t));
        if (filter_keys == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    filter = ngx_array_push(filter_keys);
    if (filter == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &filter->filter_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[2];
        ccv.complex_value = &filter->filter_name;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (cf->cmd_type == NGX_HTTP_MAIN_CONF) {
        ctx->filter_keys = filter_keys;
    } else {
        vtscf->filter_keys = filter_keys;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_vhost_traffic_status_display(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_vhost_traffic_status_display_handler;

    return NGX_CONF_OK;
}


static void *
ngx_http_vhost_traffic_status_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_vhost_traffic_status_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->enable = NGX_CONF_UNSET;
    ctx->filter_check_duplicate = NGX_CONF_UNSET;

    return ctx;
}


static char *
ngx_http_vhost_traffic_status_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_vhost_traffic_status_ctx_t  *ctx = conf;

    ngx_int_t                                  rc;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_vhost_traffic_status_module);

    if (vtscf->filter_check_duplicate != 0) {
        rc = ngx_http_vhost_traffic_status_filter_unique(cf->pool, &ctx->filter_keys);
        if (rc != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "filter_unique failed");
        }
    }

    ngx_conf_init_value(ctx->enable, 0);
    ngx_conf_init_value(ctx->filter_check_duplicate, vtscf->filter_check_duplicate);

    return NGX_CONF_OK;
}


static void *
ngx_http_vhost_traffic_status_create_loc_conf(ngx_conf_t *cf)
{
    ngx_time_t                                *tp;
    ngx_http_vhost_traffic_status_loc_conf_t  *conf;

    tp = ngx_timeofday();

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_vhost_traffic_status_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->start_msec = (ngx_msec_t) (tp->sec * 1000 + tp->msec);
    conf->enable = NGX_CONF_UNSET;
    conf->filter = NGX_CONF_UNSET;
    conf->filter_host = NGX_CONF_UNSET;
    conf->filter_check_duplicate = NGX_CONF_UNSET;
    conf->shm_zone = NGX_CONF_UNSET_PTR;
    conf->format = NGX_CONF_UNSET;
    conf->vtsn_server = NULL;
    conf->vtsn_upstream = NULL;
    conf->vtsn_hash = 0;

    return conf;
}


static char *
ngx_http_vhost_traffic_status_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_vhost_traffic_status_loc_conf_t *prev = parent;
    ngx_http_vhost_traffic_status_loc_conf_t *conf = child;

    ngx_int_t                             rc;
    ngx_str_t                             name;
    ngx_shm_zone_t                       *shm_zone;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = ngx_http_conf_get_module_main_conf(cf, ngx_http_vhost_traffic_status_module);

    if (!ctx->enable) {
        return NGX_CONF_OK;
    }

    if (conf->filter_keys == NULL) {
        conf->filter_keys = prev->filter_keys;
    } else {
        if (conf->filter_check_duplicate == NGX_CONF_UNSET) {
            conf->filter_check_duplicate = ctx->filter_check_duplicate;
        }
        if (conf->filter_check_duplicate != 0) {
            rc = ngx_http_vhost_traffic_status_filter_unique(cf->pool, &conf->filter_keys);
            if (rc != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "filter_unique failed");
            }
        }
    }

    ngx_conf_merge_value(conf->enable, prev->enable, 1);
    ngx_conf_merge_value(conf->filter, prev->filter, 1);
    ngx_conf_merge_value(conf->filter_host, prev->filter_host, 0);
    ngx_conf_merge_value(conf->filter_check_duplicate, prev->filter_check_duplicate, 1);
    ngx_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);
    ngx_conf_merge_value(conf->format, prev->format,
                         NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON);

    name = ctx->shm_name;

    shm_zone = ngx_shared_memory_add(cf, &name, 0,
                                     &ngx_http_vhost_traffic_status_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->shm_zone = shm_zone;
    conf->shm_name = name;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_vhost_traffic_status_handler;

    return NGX_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
