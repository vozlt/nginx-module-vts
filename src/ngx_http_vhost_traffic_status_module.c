
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include "ngx_http_vhost_traffic_status_module_html.h"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO          0
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA          1
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG          2
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC          3
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG          4

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAMS            (u_char *) "NO\0UA\0UG\0CC\0FG\0"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE            0
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_FIND            1

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR        (u_char) 0x1f

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_NONE          0
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON          1
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML          2

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE     0
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_STATUS   1
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_DELETE   2
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_RESET    3

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_NONE   0
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL    1
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP  2
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE   3

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_NAME     "vhost_traffic_status"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_SIZE     0xfffff

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S           "{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_S    "\"%V\":{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S     "\"%V\":["

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E     "]"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_E    "}"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E           "}"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT        ","

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CONTROL "{"                     \
    "\"processingReturn\":%s,"                                                 \
    "\"processingCommandString\":\"%V\","                                      \
    "\"processingGroupString\":\"%V\","                                        \
    "\"processingZoneString\":\"%V\","                                         \
    "\"processingCounts\":%ui"                                                 \
    "}"

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
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER "\"%V\":{"               \
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
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER "\"%V\":{"               \
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
    "\"responseMsec\":%M,"                                                     \
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
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE "\"%V\":{"                \
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

#define ngx_vhost_traffic_status_group_to_string(n) (u_char *) (               \
    (n > 4)                                                                    \
    ? NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAMS                                  \
    : NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAMS + 3 * n                          \
)

#define ngx_vhost_traffic_status_string_to_group(s) (unsigned) (               \
{                                                                              \
    unsigned n = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;                    \
    if (*s == 'N' && *(s + 1) == 'O') {                                        \
        n = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;                         \
    } else if (*s == 'U' && *(s + 1) == 'A') {                                 \
        n = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;                         \
    } else if (*s == 'U' && *(s + 1) == 'G') {                                 \
        n = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;                         \
    } else if (*s == 'C' && *(s + 1) == 'C') {                                 \
        n = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC;                         \
    } else if (*s == 'F' && *(s + 1) == 'G') {                                 \
        n = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG;                         \
    }                                                                          \
    n;                                                                         \
}                                                                              \
)

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
    ngx_rbtree_node_t           *node;
} ngx_http_vhost_traffic_status_delete_t;


typedef struct {
    ngx_http_request_t          *r;
    ngx_uint_t                   command;
    ngx_int_t                    group;
    ngx_str_t                   *zone;
    ngx_str_t                   *arg_cmd;
    ngx_str_t                   *arg_group;
    ngx_str_t                   *arg_zone;
    ngx_uint_t                   range;
    ngx_uint_t                   count;
    u_char                     **buf;
} ngx_http_vhost_traffic_status_control_t;


typedef struct {
    ngx_http_complex_value_t     key;
    ngx_http_complex_value_t     variable;
    ngx_atomic_t                 size;
    ngx_uint_t                   code;
    unsigned                     type;        /* unsigned type:5 */
} ngx_http_vhost_traffic_status_limit_t;


typedef struct {
    ngx_rbtree_t                *rbtree;

    /* array of ngx_http_vhost_traffic_status_filter_t */
    ngx_array_t                 *filter_keys;

    /* array of ngx_http_vhost_traffic_status_limit_t */
    ngx_array_t                 *limit_traffics;

    /* array of ngx_http_vhost_traffic_status_limit_t */
    ngx_array_t                 *limit_filter_traffics;

    ngx_flag_t                   enable;
    ngx_flag_t                   filter_check_duplicate;
    ngx_flag_t                   limit_check_duplicate;
    ngx_str_t                    shm_name;
    ssize_t                      shm_size;
} ngx_http_vhost_traffic_status_ctx_t;


typedef struct {
    unsigned                     type;        /* unsigned type:5 */
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
    ngx_http_vhost_traffic_status_node_t            *node;
} ngx_http_vhost_traffic_status_filter_node_t;


typedef struct {
    ngx_shm_zone_t                                  *shm_zone;
    ngx_flag_t                                       enable;
    ngx_flag_t                                       filter;
    ngx_flag_t                                       filter_host;
    ngx_flag_t                                       filter_check_duplicate;

    /* array of ngx_http_vhost_traffic_status_filter_t */
    ngx_array_t                                     *filter_keys;

    ngx_flag_t                                       limit;
    ngx_flag_t                                       limit_check_duplicate;

    /* array of ngx_http_vhost_traffic_status_limit_t */
    ngx_array_t                                     *limit_traffics;

    /* array of ngx_http_vhost_traffic_status_limit_t */
    ngx_array_t                                     *limit_filter_traffics;

    ngx_str_t                                        shm_name;
    ngx_http_vhost_traffic_status_node_t             stats;
    ngx_msec_t                                       start_msec;
    ngx_str_t                                        display;
    ngx_flag_t                                       format;

    ngx_rbtree_node_t                              **node_caches;
} ngx_http_vhost_traffic_status_loc_conf_t;


#if !defined(nginx_version) || nginx_version < 1007009
uintptr_t ngx_http_vhost_traffic_status_escape_json(u_char *dst, u_char *src, size_t size);
#endif

static ngx_int_t ngx_http_vhost_traffic_status_escape_json_pool(ngx_pool_t *pool,
    ngx_str_t *buf, ngx_str_t *dst);
static ngx_int_t ngx_http_vhost_traffic_status_copy_str(ngx_pool_t *pool,
    ngx_str_t *buf, ngx_str_t *dst);
static ngx_int_t ngx_http_vhost_traffic_status_replace_chrc(ngx_str_t *buf,
    u_char in, u_char to);
static ngx_int_t ngx_http_vhost_traffic_status_replace_strc(ngx_str_t *buf,
    ngx_str_t *dst, u_char c);

static ngx_int_t ngx_http_vhost_traffic_status_node_generate_key(ngx_pool_t *pool,
    ngx_str_t *buf, ngx_str_t *dst, unsigned type);
static ngx_int_t ngx_http_vhost_traffic_status_node_position_key(ngx_str_t *buf,
    size_t pos);

static ngx_int_t ngx_http_vhost_traffic_status_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_vhost_traffic_status_limit_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_vhost_traffic_status_limit_handler_traffic(ngx_http_request_t *r,
    ngx_array_t *traffics);
static ngx_int_t ngx_http_vhost_traffic_status_display_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_vhost_traffic_status_display_handler_control(ngx_http_request_t *r);
static ngx_int_t ngx_http_vhost_traffic_status_display_handler_default(ngx_http_request_t *r);

static ngx_int_t ngx_vhost_traffic_status_node_member_cmp(ngx_str_t *member, const char *name);
static ngx_atomic_uint_t ngx_vhost_traffic_status_node_member(ngx_http_vhost_traffic_status_node_t *vtsn,
    ngx_str_t *member);
static ngx_int_t ngx_http_vhost_traffic_status_node_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void ngx_http_vhost_traffic_status_find_name(ngx_http_request_t *r,
    ngx_str_t *buf);
static ngx_rbtree_node_t *ngx_http_vhost_traffic_status_find_node(ngx_http_request_t *r,
    ngx_str_t *key, unsigned type, uint32_t key_hash);

static ngx_int_t ngx_http_vhost_traffic_status_shm_add_node(ngx_http_request_t *r,
    ngx_str_t *key, unsigned type);
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_node_upstream(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, unsigned init);

#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_node_cache(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, unsigned init);
#endif

static ngx_int_t ngx_http_vhost_traffic_status_shm_add_filter_node(ngx_http_request_t *r,
    ngx_array_t *filter_keys);
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_server(ngx_http_request_t *r);
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_upstream(ngx_http_request_t *r);

#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_cache(ngx_http_request_t *r);
#endif

static ngx_rbtree_node_t *ngx_http_vhost_traffic_status_node_lookup(
    ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash);
static void ngx_http_vhost_traffic_status_node_zero(
    ngx_http_vhost_traffic_status_node_t *vtsn);
static void ngx_http_vhost_traffic_status_node_init(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn);
static void ngx_vhost_traffic_status_node_set(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn);

static void ngx_http_vhost_traffic_status_node_upstream_lookup(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_http_upstream_server_t *us);
static void ngx_http_vhost_traffic_status_node_control_range_set(
    ngx_http_vhost_traffic_status_control_t *control);
static void ngx_http_vhost_traffic_status_node_status_all(
    ngx_http_vhost_traffic_status_control_t *control);
static void ngx_http_vhost_traffic_status_node_status_group(
    ngx_http_vhost_traffic_status_control_t *control);
static void ngx_http_vhost_traffic_status_node_status_zone(
    ngx_http_vhost_traffic_status_control_t *control);
static void ngx_http_vhost_traffic_status_node_status(
    ngx_http_vhost_traffic_status_control_t *control);

static ngx_int_t ngx_http_vhost_traffic_status_node_delete_get_nodes(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_array_t **nodes, ngx_rbtree_node_t *node);
static void ngx_http_vhost_traffic_status_node_delete_all(
    ngx_http_vhost_traffic_status_control_t *control);
static void ngx_http_vhost_traffic_status_node_delete_group(
    ngx_http_vhost_traffic_status_control_t *control);
static void ngx_http_vhost_traffic_status_node_delete_zone(
    ngx_http_vhost_traffic_status_control_t *control);
static void ngx_http_vhost_traffic_status_node_delete(
    ngx_http_vhost_traffic_status_control_t *control);

static void ngx_http_vhost_traffic_status_node_reset_all(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_rbtree_node_t *node);
static void ngx_http_vhost_traffic_status_node_reset_group(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_rbtree_node_t *node);
static void ngx_http_vhost_traffic_status_node_reset_zone(
    ngx_http_vhost_traffic_status_control_t *control);
 static void ngx_http_vhost_traffic_status_node_reset(
    ngx_http_vhost_traffic_status_control_t *control);

static int ngx_libc_cdecl ngx_http_traffic_status_filter_cmp_hashs(
    const void *one, const void *two);
static int ngx_libc_cdecl ngx_http_traffic_status_filter_cmp_keys(
    const void *one, const void *two);
static ngx_int_t ngx_http_vhost_traffic_status_filter_unique(
    ngx_pool_t *pool, ngx_array_t **keys);
static ngx_int_t ngx_http_vhost_traffic_status_filter_get_keys(
    ngx_http_request_t *r, ngx_array_t **filter_keys,
    ngx_rbtree_node_t *node);
static ngx_int_t ngx_http_vhost_traffic_status_filter_get_nodes(
    ngx_http_request_t *r, ngx_array_t **filter_nodes,
    ngx_str_t *name, ngx_rbtree_node_t *node);

static ngx_int_t ngx_http_vhost_traffic_status_limit_traffic_unique(
    ngx_pool_t *pool, ngx_array_t **keys);

static u_char *ngx_http_vhost_traffic_status_display_set_main(
    ngx_http_request_t *r, u_char *buf);
static u_char *ngx_http_vhost_traffic_status_display_set_server_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn);
static u_char *ngx_http_vhost_traffic_status_display_set_server(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
static u_char *ngx_http_vhost_traffic_status_display_set_filter_node(
    ngx_http_request_t *r, u_char *buf,
    ngx_http_vhost_traffic_status_node_t *vtsn);
static u_char *ngx_http_vhost_traffic_status_display_set_filter(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
static u_char *ngx_http_vhost_traffic_status_display_set_upstream_node(
    ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_server_t *us,
#if nginx_version > 1007001
    ngx_http_vhost_traffic_status_node_t *vtsn
#else
    ngx_http_vhost_traffic_status_node_t *vtsn, ngx_str_t *name
#endif
    );
static u_char *ngx_http_vhost_traffic_status_display_set_upstream_alone(
    ngx_http_request_t *r, u_char *buf, ngx_rbtree_node_t *node);
static u_char *ngx_http_vhost_traffic_status_display_set_upstream_group(
    ngx_http_request_t *r, u_char *buf);

#if (NGX_HTTP_CACHE)
static u_char *ngx_http_vhost_traffic_status_display_set_cache_node(
    ngx_http_request_t *r, u_char *buf,
    ngx_http_vhost_traffic_status_node_t *vtsn);
static u_char *ngx_http_vhost_traffic_status_display_set_cache(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
#endif

static u_char *ngx_http_vhost_traffic_status_display_set(ngx_http_request_t *r,
    u_char *buf);

static void ngx_http_vhost_traffic_status_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_vhost_traffic_status_init_zone(
    ngx_shm_zone_t *shm_zone, void *data);
static char *ngx_http_vhost_traffic_status_zone(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_vhost_traffic_status_filter_by_set_key(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_vhost_traffic_status_limit_traffic(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_vhost_traffic_status_limit_traffic_by_set_key(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_vhost_traffic_status_display(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_vhost_traffic_status_add_variables(ngx_conf_t *cf);
static void *ngx_http_vhost_traffic_status_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_vhost_traffic_status_init_main_conf(ngx_conf_t *cf,
    void *conf);
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

    { ngx_string("vhost_traffic_status_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, limit),
      NULL },

    { ngx_string("vhost_traffic_status_limit_check_duplicate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, limit_check_duplicate),
      NULL },

    { ngx_string("vhost_traffic_status_limit_traffic"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_vhost_traffic_status_limit_traffic,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("vhost_traffic_status_limit_traffic_by_set_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_vhost_traffic_status_limit_traffic_by_set_key,
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
    ngx_http_vhost_traffic_status_add_variables,    /* preconfiguration */
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


static ngx_http_variable_t  ngx_http_vhost_traffic_status_vars[] = {

    { ngx_string("vts_request_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_request_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_in_bytes"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_in_bytes),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_out_bytes"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_out_bytes),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_1xx_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_1xx_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_2xx_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_2xx_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_3xx_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_3xx_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_4xx_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_4xx_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_5xx_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_5xx_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if (NGX_HTTP_CACHE)
    { ngx_string("vts_cache_miss_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_cache_miss_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_cache_bypass_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_cache_bypass_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_cache_expired_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_cache_expired_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_cache_stale_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_cache_stale_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_cache_updating_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_cache_updating_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_cache_revalidated_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_cache_revalidated_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_cache_hit_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_cache_hit_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("vts_cache_scarce_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_cache_scarce_counter),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
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
ngx_http_vhost_traffic_status_escape_json_pool(ngx_pool_t *pool,
    ngx_str_t *buf, ngx_str_t *dst)
{
    u_char  *p;

    buf->len = dst->len * 6;
    buf->data = ngx_pcalloc(pool, buf->len);
    if (buf->data == NULL) {
        *buf = *dst;
        return NGX_ERROR;
    }

    p = buf->data;

#if !defined(nginx_version) || nginx_version < 1007009
    p = (u_char *) ngx_http_vhost_traffic_status_escape_json(p, dst->data, dst->len);
#else
    p = (u_char *) ngx_escape_json(p, dst->data, dst->len);
#endif

    buf->len = ngx_strlen(buf->data);

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_copy_str(ngx_pool_t *pool,
    ngx_str_t *buf, ngx_str_t *dst)
{
    u_char  *p;

    buf->len = dst->len;
    buf->data = ngx_pcalloc(pool, dst->len + 1); /* 1 byte for terminating '\0' */
    if (buf->data == NULL) {
        return NGX_ERROR;
    }

    p = buf->data;

    ngx_memcpy(p, dst->data, dst->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_replace_chrc(ngx_str_t *buf,
    u_char in, u_char to)
{
    size_t   len;
    u_char  *p;

    p = buf->data;

    len = buf->len;

    while(len--) {
        if (*p == in) {
            *p = to;
        }
        p++;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_replace_strc(ngx_str_t *buf,
    ngx_str_t *dst, u_char c)
{
    size_t   n, len;
    u_char  *p, *o;
    p = o = buf->data;
    n = 0;

    /* we need the buf's last '\0' for ngx_strstrn() */
    if (*(buf->data + buf->len) != 0) {
        return NGX_ERROR;
    }

    while ((p = ngx_strstrn(p, (char *) dst->data, dst->len - 1)) != NULL) {
        n++;
        len = buf->len - (p - o) - (n * dst->len) + n - 1;
        *p++ = c;
        ngx_memmove(p, p + dst->len - 1, len);
    }

    if (n > 0) {
        buf->len = buf->len - (n * dst->len) + n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_node_generate_key(ngx_pool_t *pool,
    ngx_str_t *buf, ngx_str_t *dst, unsigned type)
{
    size_t   len;
    u_char  *p;

    len = ngx_strlen(ngx_vhost_traffic_status_group_to_string(type));

    buf->len = len + sizeof("@") - 1 + dst->len;
    buf->data = ngx_pcalloc(pool, buf->len);
    if (buf->data == NULL) {
        *buf = *dst;
        return NGX_ERROR;
    }

    p = buf->data;

    p = ngx_cpymem(p, ngx_vhost_traffic_status_group_to_string(type), len);
    *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
    p = ngx_cpymem(p, dst->data, dst->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_node_position_key(ngx_str_t *buf, size_t pos)
{
    size_t   n, c, len;
    u_char  *p, *s;

    n = buf->len + 1;
    c = len = 0;
    p = s = buf->data;

    while (--n) {
        if (*p == NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR) {
            if (pos == c) {
                break;
            }
            s = (p + 1);
            c++;
        }
        p++;
        len = (p - s);
    }

    if (pos > c || len == 0) {
        return NGX_ERROR;
    }

    buf->data = s;
    buf->len = len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_handler(ngx_http_request_t *r)
{
    ngx_int_t                                  rc;
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

    rc = ngx_http_vhost_traffic_status_shm_add_server(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "handler::shm_add_server() failed");
    }

    rc = ngx_http_vhost_traffic_status_shm_add_upstream(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "handler::shm_add_upstream() failed");
    }

    rc = ngx_http_vhost_traffic_status_shm_add_filter(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "handler::shm_add_filter() failed");
    }

#if (NGX_HTTP_CACHE)
    rc = ngx_http_vhost_traffic_status_shm_add_cache(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "handler::shm_add_cache() failed");
    }
#endif

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_vhost_traffic_status_limit_handler(ngx_http_request_t *r)
{
    ngx_int_t                                  rc;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (!vtscf->limit) {
        return NGX_DECLINED;
    }

    /* limit traffic of server */
    rc = ngx_http_vhost_traffic_status_limit_handler_traffic(r, ctx->limit_traffics);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = ngx_http_vhost_traffic_status_limit_handler_traffic(r, vtscf->limit_traffics);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* limit traffic of filter */
    rc = ngx_http_vhost_traffic_status_limit_handler_traffic(r, ctx->limit_filter_traffics);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = ngx_http_vhost_traffic_status_limit_handler_traffic(r, vtscf->limit_filter_traffics);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_vhost_traffic_status_limit_handler_traffic(ngx_http_request_t *r,
    ngx_array_t *traffics)
{
    unsigned                                   type;
    ngx_str_t                                  variable, key, dst;
    ngx_int_t                                  rc;
    ngx_uint_t                                 i, n;
    ngx_atomic_t                               traffic_used;
    ngx_slab_pool_t                           *shpool;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_node_t      *vtsn;
    ngx_http_vhost_traffic_status_limit_t     *limits;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    rc = NGX_DECLINED;

    if (traffics == NULL) {
        return rc;
    }

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    limits = traffics->elts;
    n = traffics->nelts;

    for (i = 0; i < n; i++) {
        if (&limits[i].variable == NULL) {
            continue;
        }

        /* init */
        traffic_used = 0;
        variable.len = 0;
        key.len = 0;
        dst.len = 0;
        type = limits[i].type;

        if (ngx_http_complex_value(r, &limits[i].variable, &variable) != NGX_OK) {
            goto done;
        }

        if (variable.len == 0) {
            continue;
        }

        /* traffic of filter */
        if (limits[i].key.value.len > 0) {
            if (ngx_http_complex_value(r, &limits[i].key, &key) != NGX_OK) {
                goto done;
            }

            if (key.len == 0) {
                continue;
            }

            node = ngx_http_vhost_traffic_status_find_node(r, &key, type, 0);

            if (node == NULL) {
                continue;
            }

            vtscf->node_caches[type] = node;

            vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

            traffic_used = (ngx_atomic_t) ngx_vhost_traffic_status_node_member(vtsn, &variable);

        /* traffic of server */
        } else {
            ngx_http_vhost_traffic_status_find_name(r, &dst);

            if (ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type)
                != NGX_OK || key.len == 0)
            {
                goto done;
            }

            node = ngx_http_vhost_traffic_status_find_node(r, &key, type, 0);

            if (node == NULL) {
                continue;
            }

            vtscf->node_caches[type] = node;

            vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

            traffic_used = (ngx_atomic_t) ngx_vhost_traffic_status_node_member(vtsn, &variable);
        }

        if (traffic_used > limits[i].size) {
            rc = limits[i].code;
            goto done;
        }
    }

done:

    ngx_shmtx_unlock(&shpool->mutex);

    return rc;
}


static ngx_int_t
ngx_http_vhost_traffic_status_display_handler(ngx_http_request_t *r)
{
    size_t                                     len;
    u_char                                    *p;
    ngx_int_t                                  rc;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (!ctx->enable) {
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    len = 0;

    p = (u_char *) ngx_strchr(r->uri.data, '/');

    if (p) {
        p = (u_char *) ngx_strchr(p + 1, '/');
        len = r->uri.len - (p - r->uri.data);
    }

    /* control processing handler */
    if (p && len >= sizeof("/control") - 1) {
        p = r->uri.data + r->uri.len - sizeof("/control") + 1;
        if (ngx_strncasecmp(p, (u_char *) "/control", sizeof("/control") - 1) == 0) {
            rc = ngx_http_vhost_traffic_status_display_handler_control(r);
            goto done;
        }
    }

    /* default processing handler */
    rc = ngx_http_vhost_traffic_status_display_handler_default(r);

done:

    return rc;
}


static ngx_int_t
ngx_http_vhost_traffic_status_display_handler_control(ngx_http_request_t *r)
{
    size_t                                     size;
    ngx_int_t                                  rc;
    ngx_str_t                                  type, alpha, arg_cmd, arg_group, arg_zone;
    ngx_buf_t                                 *b;
    ngx_chain_t                                out;
    ngx_slab_pool_t                           *shpool;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_control_t   *control;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    /* init control */
    control = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_control_t));
    control->r = r;
    control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE;
    control->group = -2;
    control->arg_cmd = &arg_cmd;
    control->arg_group = &arg_group;
    control->arg_zone = &arg_zone;
    control->range = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_NONE;
    control->count = 0;

    arg_cmd.len = 0;
    arg_group.len = 0;
    arg_zone.len = 0;

    if (r->args.len) {

        if (ngx_http_arg(r, (u_char *) "cmd", 3, &arg_cmd) == NGX_OK) {

            if (arg_cmd.len == 6 && ngx_strncmp(arg_cmd.data, "status", 6) == 0)
            {
                control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_STATUS;
            }
            else if (arg_cmd.len == 6 && ngx_strncmp(arg_cmd.data, "delete", 6) == 0)
            {
                control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_DELETE;
            }
            else if (arg_cmd.len == 5 && ngx_strncmp(arg_cmd.data, "reset", 5) == 0)
            {
                control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_RESET;
            }
            else
            {
                control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE;
            }
        }

        if (ngx_http_arg(r, (u_char *) "group", 5, &arg_group) == NGX_OK) {

            if (arg_group.len == 1 && ngx_strncmp(arg_group.data, "*", 1) == 0)
            {
                control->group = -1;
            }
            else if (arg_group.len == 6
                     && ngx_strncasecmp(arg_group.data, (u_char *) "server", 6) == 0)
            {
                control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;
            }
            else if (arg_group.len == 14
                     && ngx_strncasecmp(arg_group.data, (u_char *) "upstream@alone", 14) == 0)
            {
                control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;
            }
            else if (arg_group.len == 14
                     && ngx_strncasecmp(arg_group.data, (u_char *) "upstream@group", 14) == 0)
            {
                control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;
            }
            else if (arg_group.len == 5
                     && ngx_strncasecmp(arg_group.data, (u_char *) "cache", 5) == 0)
            {
                control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC;
            }
            else if (arg_group.len == 6
                     && ngx_strncasecmp(arg_group.data, (u_char *) "filter", 6) == 0)
            {
                control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG;
            }
            else {
                control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE;
            }
        }

        if (ngx_http_arg(r, (u_char *) "zone", 4, &arg_zone) != NGX_OK) {
            if (control->group != -1) {
                control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE;
            }

        } else {
            control->zone = ngx_palloc(r->pool, sizeof(ngx_str_t));

            rc = ngx_http_vhost_traffic_status_copy_str(r->pool, control->zone, &arg_zone);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_handler_control::copy_str() failed");
            }

            (void) ngx_http_vhost_traffic_status_replace_chrc(control->zone, '@',
                       NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR);

            ngx_str_set(&alpha, "[:alpha:]");

            rc = ngx_http_vhost_traffic_status_replace_strc(control->zone, &alpha, '@');
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_handler_control::replace_strc() failed");
            }
        }

        ngx_http_vhost_traffic_status_node_control_range_set(control);
    }

    if (control->command == NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_STATUS) {
        size = ctx->shm_size;

    } else {
        size = sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CONTROL)
               + arg_cmd.len + arg_group.len + arg_zone.len + 256;
    }

    ngx_str_set(&type, "application/json");

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

    control->buf = &b->last;

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    switch (control->command) {

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_STATUS:
        ngx_http_vhost_traffic_status_node_status(control);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_DELETE:
        ngx_http_vhost_traffic_status_node_delete(control);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_RESET:
        ngx_http_vhost_traffic_status_node_reset(control);
        break;

    default:
        *control->buf = ngx_sprintf(*control->buf,
                                    NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CONTROL,
                                    ngx_vhost_traffic_status_boolean_to_string(0),
                                    control->arg_cmd, control->arg_group,
                                    control->arg_zone, control->count);
        break;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    if (b->last == b->pos) {
        b->last = ngx_sprintf(b->last, "{}");
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


static ngx_int_t
ngx_http_vhost_traffic_status_display_handler_default(ngx_http_request_t *r)
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
        b->last = ngx_http_vhost_traffic_status_display_set(r, b->last);
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


static ngx_int_t
ngx_vhost_traffic_status_node_member_cmp(ngx_str_t *member, const char *name)
{
    if (member->len == ngx_strlen(name) && ngx_strncmp(name, member->data, member->len) == 0) {
        return 0;
    }

    return 1;
}


static ngx_atomic_uint_t
ngx_vhost_traffic_status_node_member(ngx_http_vhost_traffic_status_node_t *vtsn,
    ngx_str_t *member)
{
    if (ngx_vhost_traffic_status_node_member_cmp(member, "request") == 0)
    {
        return vtsn->stat_request_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "in") == 0)
    {
        return vtsn->stat_in_bytes;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "out") == 0)
    {
        return vtsn->stat_out_bytes;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "1xx") == 0)
    {
        return vtsn->stat_1xx_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "2xx") == 0)
    {
        return vtsn->stat_2xx_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "3xx") == 0)
    {
        return vtsn->stat_3xx_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "4xx") == 0)
    {
        return vtsn->stat_4xx_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "5xx") == 0)
    {
        return vtsn->stat_5xx_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "cache_miss") == 0)
    {
        return vtsn->stat_cache_miss_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "cache_bypass") == 0)
    {
        return vtsn->stat_cache_bypass_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "cache_expired") == 0)
    {
        return vtsn->stat_cache_expired_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "cache_stale") == 0)
    {
        return vtsn->stat_cache_stale_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "cache_updating") == 0)
    {
        return vtsn->stat_cache_updating_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "cache_revalidated") == 0)
    {
        return vtsn->stat_cache_revalidated_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "cache_hit") == 0)
    {
        return vtsn->stat_cache_hit_counter;
    }
    else if (ngx_vhost_traffic_status_node_member_cmp(member, "cache_scarce") == 0)
    {
        return vtsn->stat_cache_scarce_counter;
    }

    return 0;
}


static ngx_int_t
ngx_http_vhost_traffic_status_node_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                                    *p;
    unsigned                                   type;
    ngx_int_t                                  rc;
    ngx_str_t                                  key, dst;
    ngx_slab_pool_t                           *shpool;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_node_t      *vtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    ngx_http_vhost_traffic_status_find_name(r, &dst);

    type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (key.len == 0) {
        return NGX_ERROR;
    }

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    node = ngx_http_vhost_traffic_status_find_node(r, &key, type, 0);

    if (node == NULL) {
        goto not_found;
    }

    p = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
    if (p == NULL) {
        goto not_found;
    }

    vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

    v->len = ngx_sprintf(p, "%uA", *((ngx_atomic_t *) ((char *) vtsn + data))) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    goto done;

not_found:

    v->not_found = 1;

done:

    vtscf->node_caches[type] = node;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


static void
ngx_http_vhost_traffic_status_find_name(ngx_http_request_t *r,
    ngx_str_t *buf)
{
    ngx_http_core_srv_conf_t                  *cscf;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (vtscf->filter && vtscf->filter_host && r->headers_in.server.len) {
        /* set the key by host header */
        *buf = r->headers_in.server;

    } else {
        /* set the key by server_name variable */
        *buf = cscf->server_name;

        if (buf->len == 0) {
            buf->len = 1;
            buf->data = (u_char *) "_";
        }
    }
}


static ngx_rbtree_node_t *
ngx_http_vhost_traffic_status_find_node(ngx_http_request_t *r,
    ngx_str_t *key, unsigned type, uint32_t key_hash)
{
    uint32_t                                   hash;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    hash = key_hash;

    if (hash == 0) {
        hash = ngx_crc32_short(key->data, key->len);
    }

    if (vtscf->node_caches[type] != NULL) {
        if (vtscf->node_caches[type]->key == hash) {
            node = vtscf->node_caches[type];
            goto found;
        }
    }

    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, key, hash);

found:

    return node;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_node(ngx_http_request_t *r,
    ngx_str_t *key, unsigned type)
{
    size_t                                     size;
    unsigned                                   init;
    uint32_t                                   hash;
    ngx_slab_pool_t                           *shpool;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_node_t      *vtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (key->len == 0) {
        return NGX_ERROR;
    }

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    /* find node */
    hash = ngx_crc32_short(key->data, key->len);

    node = ngx_http_vhost_traffic_status_find_node(r, key, type, hash);

    /* set common */
    if (node == NULL) {
        init = NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE;
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
        ngx_http_vhost_traffic_status_node_init(r, vtsn);
        vtsn->stat_upstream.type = type;
        ngx_memcpy(vtsn->data, key->data, key->len);

        ngx_rbtree_insert(ctx->rbtree, node);

    } else {
        init = NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_FIND;
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
        ngx_vhost_traffic_status_node_set(r, vtsn);
    }

    /* set addition */
    switch(type) {
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO:
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:
        (void) ngx_http_vhost_traffic_status_shm_add_node_upstream(r, vtsn, init);
        break;

#if (NGX_HTTP_CACHE)
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
        (void) ngx_http_vhost_traffic_status_shm_add_node_cache(r, vtsn, init);
        break;
#endif

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG:
        break;
    }

    vtscf->node_caches[type] = node;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_node_upstream(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, unsigned init)
{
    ngx_uint_t                  i;
    ngx_msec_int_t              ms;
    ngx_http_upstream_state_t  *state;

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

    if (init == NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE) {
        vtsn->stat_upstream.rtms = ms;

    } else {
        vtsn->stat_upstream.rtms = (ngx_msec_t)
                                   (vtsn->stat_upstream.rtms + ms) / 2
                                   + (vtsn->stat_upstream.rtms + ms) % 2;
    }

    return NGX_OK;
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_node_cache(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, unsigned init)
{
    ngx_http_cache_t       *c;
    ngx_http_upstream_t    *u;
    ngx_http_file_cache_t  *cache;

    u = r->upstream;

    if (u != NULL && u->cache_status != 0 && r->cache != NULL) {
        c = r->cache;
        cache = c->file_cache;

    } else {
        return NGX_OK;
    }

    if (init == NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE) {
        vtsn->stat_cache_max_size = (ngx_atomic_uint_t) (cache->max_size * cache->bsize);

    } else {
        ngx_shmtx_lock(&cache->shpool->mutex);

        vtsn->stat_cache_used_size = (ngx_atomic_uint_t) (cache->sh->size * cache->bsize);

        ngx_shmtx_unlock(&cache->shpool->mutex);
    }

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_filter_node(ngx_http_request_t *r,
    ngx_array_t *filter_keys)
{
    u_char                                  *p;
    unsigned                                 type;
    ngx_int_t                                rc;
    ngx_str_t                                key, dst, filter_key, filter_name;
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
            type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

            rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &filter_key, type);
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

        } else {
            type = filter_name.len
                   ? NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG
                   : NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

            dst.len = filter_name.len + sizeof("@") - 1 + filter_key.len;
            dst.data = ngx_pnalloc(r->pool, dst.len);
            if (dst.data == NULL) {
                return NGX_ERROR;
            }

            p = dst.data;
            p = ngx_cpymem(p, filter_name.data, filter_name.len);
            *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
            p = ngx_cpymem(p, filter_key.data, filter_key.len);

            rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }
        }

        rc = ngx_http_vhost_traffic_status_shm_add_node(r, &key, type);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter_node::shm_add_node(\"%V\") failed", &key);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_server(ngx_http_request_t *r)
{
    unsigned                                   type;
    ngx_int_t                                  rc;
    ngx_str_t                                  key, dst;
    ngx_http_core_srv_conf_t                  *cscf;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (vtscf->filter && vtscf->filter_host && r->headers_in.server.len) {
        /* set the key by host header */
        dst = r->headers_in.server;

    } else {
        /* set the key by server_name variable */
        dst = cscf->server_name;
        if (dst.len == 0) {
            dst.len = 1;
            dst.data = (u_char *) "_";
        }
    }

    type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_vhost_traffic_status_shm_add_node(r, &key, type);
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_filter(ngx_http_request_t *r)
{
    ngx_int_t                                  rc;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (!vtscf->filter) {
        return NGX_OK;
    }

    if (ctx->filter_keys != NULL) {
        rc = ngx_http_vhost_traffic_status_shm_add_filter_node(r, ctx->filter_keys);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter::shm_add_filter_node(\"http\") failed");
        }
    }

    if (vtscf->filter_keys != NULL) {
        rc = ngx_http_vhost_traffic_status_shm_add_filter_node(r, vtscf->filter_keys);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter::shm_add_filter_node(\"server\") failed");
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_upstream(ngx_http_request_t *r)
{
    u_char                         *p;
    unsigned                        type;
    ngx_int_t                       rc;
    ngx_str_t                      *host, key, dst;
    ngx_uint_t                      i;
    ngx_http_upstream_t            *u;
    ngx_http_upstream_state_t      *state;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

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

    dst.len = (uscf->port ? 0 : uscf->host.len + sizeof("@") - 1) + state[0].peer->len;
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    p = dst.data;
    if (uscf->port) {
        p = ngx_cpymem(p, state[0].peer->data, state[0].peer->len);
        type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;

    } else {
        p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
        *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
        p = ngx_cpymem(p, state[0].peer->data, state[0].peer->len);
        type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;
    }

    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_vhost_traffic_status_shm_add_node(r, &key, type);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_upstream::shm_add_node(\"%V\") failed", &key);
    }

    return NGX_OK;
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_cache(ngx_http_request_t *r)
{
    unsigned                type;
    ngx_int_t               rc;
    ngx_str_t               key;
    ngx_http_cache_t       *c;
    ngx_http_upstream_t    *u;
    ngx_http_file_cache_t  *cache;

    u = r->upstream;

    if (u != NULL && u->cache_status != 0 && r->cache != NULL) {
        c = r->cache;
        cache = c->file_cache;

    } else {
        return NGX_OK;
    }

    type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC;

    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &cache->shm_zone->shm.name,
                                                         type);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_vhost_traffic_status_shm_add_node(r, &key, type);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_cache::shm_add_node(\"%V\") failed", &key);
    }

    return NGX_OK;
}

#endif


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


static void
ngx_http_vhost_traffic_status_node_zero(ngx_http_vhost_traffic_status_node_t *vtsn)
{
    vtsn->stat_request_counter = 0;
    vtsn->stat_in_bytes = 0;
    vtsn->stat_out_bytes = 0;
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
#endif

}


static void
ngx_http_vhost_traffic_status_node_init(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_uint_t status = r->headers_out.status;

    ngx_http_vhost_traffic_status_node_zero(vtsn);

    vtsn->stat_upstream.type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;
    vtsn->stat_request_counter = 1;
    vtsn->stat_in_bytes = (ngx_atomic_uint_t) r->request_length;
    vtsn->stat_out_bytes = (ngx_atomic_uint_t) r->connection->sent;

    ngx_vhost_traffic_status_add_rc(status, vtsn);

#if (NGX_HTTP_CACHE)
    if (r->upstream != NULL && r->upstream->cache_status != 0) {
        ngx_vhost_traffic_status_add_cc(r->upstream->cache_status, vtsn);
    }
#endif

}


static void
ngx_vhost_traffic_status_node_set(ngx_http_request_t *r,
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


static void
ngx_http_vhost_traffic_status_node_upstream_lookup(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_http_upstream_server_t *usn)
{
    ngx_int_t                       rc;
    ngx_str_t                       key, usg, ush;
    ngx_uint_t                      i, j;
    ngx_http_upstream_server_t     *us;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(control->r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    key = *control->zone;

    if (control->group == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA) {

#if nginx_version > 1007001
        usn->name = key;
#endif

        usn->weight = 0;
        usn->max_fails = 0;
        usn->fail_timeout = 0;
        usn->down = 0;
        usn->backup = 0;
        control->count++;
        return;
    }

    usg = ush = key;

    rc = ngx_http_vhost_traffic_status_node_position_key(&usg, 0);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, control->r->connection->log, 0,
                      "node_upstream_lookup::node_position_key(\"%V\", 0) group not found", &usg);
        return;
    }

    rc = ngx_http_vhost_traffic_status_node_position_key(&ush, 1);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, control->r->connection->log, 0,
                      "node_upstream_lookup::node_position_key(\"%V\", 1) host not found", &ush);
        return;
    }

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        /* nogroups */
        if(uscf->servers == NULL && uscf->port != 0) {
            continue;
        }

        us = uscf->servers->elts;

        if (uscf->host.len == usg.len) {
            if (ngx_strncmp(uscf->host.data, usg.data, usg.len) == 0) {

                for (j = 0; j < uscf->servers->nelts; j++) {
                    if (us[j].addrs->name.len == ush.len) {
                        if (ngx_strncmp(us[j].addrs->name.data, ush.data, ush.len) == 0) {
                            *usn = us[j];

#if nginx_version > 1007001
                            usn->name = us[j].addrs->name;
#endif

                            control->count++;
                            break;
                        }
                    }
                }

                break;
            }
        }
    }
}


static void
ngx_http_vhost_traffic_status_node_control_range_set(
    ngx_http_vhost_traffic_status_control_t *control)
{
    ngx_uint_t  state;

    if (control->group == -1) {
        state = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL;

    } else {
        state = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE;

        if (control->zone->len == 0) {
            state = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_NONE;

        } else if (control->zone->len == 1) {
            if(ngx_strncmp(control->zone->data, "*", 1) == 0) {
                state = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP;
            }
        }
    }

    control->range = state;
}


static void
ngx_http_vhost_traffic_status_node_status_all(
    ngx_http_vhost_traffic_status_control_t *control)
{
    *control->buf = ngx_http_vhost_traffic_status_display_set(control->r, *control->buf);
}


static void
ngx_http_vhost_traffic_status_node_status_group(
    ngx_http_vhost_traffic_status_control_t *control)
{
    u_char                               *o, *s;
    ngx_str_t                             key;
    ngx_rbtree_node_t                    *node;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = ngx_http_get_module_main_conf(control->r, ngx_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;

    *control->buf = ngx_sprintf(*control->buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);

    o = s = *control->buf;

    switch(control->group) {
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO:
        *control->buf = ngx_sprintf(*control->buf,
                                    NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S);
        s = *control->buf;
        *control->buf = ngx_http_vhost_traffic_status_display_set_server(
                            control->r, *control->buf, node);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
        ngx_str_set(&key, "::nogroups");
        *control->buf = ngx_sprintf(*control->buf,
                                    NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S, &key);
        s = *control->buf;
        *control->buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(
                            control->r, *control->buf, node);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:
        *control->buf = ngx_sprintf(*control->buf,
                                    NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S);
        s = *control->buf;
        *control->buf = ngx_http_vhost_traffic_status_display_set_upstream_group(
                            control->r, *control->buf);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
        *control->buf = ngx_sprintf(*control->buf,
                                    NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE_S);
        s = *control->buf;
        *control->buf = ngx_http_vhost_traffic_status_display_set_cache(
                            control->r, *control->buf, node);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG:
        *control->buf = ngx_sprintf(*control->buf,
                                    NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER_S);
        s = *control->buf;
        *control->buf = ngx_http_vhost_traffic_status_display_set_filter(
                            control->r, *control->buf, node);
        break;
    }

    if (s == *control->buf) {
        *control->buf = o;

    } else {
        (*control->buf)--;

        if (control->group == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA) {
            *control->buf = ngx_sprintf(*control->buf,
                                        NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);

        } else {
            *control->buf = ngx_sprintf(*control->buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
        }

        control->count++;
    }

    *control->buf = ngx_sprintf(*control->buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
}


static void
ngx_http_vhost_traffic_status_node_status_zone(
    ngx_http_vhost_traffic_status_control_t *control)
{
    u_char                                *o;
    uint32_t                               hash;
    ngx_int_t                              rc;
    ngx_str_t                              key, dst;
    ngx_rbtree_node_t                     *node;
    ngx_http_upstream_server_t             us;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(control->r, ngx_http_vhost_traffic_status_module);

    rc = ngx_http_vhost_traffic_status_node_generate_key(control->r->pool, &key, control->zone,
                                                         control->group);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, control->r->connection->log, 0,
                      "node_status_zone::node_generate_key(\"%V\") failed", &key);
        return;
    }

    hash = ngx_crc32_short(key.data, key.len);
    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

    if (node == NULL) {
        return;
    }

    vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

    if (control->group != NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG
        && control->group != NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA)
    {
        *control->buf = ngx_sprintf(*control->buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);

        o = *control->buf;

    } else {
        o = *control->buf;
    }

    dst.data = vtsn->data;
    dst.len = vtsn->len;

    switch (control->group) {

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO:
        *control->buf = ngx_http_vhost_traffic_status_display_set_server_node(control->r,
                            *control->buf, &key, vtsn);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:
        ngx_http_vhost_traffic_status_node_upstream_lookup(control, &us);
        if (control->count) {
#if nginx_version > 1007001
            *control->buf = ngx_http_vhost_traffic_status_display_set_upstream_node(control->r,
                                *control->buf, &us, vtsn);
#else
            (void) ngx_http_vhost_traffic_status_node_position_key(&dst, 1);
            *control->buf = ngx_http_vhost_traffic_status_display_set_upstream_node(control->r,
                                *control->buf, &us, vtsn, &dst);
#endif
        }
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
        *control->buf = ngx_http_vhost_traffic_status_display_set_cache_node(control->r,
                            *control->buf, vtsn);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG:
        (void) ngx_http_vhost_traffic_status_node_position_key(&dst, 2);
        *control->buf = ngx_http_vhost_traffic_status_display_set_server_node(control->r,
                            *control->buf, &dst, vtsn);
        break;
    }

    if (o != *control->buf) {
        (*control->buf)--;

        if (control->group != NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG
                && control->group != NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA)
        {
            *control->buf = ngx_sprintf(*control->buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
        }

        control->count++;
    }
}


static void
ngx_http_vhost_traffic_status_node_status(
    ngx_http_vhost_traffic_status_control_t *control)
{
    switch (control->range) {

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL:
        ngx_http_vhost_traffic_status_node_status_all(control);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP:
        ngx_http_vhost_traffic_status_node_status_group(control);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE:
        ngx_http_vhost_traffic_status_node_status_zone(control);
        break;
    }
}


static ngx_int_t
ngx_http_vhost_traffic_status_node_delete_get_nodes(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_array_t **nodes, ngx_rbtree_node_t *node)
{
    ngx_int_t                                rc;
    ngx_http_vhost_traffic_status_ctx_t     *ctx;
    ngx_http_vhost_traffic_status_node_t    *vtsn;
    ngx_http_vhost_traffic_status_delete_t  *delete;

    ctx = ngx_http_get_module_main_conf(control->r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if ((ngx_int_t) vtsn->stat_upstream.type == control->group) {

            if (*nodes == NULL) {
                *nodes = ngx_array_create(control->r->pool, 1,
                        sizeof(ngx_http_vhost_traffic_status_delete_t));

                if (*nodes == NULL) {
                    ngx_log_error(NGX_LOG_ERR, control->r->connection->log, 0,
                                  "node_delete_get_nodes::ngx_array_create() failed");
                    return NGX_ERROR;
                }
            }

            delete = ngx_array_push(*nodes);
            if (delete == NULL) {
                ngx_log_error(NGX_LOG_ERR, control->r->connection->log, 0,
                              "node_delete_get_nodes::ngx_array_push() failed");
                return NGX_ERROR;
            }

            delete->node = node;
        }

        rc = ngx_http_vhost_traffic_status_node_delete_get_nodes(control, nodes, node->left);
        if (rc != NGX_OK) {
            return rc;
        }

        rc = ngx_http_vhost_traffic_status_node_delete_get_nodes(control, nodes, node->right);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}


static void
ngx_http_vhost_traffic_status_node_delete_all(
    ngx_http_vhost_traffic_status_control_t *control)
{
    ngx_slab_pool_t                           *shpool;
    ngx_rbtree_node_t                         *node, *sentinel;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(control->r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(control->r, ngx_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;
    sentinel = ctx->rbtree->sentinel;
    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    while (node != sentinel) {

        ngx_rbtree_delete(ctx->rbtree, node);
        ngx_slab_free_locked(shpool, node);

        control->count++;

        node = ctx->rbtree->root;
    }
}


static void
ngx_http_vhost_traffic_status_node_delete_group(
    ngx_http_vhost_traffic_status_control_t *control)
{
    ngx_int_t                                  rc;
    ngx_uint_t                                 n, i;
    ngx_array_t                               *nodes;
    ngx_slab_pool_t                           *shpool;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_delete_t    *deletes;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(control->r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(control->r, ngx_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;
    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    nodes = NULL;

    rc = ngx_http_vhost_traffic_status_node_delete_get_nodes(control, &nodes, node);

    /* not found */
    if (nodes == NULL) {
        return;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, control->r->connection->log, 0,
                      "node_delete_group::node_delete_get_nodes() failed");
        return;
    }

    deletes = nodes->elts;
    n = nodes->nelts;

    for (i = 0; i < n; i++) {
        node = deletes[i].node;

        ngx_rbtree_delete(ctx->rbtree, node);
        ngx_slab_free_locked(shpool, node);

        control->count++;
    }
}


static void
ngx_http_vhost_traffic_status_node_delete_zone(
    ngx_http_vhost_traffic_status_control_t *control)
{
    uint32_t                                   hash;
    ngx_int_t                                  rc;
    ngx_str_t                                  key;
    ngx_slab_pool_t                           *shpool;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(control->r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(control->r, ngx_http_vhost_traffic_status_module);

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    rc = ngx_http_vhost_traffic_status_node_generate_key(control->r->pool, &key, control->zone,
                                                         control->group);
    if (rc != NGX_OK) {
        return;
    }

    hash = ngx_crc32_short(key.data, key.len);
    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

    if (node != NULL) {
        ngx_rbtree_delete(ctx->rbtree, node);
        ngx_slab_free_locked(shpool, node);

        control->count++;
    }
}


static void
ngx_http_vhost_traffic_status_node_delete(
    ngx_http_vhost_traffic_status_control_t *control)
{
    switch (control->range) {

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL:
        ngx_http_vhost_traffic_status_node_delete_all(control);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP:
        ngx_http_vhost_traffic_status_node_delete_group(control);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE:
        ngx_http_vhost_traffic_status_node_delete_zone(control);
        break;
    }

    *control->buf = ngx_sprintf(*control->buf,
                                NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CONTROL,
                                ngx_vhost_traffic_status_boolean_to_string(1),
                                control->arg_cmd, control->arg_group,
                                control->arg_zone, control->count);
}


static void
ngx_http_vhost_traffic_status_node_reset_all(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_rbtree_node_t *node)
{
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(control->r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        ngx_http_vhost_traffic_status_node_zero(vtsn);
        control->count++;

        ngx_http_vhost_traffic_status_node_reset_all(control, node->left);
        ngx_http_vhost_traffic_status_node_reset_all(control, node->right);
    }
}


static void
ngx_http_vhost_traffic_status_node_reset_group(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_rbtree_node_t *node)
{
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(control->r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if ((ngx_int_t) vtsn->stat_upstream.type == control->group) {
            ngx_http_vhost_traffic_status_node_zero(vtsn);
            control->count++;
        }

        ngx_http_vhost_traffic_status_node_reset_group(control, node->left);
        ngx_http_vhost_traffic_status_node_reset_group(control, node->right);
    }
}


static void
ngx_http_vhost_traffic_status_node_reset_zone(
    ngx_http_vhost_traffic_status_control_t *control)
{
    uint32_t                               hash;
    ngx_int_t                              rc;
    ngx_str_t                              key;
    ngx_rbtree_node_t                     *node;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(control->r, ngx_http_vhost_traffic_status_module);

    rc = ngx_http_vhost_traffic_status_node_generate_key(control->r->pool, &key, control->zone,
                                                         control->group);
    if (rc != NGX_OK) {
        return;
    }

    hash = ngx_crc32_short(key.data, key.len);
    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

    if (node != NULL) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
        ngx_http_vhost_traffic_status_node_zero(vtsn);
        control->count++;
    }
}


static void
ngx_http_vhost_traffic_status_node_reset(
    ngx_http_vhost_traffic_status_control_t *control)
{
    ngx_rbtree_node_t                    *node;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = ngx_http_get_module_main_conf(control->r, ngx_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;

    switch (control->range) {

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL:
        ngx_http_vhost_traffic_status_node_reset_all(control, node);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP:
        ngx_http_vhost_traffic_status_node_reset_group(control, node);
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE:
        ngx_http_vhost_traffic_status_node_reset_zone(control);
        break;
    }

    *control->buf = ngx_sprintf(*control->buf,
                                NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CONTROL,
                                ngx_vhost_traffic_status_boolean_to_string(1),
                                control->arg_cmd, control->arg_group,
                                control->arg_zone, control->count);
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
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_filter_get_keys(ngx_http_request_t *r,
    ngx_array_t **filter_keys, ngx_rbtree_node_t *node)
{
    ngx_int_t                                    rc;
    ngx_str_t                                    key;
    ngx_http_vhost_traffic_status_ctx_t         *ctx;
    ngx_http_vhost_traffic_status_node_t        *vtsn;
    ngx_http_vhost_traffic_status_filter_key_t  *keys;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            rc = ngx_http_vhost_traffic_status_node_position_key(&key, 1);
            if (rc != NGX_OK) {
                goto next;
            }

            if (*filter_keys == NULL) {
                *filter_keys = ngx_array_create(r->pool, 1,
                                  sizeof(ngx_http_vhost_traffic_status_filter_key_t));

                if (*filter_keys == NULL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "filter_get_keys::ngx_array_create() failed");
                    return NGX_ERROR;
                }
            }

            keys = ngx_array_push(*filter_keys);
            if (keys == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "filter_get_keys::ngx_array_push() failed");
                return NGX_ERROR;
            }

            keys->key.len = key.len;
            /* 1 byte for terminating '\0' for ngx_strcmp() */
            keys->key.data = ngx_pcalloc(r->pool, key.len + 1);
            if (keys->key.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "filter_get_keys::ngx_pcalloc() failed");
            }

            ngx_memcpy(keys->key.data, key.data, key.len);
        }
next:
        rc = ngx_http_vhost_traffic_status_filter_get_keys(r, filter_keys, node->left);
        if (rc != NGX_OK) {
            return rc;
        }

        rc = ngx_http_vhost_traffic_status_filter_get_keys(r, filter_keys, node->right);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_filter_get_nodes(ngx_http_request_t *r,
    ngx_array_t **filter_nodes, ngx_str_t *name,
    ngx_rbtree_node_t *node)
{
    ngx_int_t                                     rc;
    ngx_str_t                                     key;
    ngx_http_vhost_traffic_status_ctx_t          *ctx;
    ngx_http_vhost_traffic_status_node_t         *vtsn;
    ngx_http_vhost_traffic_status_filter_node_t  *nodes;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            rc = ngx_http_vhost_traffic_status_node_position_key(&key, 1);
            if (rc != NGX_OK) {
                goto next;
            }

            if (name->len != key.len) {
                goto next;
            }

            if (ngx_strncmp(name->data, key.data, key.len) != 0) {
                goto next;
            }

            if (*filter_nodes == NULL) {
                *filter_nodes = ngx_array_create(r->pool, 1,
                                    sizeof(ngx_http_vhost_traffic_status_filter_node_t));

                if (*filter_nodes == NULL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "filter_get_nodes::ngx_array_create() failed");
                    return NGX_ERROR;
                }
            }

            nodes = ngx_array_push(*filter_nodes);
            if (nodes == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "filter_get_nodes::ngx_array_push() failed");
                return NGX_ERROR;
            }

            nodes->node = vtsn;
        }
next:
        rc = ngx_http_vhost_traffic_status_filter_get_nodes(r, filter_nodes, name, node->left);
        if (rc != NGX_OK) {
            return rc;
        }

        rc = ngx_http_vhost_traffic_status_filter_get_nodes(r, filter_nodes, name, node->right);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_limit_traffic_unique(ngx_pool_t *pool, ngx_array_t **keys)
{
    uint32_t                                      hash;
    u_char                                       *p;
    ngx_str_t                                     key;
    ngx_uint_t                                    i, n;
    ngx_array_t                                  *uniqs, *traffic_keys;
    ngx_http_vhost_traffic_status_limit_t        *traffic, *traffics;
    ngx_http_vhost_traffic_status_filter_uniq_t  *traffic_uniqs;

    if (*keys == NULL) {
        return NGX_OK;
    }

    uniqs = ngx_array_create(pool, 1,
                             sizeof(ngx_http_vhost_traffic_status_filter_uniq_t));
    if (uniqs == NULL) {
        return NGX_ERROR;
    }

    /* init array */
    traffic_keys = NULL;
    traffic_uniqs = NULL;

    traffics = (*keys)->elts;
    n = (*keys)->nelts;

    for (i = 0; i < n; i++) {
        key.len = traffics[i].key.value.len
                  + traffics[i].variable.value.len;
        key.data = ngx_pcalloc(pool, key.len);
        if (key.data == NULL) {
            return NGX_ERROR;
        }

        p = key.data;
        p = ngx_cpymem(p, traffics[i].key.value.data,
                       traffics[i].key.value.len);
        ngx_memcpy(p, traffics[i].variable.value.data,
                   traffics[i].variable.value.len);
        hash = ngx_crc32_short(key.data, key.len);

        traffic_uniqs = ngx_array_push(uniqs);
        if (traffic_uniqs == NULL) {
            return NGX_ERROR;
        }

        traffic_uniqs->hash = hash;
        traffic_uniqs->index = i;

        if (p != NULL) {
            ngx_pfree(pool, key.data);
        }
    }

    traffic_uniqs = uniqs->elts;
    n = uniqs->nelts;

    ngx_qsort(traffic_uniqs, (size_t) n,
              sizeof(ngx_http_vhost_traffic_status_filter_uniq_t),
              ngx_http_traffic_status_filter_cmp_hashs);

    hash = 0;
    for (i = 0; i < n; i++) {
        if (traffic_uniqs[i].hash == hash) {
            continue;
        }

        hash = traffic_uniqs[i].hash;

        if (traffic_keys == NULL) {
            traffic_keys = ngx_array_create(pool, 1,
                                            sizeof(ngx_http_vhost_traffic_status_limit_t));
            if (traffic_keys == NULL) {
                return NGX_ERROR;
            }
        }

        traffic = ngx_array_push(traffic_keys);
        if (traffic == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(traffic, &traffics[traffic_uniqs[i].index],
                   sizeof(ngx_http_vhost_traffic_status_limit_t));

    }

    if ((*keys)->nelts != traffic_keys->nelts) {
        *keys = traffic_keys;
    }

    return NGX_OK;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_main(ngx_http_request_t *r,
    u_char *buf)
{
    ngx_time_t                                *tp;
    ngx_msec_t                                 now;
    ngx_atomic_int_t                           ap, hn, ac, rq, rd, wr, wa;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;
    wa = *ngx_stat_waiting;

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_MAIN, NGINX_VERSION,
                      vtscf->start_msec, now, ac, rd, wr, wa, ap, hn, rq);

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_server_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_int_t  rc;
    ngx_str_t  tmp, dst;

    tmp = *key;

    (void) ngx_http_vhost_traffic_status_node_position_key(&tmp, 1);

    rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &dst, &tmp);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_set_server_node::escape_json_pool() failed");
    }

#if (NGX_HTTP_CACHE)
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER,
                      &dst, vtsn->stat_request_counter,
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
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER,
                      key, vtsn->stat_request_counter,
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

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_server(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_str_t                                  key;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_node_t      *vtsn, ovtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            ovtsn = vtscf->stats;

            buf = ngx_http_vhost_traffic_status_display_set_server_node(r, buf, &key, vtsn);

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
        }

        buf = ngx_http_vhost_traffic_status_display_set_server(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_display_set_server(r, buf, node->right);
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_filter_node(ngx_http_request_t *r,
    u_char *buf, ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_str_t   key;

    key.data = vtsn->data;
    key.len = vtsn->len;

    (void) ngx_http_vhost_traffic_status_node_position_key(&key, 2);

    return ngx_http_vhost_traffic_status_display_set_server_node(r, buf, &key, vtsn);
}


static u_char *
ngx_http_vhost_traffic_status_display_set_filter(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_str_t                                     key;
    ngx_uint_t                                    i, j, n, rc;
    ngx_array_t                                  *filter_keys, *filter_nodes;
    ngx_http_vhost_traffic_status_filter_key_t   *keys;
    ngx_http_vhost_traffic_status_filter_node_t  *nodes;

    /* init array */
    filter_keys = NULL;
    filter_nodes = NULL;

    rc = ngx_http_vhost_traffic_status_filter_get_keys(r, &filter_keys, node);

    if (filter_keys != NULL && rc == NGX_OK) {
        keys = filter_keys->elts;
        n = filter_keys->nelts;

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

            rc = ngx_http_vhost_traffic_status_filter_get_nodes(r, &filter_nodes, &key, node);

            if (filter_nodes != NULL && rc == NGX_OK) {
                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_S,
                                  &keys[i].key);

                nodes = filter_nodes->elts;
                for (j = 0; j < filter_nodes->nelts; j++) {
                    buf = ngx_http_vhost_traffic_status_display_set_filter_node(r, buf,
                              nodes[j].node);
                }

                buf--;
                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_E);
                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);

                /* destory array to prevent duplication */
                if (filter_nodes != NULL) {
                    filter_nodes = NULL;
                }
            }

        }

        /* destory array */
        for (i = 0; i < n; i++) {
             if (keys[i].key.data != NULL) {
                 ngx_pfree(r->pool, keys[i].key.data);
             }
        }
        if (filter_keys != NULL) {
            filter_keys = NULL;
        }
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_upstream_node(ngx_http_request_t *r,
     u_char *buf, ngx_http_upstream_server_t *us,
#if nginx_version > 1007001
     ngx_http_vhost_traffic_status_node_t *vtsn
#else
     ngx_http_vhost_traffic_status_node_t *vtsn, ngx_str_t *name
#endif
     )
{
    ngx_int_t  rc;
    ngx_str_t  key;

#if nginx_version > 1007001
    rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &key, &us->name);
#else
    rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &key, name);
#endif

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_set_upstream_node::escape_json_pool() failed");
    }

    if (vtsn != NULL) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM,
                &key, vtsn->stat_request_counter,
                vtsn->stat_in_bytes, vtsn->stat_out_bytes,
                vtsn->stat_1xx_counter, vtsn->stat_2xx_counter,
                vtsn->stat_3xx_counter, vtsn->stat_4xx_counter,
                vtsn->stat_5xx_counter, vtsn->stat_upstream.rtms,
                us->weight, us->max_fails,
                us->fail_timeout,
                ngx_vhost_traffic_status_boolean_to_string(us->backup),
                ngx_vhost_traffic_status_boolean_to_string(us->down),
                ngx_vhost_traffic_status_max_integer,
                vtsn->stat_request_counter_oc, vtsn->stat_in_bytes_oc,
                vtsn->stat_out_bytes_oc, vtsn->stat_1xx_counter_oc,
                vtsn->stat_2xx_counter_oc, vtsn->stat_3xx_counter_oc,
                vtsn->stat_4xx_counter_oc, vtsn->stat_5xx_counter_oc);

    } else {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM,
                &key, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_msec_t) 0,
                us->weight, us->max_fails,
                us->fail_timeout,
                ngx_vhost_traffic_status_boolean_to_string(us->backup),
                ngx_vhost_traffic_status_boolean_to_string(us->down),
                ngx_vhost_traffic_status_max_integer,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0);
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_upstream_alone(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    unsigned                               type;
    ngx_str_t                              key;
    ngx_http_upstream_server_t             us;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == type) {
            key.len = vtsn->len;
            key.data = vtsn->data;

            (void) ngx_http_vhost_traffic_status_node_position_key(&key, 1);

#if nginx_version > 1007001
            us.name = key;
#endif
            us.weight = 0;
            us.max_fails = 0;
            us.fail_timeout = 0;
            us.down = 0;
            us.backup = 0;

#if nginx_version > 1007001
            buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &us, vtsn);
#else
            buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &us, vtsn, &key);
#endif
        }

        buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(r, buf, node->right);
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_upstream_group(ngx_http_request_t *r,
    u_char *buf)
{
    size_t                                 len;
    u_char                                *p, *o, *s;
    uint32_t                               hash;
    unsigned                               type, zone;
    ngx_int_t                              rc;
    ngx_str_t                              key, dst;
    ngx_uint_t                             i, j;
    ngx_rbtree_node_t                     *node;
    ngx_http_upstream_server_t            *us, usn;
#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_http_upstream_rr_peer_t           *peer;
    ngx_http_upstream_rr_peers_t          *peers;
#endif
    ngx_http_upstream_srv_conf_t          *uscf, **uscfp;
    ngx_http_upstream_main_conf_t         *umcf;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    len = 0;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];
        len = ngx_max(uscf->host.len, len);
    }

    dst.len = len + sizeof("@[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535") - 1;
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return buf;
    }

    p = dst.data;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        /* groups */
        if (uscf->servers && !uscf->port) {
            us = uscf->servers->elts;

            type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;

            o = buf;

            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S,
                              &uscf->host);
            s = buf;

            zone = 0;

#if (NGX_HTTP_UPSTREAM_ZONE)
            if (uscf->shm_zone == NULL) {
                goto not_supported;
            }

            zone = 1;

            peers = uscf->peer.data;

            ngx_http_upstream_rr_peers_rlock(peers);

            for (peer = peers->peer; peer ; peer = peer->next) {
                p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
                *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
                p = ngx_cpymem(p, peer->name.data, peer->name.len);

                dst.len = uscf->host.len + sizeof("@") - 1 + peer->name.len;

                rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
                if (rc != NGX_OK) {
                    ngx_http_upstream_rr_peers_unlock(peers);
                    return buf;
                }

                hash = ngx_crc32_short(key.data, key.len);
                node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

                usn.weight = peer->weight;
                usn.max_fails = peer->max_fails;
                usn.fail_timeout = peer->fail_timeout;
                usn.backup = 0;
                usn.down = peer->down;

#if nginx_version > 1007001
                usn.name = peer->name;
#endif

                if (node != NULL) {
                    vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
#if nginx_version > 1007001
                    buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn);
#else
                    buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn, &peer->name);
#endif

                } else {
#if nginx_version > 1007001
                    buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL);
#else
                    buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL, &peer->name);
#endif
                }

                p = dst.data;
            }

            ngx_http_upstream_rr_peers_unlock(peers);

not_supported:

#endif

            for (j = 0; j < uscf->servers->nelts; j++) {
                usn = us[j];

                if (zone && usn.backup != 1) {
                    continue;
                }

                p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
                *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
                p = ngx_cpymem(p, us[j].addrs->name.data, us[j].addrs->name.len);

                dst.len = uscf->host.len + sizeof("@") - 1 + us[j].addrs->name.len;

                rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
                if (rc != NGX_OK) {
                    return buf;
                }

                hash = ngx_crc32_short(key.data, key.len);
                node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

#if nginx_version > 1007001
                usn.name = us[j].addrs->name;
#endif

                if (node != NULL) {
                    vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
#if nginx_version > 1007001
                    buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn);
#else
                    buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn, &us[j].addrs->name);
#endif

                } else {
#if nginx_version > 1007001
                    buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL);
#else
                    buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL, &us[j].addrs->name);
#endif
                }

                p = dst.data;
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

    buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(r, buf, ctx->rbtree->root);

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

static u_char
*ngx_http_vhost_traffic_status_display_set_cache_node(ngx_http_request_t *r,
    u_char *buf, ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_int_t  rc;
    ngx_str_t  key, dst;

    dst.data = vtsn->data;
    dst.len = vtsn->len;

    (void) ngx_http_vhost_traffic_status_node_position_key(&dst, 1);

    rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &key, &dst);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_set_cache_node::escape_json_pool() failed");
    }

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE,
                      &key, vtsn->stat_cache_max_size,
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

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_cache(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC) {
            buf = ngx_http_vhost_traffic_status_display_set_cache_node(r, buf, vtsn);
        }

        buf = ngx_http_vhost_traffic_status_display_set_cache(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_display_set_cache(r, buf, node->right);
    }

    return buf;
}

#endif


static u_char *
ngx_http_vhost_traffic_status_display_set(ngx_http_request_t *r,
    u_char *buf)
{
    u_char                                    *o, *s;
    ngx_str_t                                  stats;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;

    ngx_memzero(&vtscf->stats, sizeof(vtscf->stats));

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);

    /* main & connections */
    buf = ngx_http_vhost_traffic_status_display_set_main(r, buf);

    /* serverZones */
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S);

    buf = ngx_http_vhost_traffic_status_display_set_server(r, buf, node);

    ngx_str_set(&stats, "*");

    buf = ngx_http_vhost_traffic_status_display_set_server_node(r, buf, &stats,
                                                                &vtscf->stats);

    buf--;
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);

    /* filterZones */
    ngx_memzero(&vtscf->stats, sizeof(vtscf->stats));

    o = buf;

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER_S);

    s = buf;

    buf = ngx_http_vhost_traffic_status_display_set_filter(r, buf, node);

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

    buf = ngx_http_vhost_traffic_status_display_set_upstream_group(r, buf);

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

    buf = ngx_http_vhost_traffic_status_display_set_cache(r, buf, node);

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
ngx_http_vhost_traffic_status_limit_traffic(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    u_char                                 *p;
    off_t                                   size;
    ngx_str_t                              *value, s;
    ngx_array_t                            *limit_traffics;
    ngx_http_compile_complex_value_t        ccv;
    ngx_http_vhost_traffic_status_ctx_t    *ctx;
    ngx_http_vhost_traffic_status_limit_t  *traffic;

    ctx = ngx_http_conf_get_module_main_conf(cf, ngx_http_vhost_traffic_status_module);
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "limit_traffic() empty value pattern");
        return NGX_CONF_ERROR;
    }

    if (value[1].len > 5 && ngx_strstrn(value[1].data, "$vts_", 5 - 1)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "limit_traffic() $vts_* is not allowed here");
        return NGX_CONF_ERROR;
    }

    p = (u_char *) ngx_strchr(value[1].data, ':');
    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "limit_traffic() empty size pattern");
        return NGX_CONF_ERROR;
    }

    s.data = p + 1;
    s.len = value[1].data + value[1].len - s.data;

    size = ngx_parse_offset(&s);
    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "limit_traffic() invalid limit size \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    limit_traffics = (cf->cmd_type == NGX_HTTP_MAIN_CONF)
                     ? ctx->limit_traffics
                     : vtscf->limit_traffics;
    if (limit_traffics == NULL) {
        limit_traffics = ngx_array_create(cf->pool, 1,
                                          sizeof(ngx_http_vhost_traffic_status_limit_t));
        if (limit_traffics == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    traffic = ngx_array_push(limit_traffics);
    if (traffic == NULL) {
        return NGX_CONF_ERROR;
    }

    value[1].len = p - value[1].data;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &traffic->variable;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    traffic->size = (ngx_atomic_t) size;

    traffic->code = (cf->args->nelts == 3)
                    ? (ngx_uint_t) ngx_atoi(value[2].data, value[2].len)
                    : NGX_HTTP_SERVICE_UNAVAILABLE;

    traffic->type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

    traffic->key.value.len = 0;

    if (cf->cmd_type == NGX_HTTP_MAIN_CONF) {
        ctx->limit_traffics = limit_traffics;

    } else {
        vtscf->limit_traffics = limit_traffics;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_vhost_traffic_status_limit_traffic_by_set_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    u_char                                 *p;
    off_t                                   size;
    ngx_str_t                              *value, s, alpha;
    ngx_array_t                            *limit_traffics;
    ngx_http_compile_complex_value_t        ccv;
    ngx_http_vhost_traffic_status_ctx_t    *ctx;
    ngx_http_vhost_traffic_status_limit_t  *traffic;

    ctx = ngx_http_conf_get_module_main_conf(cf, ngx_http_vhost_traffic_status_module);
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "limit_traffic_by_set_key() empty key pattern");
        return NGX_CONF_ERROR;
    }

    if (value[2].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "limit_traffic_by_set_key() empty value pattern");
        return NGX_CONF_ERROR;
    }

    if (value[2].len > 5 && ngx_strstrn(value[2].data, "$vts_", 5 - 1)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "limit_traffic_by_set_key() $vts_* is not allowed here");
        return NGX_CONF_ERROR;
    }

    p = (u_char *) ngx_strchr(value[2].data, ':');
    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "limit_traffic_by_set_key() empty size pattern");
        return NGX_CONF_ERROR;
    }

    s.data = p + 1;
    s.len = value[2].data + value[2].len - s.data;

    size = ngx_parse_offset(&s);
    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "limit_traffic_by_set_key() invalid limit size \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    limit_traffics = (cf->cmd_type == NGX_HTTP_MAIN_CONF)
                     ? ctx->limit_filter_traffics
                     : vtscf->limit_filter_traffics;
    if (limit_traffics == NULL) {
        limit_traffics = ngx_array_create(cf->pool, 1,
                                          sizeof(ngx_http_vhost_traffic_status_limit_t));
        if (limit_traffics == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    traffic = ngx_array_push(limit_traffics);
    if (traffic == NULL) {
        return NGX_CONF_ERROR;
    }

    /* set key to be limited */
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    (void) ngx_http_vhost_traffic_status_replace_chrc(&value[1], '@',
                                                      NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR);
    ngx_str_set(&alpha, "[:alpha:]");
    if (ngx_http_vhost_traffic_status_replace_strc(&value[1], &alpha, '@') != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "limit_traffic_by_set_key()::replace_strc() failed");
    }

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &traffic->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* set member to be limited */
    value[2].len = p - value[2].data;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &traffic->variable;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    traffic->size = (ngx_atomic_t) size;

    traffic->code = (cf->args->nelts == 4)
                    ? (ngx_uint_t) ngx_atoi(value[3].data, value[3].len)
                    : NGX_HTTP_SERVICE_UNAVAILABLE;

    traffic->type = ngx_vhost_traffic_status_string_to_group(value[1].data);

    if (cf->cmd_type == NGX_HTTP_MAIN_CONF) {
        ctx->limit_filter_traffics = limit_traffics;

    } else {
        vtscf->limit_filter_traffics = limit_traffics;
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


static ngx_int_t
ngx_http_vhost_traffic_status_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_vhost_traffic_status_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
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
    ctx->limit_check_duplicate = NGX_CONF_UNSET;

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
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "init_main_conf::filter_unique() failed");
        }
    }

    if (vtscf->limit_check_duplicate != 0) {
        rc = ngx_http_vhost_traffic_status_limit_traffic_unique(cf->pool, &ctx->limit_traffics);
        if (rc != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "init_main_conf::limit_traffic_unique(server) failed");
        }

        rc = ngx_http_vhost_traffic_status_limit_traffic_unique(cf->pool,
                                                                &ctx->limit_filter_traffics);
        if (rc != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "init_main_conf::limit_traffic_unique(filter) failed");
        }
    }

    ngx_conf_init_value(ctx->enable, 0);
    ngx_conf_init_value(ctx->filter_check_duplicate, vtscf->filter_check_duplicate);
    ngx_conf_init_value(ctx->limit_check_duplicate, vtscf->limit_check_duplicate);

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
    conf->limit = NGX_CONF_UNSET;
    conf->limit_check_duplicate = NGX_CONF_UNSET;
    conf->shm_zone = NGX_CONF_UNSET_PTR;
    conf->format = NGX_CONF_UNSET;

    conf->node_caches = ngx_pcalloc(cf->pool, sizeof(ngx_rbtree_node_t *)
                                    * (NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG + 1));
    conf->node_caches[NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO] = NULL;
    conf->node_caches[NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA] = NULL;
    conf->node_caches[NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG] = NULL;
    conf->node_caches[NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC] = NULL;
    conf->node_caches[NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG] = NULL;

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
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "mere_loc_conf::filter_unique() failed");
            }
        }
    }

    if (conf->limit_traffics == NULL) {
        conf->limit_traffics = prev->limit_traffics;

    } else {
        if (conf->limit_check_duplicate == NGX_CONF_UNSET) {
            conf->limit_check_duplicate = ctx->limit_check_duplicate;
        }

        if (conf->limit_check_duplicate != 0) {
            rc = ngx_http_vhost_traffic_status_limit_traffic_unique(cf->pool,
                                                                    &conf->limit_traffics);
            if (rc != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "mere_loc_conf::limit_traffic_unique(server) failed");
            }
        }
    }

    if (conf->limit_filter_traffics == NULL) {
        conf->limit_filter_traffics = prev->limit_filter_traffics;

    } else {
        if (conf->limit_check_duplicate == NGX_CONF_UNSET) {
            conf->limit_check_duplicate = ctx->limit_check_duplicate;
        }

        if (conf->limit_check_duplicate != 0) {
            rc = ngx_http_vhost_traffic_status_limit_traffic_unique(cf->pool,
                                                                    &conf->limit_filter_traffics);
            if (rc != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "mere_loc_conf::limit_traffic_unique(filter) failed");
            }
        }
    }

    ngx_conf_merge_value(conf->enable, prev->enable, 1);
    ngx_conf_merge_value(conf->filter, prev->filter, 1);
    ngx_conf_merge_value(conf->filter_host, prev->filter_host, 0);
    ngx_conf_merge_value(conf->filter_check_duplicate, prev->filter_check_duplicate, 1);
    ngx_conf_merge_value(conf->limit, prev->limit, 1);
    ngx_conf_merge_value(conf->limit_check_duplicate, prev->limit_check_duplicate, 1);
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

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_vhost_traffic_status_limit_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_vhost_traffic_status_handler;

    return NGX_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
