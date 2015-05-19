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
    "\"loadMsec\":%M," \
    "\"nowMsec\":%M," \
    "\"connections\":{" \
    "\"active\":%uA," \
    "\"reading\":%uA," \
    "\"writing\":%uA," \
    "\"waiting\":%uA," \
    "\"accepted\":%uA," \
    "\"handled\":%uA," \
    "\"requests\":%uA" \
    "},"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S "\"serverZones\":{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER "\"%s\":{" \
    "\"requestCounter\":%uA," \
    "\"inBytes\":%uA," \
    "\"outBytes\":%uA," \
    "\"responses\":{" \
    "\"1xx\":%uA," \
    "\"2xx\":%uA," \
    "\"3xx\":%uA," \
    "\"4xx\":%uA," \
    "\"5xx\":%uA" \
    "}" \
    "},"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S "\"upstreamZones\":{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM "{\"server\":\"%V\"," \
    "\"requestCounter\":%uA," \
    "\"inBytes\":%uA," \
    "\"outBytes\":%uA," \
    "\"responses\":{" \
    "\"1xx\":%uA," \
    "\"2xx\":%uA," \
    "\"3xx\":%uA," \
    "\"4xx\":%uA," \
    "\"5xx\":%uA" \
    "}," \
    "\"responeMsec\":%M," \
    "\"weight\":%ui," \
    "\"maxFails\":%ui," \
    "\"failTimeout\":%T," \
    "\"backup\":%s," \
    "\"down\":%s" \
    "},"

#define ngx_vhost_traffic_status_add_rc(s, n) { \
    if(s < 200) {n->stat_1xx_counter++;} \
    else if(s < 300) {n->stat_2xx_counter++;} \
    else if(s < 400) {n->stat_3xx_counter++;} \
    else if(s < 500) {n->stat_4xx_counter++;} \
    else {n->stat_5xx_counter++;} \
}

#define ngx_vhost_traffic_status_boolean_to_string(b) (b) ? "true" : "false"


typedef struct {
    ngx_rbtree_t    *rbtree;
    ngx_flag_t      enable;
    ngx_str_t       shm_name;
    ssize_t         shm_size;
} ngx_http_vhost_traffic_status_ctx_t;


typedef struct {
    unsigned    type:3;
    ngx_msec_t  rtms;
} ngx_http_vhost_traffic_status_node_upstream_t;


typedef struct {
    u_char                                          color;
    ngx_atomic_t                                    stat_request_counter;
    ngx_atomic_t                                    stat_in_bytes;
    ngx_atomic_t                                    stat_out_bytes;
    ngx_atomic_t                                    stat_1xx_counter;
    ngx_atomic_t                                    stat_2xx_counter;
    ngx_atomic_t                                    stat_3xx_counter;
    ngx_atomic_t                                    stat_4xx_counter;
    ngx_atomic_t                                    stat_5xx_counter;
    ngx_http_vhost_traffic_status_node_upstream_t   stat_upstream;
    u_short                                         len;
    u_char                                          data[1];
} ngx_http_vhost_traffic_status_node_t;


typedef struct {
    ngx_shm_zone_t                          *shm_zone;
    ngx_flag_t                              enable;
    ngx_str_t                               shm_name;
    ngx_http_vhost_traffic_status_node_t    stats;
    ngx_msec_t                              start_msec;
    ngx_str_t                               display;
    ngx_flag_t                              format;
    ngx_http_vhost_traffic_status_node_t    *vtsn_server;
    ngx_http_vhost_traffic_status_node_t    *vtsn_upstream;
    uint32_t                                vtsn_hash;
} ngx_http_vhost_traffic_status_loc_conf_t;

#if !defined(nginx_version) || nginx_version < 1007009
uintptr_t ngx_http_vhost_traffic_status_escape_json(u_char *dst, u_char *src, size_t size);
#endif

static ngx_int_t ngx_http_vhost_traffic_status_shm_add_server(ngx_http_request_t *r,
        ngx_http_vhost_traffic_status_ctx_t *ctx, ngx_http_core_srv_conf_t *cscf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static ngx_int_t ngx_http_vhost_traffic_status_shm_add_upstream(ngx_http_request_t *r,
        ngx_http_vhost_traffic_status_ctx_t *ctx, ngx_http_core_srv_conf_t *cscf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf);

static ngx_rbtree_node_t *ngx_http_vhost_traffic_status_node_lookup(ngx_rbtree_t *rbtree,
        ngx_str_t *key, uint32_t hash);
static void ngx_vhost_traffic_status_node_init(ngx_http_request_t *r,
        ngx_http_vhost_traffic_status_node_t *vtsn);
static void ngx_vhost_traffic_status_node_set(ngx_http_request_t *r,
        ngx_http_vhost_traffic_status_node_t *vtsn);

static u_char *ngx_http_vhost_traffic_status_display_set_main(const char *fmt,
        u_char *buf, ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static u_char *ngx_http_vhost_traffic_status_display_set_server(ngx_http_request_t *r,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, const char *fmt, u_char *buf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static u_char *ngx_http_vhost_traffic_status_display_set_upstream_alone(ngx_http_request_t *r,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, const char *fmt, u_char *buf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static u_char *ngx_http_vhost_traffic_status_display_set_upstream_group(ngx_http_request_t *r,
        ngx_rbtree_t *rbtree, const char *fmt, u_char *buf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf);
static u_char *ngx_http_vhost_traffic_status_display_set(ngx_http_request_t *r,
        ngx_rbtree_t *rbtree, u_char *buf, ngx_http_vhost_traffic_status_loc_conf_t *vtscf);

static char *ngx_http_vhost_traffic_status_display(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_http_vhost_traffic_status_zone(ngx_conf_t *cf, ngx_command_t *cmd,
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

/* from src/core/ngx_string.c in v1.7.9 */
#if !defined(nginx_version) || nginx_version < 1007009
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
    ngx_int_t                                   rc;
    ngx_http_vhost_traffic_status_ctx_t         *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t    *vtscf;
    ngx_http_core_srv_conf_t                    *cscf;

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

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_server(ngx_http_request_t *r,
        ngx_http_vhost_traffic_status_ctx_t *ctx,
        ngx_http_core_srv_conf_t *cscf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    size_t                                      size;
    uint32_t                                    hash;
    ngx_str_t                                   key;
    ngx_slab_pool_t                             *shpool;
    ngx_rbtree_node_t                           *node;
    ngx_http_vhost_traffic_status_node_t        *vtsn;

    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    if (vtscf->vtsn_server) {
        ngx_shmtx_lock(&shpool->mutex);

        ngx_vhost_traffic_status_node_set(r, vtscf->vtsn_server);

        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;
    }

    key = cscf->server_name;
    if (key.len == 0) {
        key.len = 1;
        key.data = (u_char *) "_";
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
        ngx_memcpy(vtsn->data, key.data, key.len);
        ngx_rbtree_insert(ctx->rbtree, node);
    } else {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
        ngx_vhost_traffic_status_node_set(r, vtsn);
    }

    vtscf->vtsn_server = vtsn;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_upstream(ngx_http_request_t *r,
        ngx_http_vhost_traffic_status_ctx_t *ctx,
        ngx_http_core_srv_conf_t *cscf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    u_char                                      *p;
    size_t                                      size;
    uint32_t                                    hash;
    ngx_uint_t                                  i;
    ngx_msec_int_t                              ms;
    ngx_str_t                                   *host, key;
    ngx_slab_pool_t                             *shpool;
    ngx_rbtree_node_t                           *node;
    ngx_http_vhost_traffic_status_node_t        *vtsn;
    ngx_http_upstream_srv_conf_t                *uscf, **uscfp;
    ngx_http_upstream_main_conf_t               *umcf;
    ngx_http_upstream_t                         *u;
    ngx_http_upstream_state_t                   *state;

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

        vtscf->vtsn_upstream->stat_upstream.rtms = (ngx_msec_t) (vtscf->vtsn_upstream->stat_upstream.rtms + ms) / 2 +
            (vtscf->vtsn_upstream->stat_upstream.rtms + ms) % 2;

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
        vtsn->stat_upstream.type = uscf->port ?
            NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA :
            NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;

        ngx_memcpy(vtsn->data, key.data, key.len);
        ngx_rbtree_insert(ctx->rbtree, node);
    } else {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        ngx_vhost_traffic_status_node_set(r, vtsn);

        vtsn->stat_upstream.rtms = (ngx_msec_t) (vtsn->stat_upstream.rtms + ms) / 2 +
            (vtsn->stat_upstream.rtms + ms) % 2;
    }

    vtscf->vtsn_upstream = vtsn;
    vtscf->vtsn_hash = hash;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_display_handler(ngx_http_request_t *r)
{
    size_t                                      size, len;
    u_char                                      *o, *s;
    ngx_str_t                                   uri, type;
    ngx_int_t                                   format, rc;
    ngx_buf_t                                   *b;
    ngx_chain_t                                 out;
    ngx_http_vhost_traffic_status_ctx_t         *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t    *vtscf;
    ngx_slab_pool_t                             *shpool;

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
ngx_http_vhost_traffic_status_node_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash)
{
    ngx_int_t                               rc;
    ngx_rbtree_node_t                       *node, *sentinel;
    ngx_http_vhost_traffic_status_node_t    *vtsn;

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
    ngx_vhost_traffic_status_add_rc(status, vtsn);
}


static void ngx_vhost_traffic_status_node_set(ngx_http_request_t *r,
        ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_uint_t status = r->headers_out.status;

    vtsn->stat_request_counter++;
    vtsn->stat_in_bytes += (ngx_atomic_uint_t) r->request_length;
    vtsn->stat_out_bytes += (ngx_atomic_uint_t) r->connection->sent;

    ngx_vhost_traffic_status_add_rc(status, vtsn);
}


static u_char *
ngx_http_vhost_traffic_status_display_set_main(const char *fmt, u_char *buf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    ngx_atomic_int_t    ap, hn, ac, rq, rd, wr, wa;
    ngx_time_t          *tp;
    ngx_msec_t          now;

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;
    wa = *ngx_stat_waiting;

    buf = ngx_sprintf(buf, fmt, NGINX_VERSION,
            vtscf->start_msec, now, ac, rd, wr, wa, ap, hn, rq);

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_server(ngx_http_request_t *r,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
        const char *fmt, u_char *buf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    u_char                                  *p;
    ngx_str_t                               key;
    ngx_http_vhost_traffic_status_node_t    *vtsn;

    if (node != sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO) {
            key.len = ngx_strlen(vtsn->data) * 6;
            key.data = ngx_pcalloc(r->pool, key.len);
            if (key.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "ngx_pcalloc() failed");
                key.len = ngx_strlen(vtsn->data);
                key.data = vtsn->data;
                p = NULL;
                goto just_start;
            }
            p = key.data;

#if !defined(nginx_version) || nginx_version < 1007009
            p = (u_char *) ngx_http_vhost_traffic_status_escape_json(p, vtsn->data, ngx_strlen(vtsn->data));
#else
            p = (u_char *) ngx_escape_json(p, vtsn->data, ngx_strlen(vtsn->data));
#endif

just_start:

            buf = ngx_sprintf(buf, fmt,
                    key.data, vtsn->stat_request_counter, vtsn->stat_in_bytes, vtsn->stat_out_bytes,
                    vtsn->stat_1xx_counter, vtsn->stat_2xx_counter, vtsn->stat_3xx_counter,
                    vtsn->stat_4xx_counter, vtsn->stat_5xx_counter);

            vtscf->stats.stat_request_counter += vtsn->stat_request_counter;
            vtscf->stats.stat_in_bytes += vtsn->stat_in_bytes;
            vtscf->stats.stat_out_bytes += vtsn->stat_out_bytes;
            vtscf->stats.stat_1xx_counter += vtsn->stat_1xx_counter;
            vtscf->stats.stat_2xx_counter += vtsn->stat_2xx_counter;
            vtscf->stats.stat_3xx_counter += vtsn->stat_3xx_counter;
            vtscf->stats.stat_4xx_counter += vtsn->stat_4xx_counter;
            vtscf->stats.stat_5xx_counter += vtsn->stat_5xx_counter;

            if (p != NULL) {
                ngx_pfree(r->pool, key.data);
            }
        }

        buf = ngx_http_vhost_traffic_status_display_set_server(r, node->left, sentinel, fmt, buf, vtscf);
        buf = ngx_http_vhost_traffic_status_display_set_server(r, node->right, sentinel, fmt, buf, vtscf);
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_upstream_alone(ngx_http_request_t *r,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
        const char *fmt, u_char *buf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    ngx_http_vhost_traffic_status_node_t    *vtsn;
    ngx_str_t                               key;

    if (node != sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA) {
            key.len = vtsn->len - 1;
            key.data = vtsn->data + 1;
            buf = ngx_sprintf(buf, fmt,
                    &key,
                    vtsn->stat_request_counter, vtsn->stat_in_bytes, vtsn->stat_out_bytes,
                    vtsn->stat_1xx_counter, vtsn->stat_2xx_counter, vtsn->stat_3xx_counter,
                    vtsn->stat_4xx_counter, vtsn->stat_5xx_counter, vtsn->stat_upstream.rtms,
                    (ngx_uint_t) 0, (ngx_uint_t) 0, (time_t) 0,
                    ngx_vhost_traffic_status_boolean_to_string(0),
                    ngx_vhost_traffic_status_boolean_to_string(0));
        }

        buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(r, node->left, sentinel, fmt, buf, vtscf);
        buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(r, node->right, sentinel, fmt, buf, vtscf);
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set_upstream_group(ngx_http_request_t *r,
        ngx_rbtree_t *rbtree, const char *fmt, u_char *buf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    size_t                                  len;
    u_char                                  *p, *o, *s;
    uint32_t                                hash;
    ngx_uint_t                              i, j;
    ngx_str_t                               key;
    ngx_rbtree_node_t                       *node;
    ngx_http_upstream_server_t              *us;
    ngx_http_upstream_main_conf_t           *umcf;
    ngx_http_upstream_srv_conf_t            *uscf, **uscfp;
    ngx_http_vhost_traffic_status_node_t    *vtsn;

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
                    &us[j].addrs->name,
                    vtsn->stat_request_counter, vtsn->stat_in_bytes, vtsn->stat_out_bytes,
                    vtsn->stat_1xx_counter, vtsn->stat_2xx_counter, vtsn->stat_3xx_counter,
                    vtsn->stat_4xx_counter, vtsn->stat_5xx_counter, vtsn->stat_upstream.rtms,
                    us[j].weight, us[j].max_fails, us[j].fail_timeout,
                    ngx_vhost_traffic_status_boolean_to_string(us[j].backup),
                    ngx_vhost_traffic_status_boolean_to_string(us[j].down));
                } else {
                    buf = ngx_sprintf(buf, fmt,
                    &us[j].addrs->name,
                    0, 0, 0,
                    0, 0, 0,
                    0, 0, (ngx_msec_t) 0,
                    us[j].weight, us[j].max_fails, us[j].fail_timeout,
                    ngx_vhost_traffic_status_boolean_to_string(us[j].backup),
                    ngx_vhost_traffic_status_boolean_to_string(us[j].down));
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

    buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(r,
        rbtree->root, rbtree->sentinel, fmt, buf, vtscf);

    if (s == buf) {
        buf = o;
    } else {
        buf--;
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    return buf;
}


static u_char *
ngx_http_vhost_traffic_status_display_set(ngx_http_request_t *r,
        ngx_rbtree_t *rbtree, u_char *buf,
        ngx_http_vhost_traffic_status_loc_conf_t *vtscf)
{
    u_char              *o, *s;
    ngx_rbtree_node_t   *node, *sentinel;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    ngx_memzero(&vtscf->stats, sizeof(vtscf->stats));

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);

    /* main & connections */
    buf = ngx_http_vhost_traffic_status_display_set_main(
            NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_MAIN,
            buf, vtscf);

    /* serverZones */
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S);

    buf = ngx_http_vhost_traffic_status_display_set_server(r, node, sentinel,
            NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER, buf, vtscf);

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER,
            "*", vtscf->stats.stat_request_counter, vtscf->stats.stat_in_bytes,
            vtscf->stats.stat_out_bytes, vtscf->stats.stat_1xx_counter,
            vtscf->stats.stat_2xx_counter, vtscf->stats.stat_3xx_counter,
            vtscf->stats.stat_4xx_counter, vtscf->stats.stat_5xx_counter);
    buf--;
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);

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

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);

    return buf;
}


static void
ngx_http_vhost_traffic_status_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t                       **p;
    ngx_http_vhost_traffic_status_node_t    *vtsn, *vtsnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
            vtsnt = (ngx_http_vhost_traffic_status_node_t *) &temp->color;

            p = (ngx_memn2cmp(vtsn->data, vtsnt->data, vtsn->len, vtsnt->len) < 0)
                ? &temp->left : &temp->right;
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
    ngx_http_vhost_traffic_status_ctx_t *octx = data;

    size_t                              len;
    ngx_slab_pool_t                     *shpool;
    ngx_rbtree_node_t                   *sentinel;
    ngx_http_vhost_traffic_status_ctx_t *ctx;

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
    ssize_t                                 size;
    u_char                                  *p;
    ngx_uint_t                              i;
    ngx_str_t                               *value, name, s;
    ngx_shm_zone_t                          *shm_zone;
    ngx_http_vhost_traffic_status_ctx_t     *ctx;

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
                "vhost_traffic_status: \"%V\" is already bound to key", &name);

        return NGX_CONF_ERROR;
    }

    ctx->shm_name = name;
    ctx->shm_size = size;
    shm_zone->init = ngx_http_vhost_traffic_status_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_vhost_traffic_status_display(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_vhost_traffic_status_display_handler;

    return NGX_CONF_OK;
}


static void *
ngx_http_vhost_traffic_status_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_vhost_traffic_status_ctx_t     *ctx;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_vhost_traffic_status_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->enable = NGX_CONF_UNSET;

    return ctx;
}


static char *
ngx_http_vhost_traffic_status_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_vhost_traffic_status_ctx_t     *ctx = conf;

    ngx_conf_init_value(ctx->enable, 0);

    return NGX_CONF_OK;
}


static void *
ngx_http_vhost_traffic_status_create_loc_conf(ngx_conf_t *cf)
{
    ngx_time_t                                  *tp;
    ngx_http_vhost_traffic_status_loc_conf_t    *conf;

    tp = ngx_timeofday();

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_vhost_traffic_status_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->start_msec = (ngx_msec_t) (tp->sec * 1000 + tp->msec);
    conf->enable = NGX_CONF_UNSET;
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

    ngx_str_t                           name;
    ngx_shm_zone_t                      *shm_zone;
    ngx_http_vhost_traffic_status_ctx_t *ctx;

    ctx = ngx_http_conf_get_module_main_conf(cf, ngx_http_vhost_traffic_status_module);

    if (!ctx->enable) {
        return NGX_CONF_OK;
    }

    ngx_conf_merge_value(conf->enable, prev->enable, 1);
    ngx_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);
    ngx_conf_merge_value(conf->format, prev->format, NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON);

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
