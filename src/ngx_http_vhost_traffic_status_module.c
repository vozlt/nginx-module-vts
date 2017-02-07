
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_shm.h"
#include "ngx_http_vhost_traffic_status_filter.h"
#include "ngx_http_vhost_traffic_status_limit.h"
#include "ngx_http_vhost_traffic_status_display.h"


static ngx_int_t ngx_http_vhost_traffic_status_handler(ngx_http_request_t *r);

static void ngx_http_vhost_traffic_status_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_vhost_traffic_status_init_zone(
    ngx_shm_zone_t *shm_zone, void *data);
static char *ngx_http_vhost_traffic_status_zone(ngx_conf_t *cf,
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
    { ngx_string("jsonp"), NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSONP },
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

    { ngx_string("vhost_traffic_status_display_jsonp"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, jsonp),
      NULL },

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

    { ngx_string("vts_request_time"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_request_time),
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


static ngx_int_t
ngx_http_vhost_traffic_status_handler(ngx_http_request_t *r)
{
    ngx_int_t                                  rc;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http vts handler");

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


ngx_msec_int_t
ngx_http_vhost_traffic_status_request_time(ngx_http_request_t *r)
{
    ngx_time_t      *tp;
    ngx_msec_int_t   ms;

    tp = ngx_timeofday();

    ms = (ngx_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    return ngx_max(ms, 0);
}


ngx_msec_int_t
ngx_http_vhost_traffic_status_upstream_response_time(ngx_http_request_t *r)
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
    return ngx_max(ms, 0);
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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts init main conf");

    vtscf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_vhost_traffic_status_module);

    if (vtscf->filter_check_duplicate != 0) {
        rc = ngx_http_vhost_traffic_status_filter_unique(cf->pool, &ctx->filter_keys);
        if (rc != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "init_main_conf::filter_unique() failed");
            return NGX_CONF_ERROR;
        }
    }

    if (vtscf->limit_check_duplicate != 0) {
        rc = ngx_http_vhost_traffic_status_limit_traffic_unique(cf->pool, &ctx->limit_traffics);
        if (rc != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "init_main_conf::limit_traffic_unique(server) failed");
            return NGX_CONF_ERROR;
        }

        rc = ngx_http_vhost_traffic_status_limit_traffic_unique(cf->pool,
                                                                &ctx->limit_filter_traffics);
        if (rc != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "init_main_conf::limit_traffic_unique(filter) failed");
            return NGX_CONF_ERROR;
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
    ngx_http_vhost_traffic_status_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_vhost_traffic_status_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->start_msec = ngx_current_msec;
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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts merge loc conf");

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
                return NGX_CONF_ERROR;
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
                return NGX_CONF_ERROR;
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
                return NGX_CONF_ERROR;
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
    ngx_conf_merge_str_value(conf->jsonp, prev->jsonp,
                             NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_JSONP);

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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts init");

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
