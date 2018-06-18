
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_variables.h"
#include "ngx_http_vhost_traffic_status_shm.h"
#include "ngx_http_vhost_traffic_status_filter.h"
#include "ngx_http_vhost_traffic_status_limit.h"
#include "ngx_http_vhost_traffic_status_display.h"
#include "ngx_http_vhost_traffic_status_set.h"
#include "ngx_http_vhost_traffic_status_dump.h"


static ngx_int_t ngx_http_vhost_traffic_status_handler(ngx_http_request_t *r);

static void ngx_http_vhost_traffic_status_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_vhost_traffic_status_init_zone(
    ngx_shm_zone_t *shm_zone, void *data);
static char *ngx_http_vhost_traffic_status_zone(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_vhost_traffic_status_dump(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_vhost_traffic_status_filter_max_node(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_vhost_traffic_status_average_method(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_vhost_traffic_status_histogram_buckets(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_vhost_traffic_status_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_vhost_traffic_status_init(ngx_conf_t *cf);
static void *ngx_http_vhost_traffic_status_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_vhost_traffic_status_init_main_conf(ngx_conf_t *cf,
    void *conf);
static void *ngx_http_vhost_traffic_status_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_vhost_traffic_status_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_vhost_traffic_status_init_worker(ngx_cycle_t *cycle);
static void ngx_http_vhost_traffic_status_exit_worker(ngx_cycle_t *cycle);


static ngx_conf_enum_t  ngx_http_vhost_traffic_status_display_format[] = {
    { ngx_string("json"), NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON },
    { ngx_string("html"), NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML },
    { ngx_string("jsonp"), NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSONP },
    { ngx_string("prometheus"), NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_vhost_traffic_status_average_method_post[] = {
    { ngx_string("AMM"), NGX_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_AMM },
    { ngx_string("WMA"), NGX_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_WMA },
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

    { ngx_string("vhost_traffic_status_filter_max_node"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_vhost_traffic_status_filter_max_node,
      0,
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

    { ngx_string("vhost_traffic_status_dump"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_vhost_traffic_status_dump,
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

    { ngx_string("vhost_traffic_status_display_sum_key"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, sum_key),
      NULL },

    { ngx_string("vhost_traffic_status_set_by_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE2,
      ngx_http_vhost_traffic_status_set_by_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("vhost_traffic_status_average_method"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_vhost_traffic_status_average_method,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("vhost_traffic_status_histogram_buckets"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_vhost_traffic_status_histogram_buckets,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("vhost_traffic_status_bypass_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, bypass_limit),
      NULL },

    { ngx_string("vhost_traffic_status_bypass_stats"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_vhost_traffic_status_loc_conf_t, bypass_stats),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_vhost_traffic_status_module_ctx = {
    ngx_http_vhost_traffic_status_preconfiguration, /* preconfiguration */
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
    ngx_http_vhost_traffic_status_init_worker,   /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    ngx_http_vhost_traffic_status_exit_worker,   /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
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

    if (!ctx->enable || !vtscf->enable || vtscf->bypass_stats) {
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


ngx_msec_t
ngx_http_vhost_traffic_status_current_msec(void)
{
    time_t           sec;
    ngx_uint_t       msec;
    struct timeval   tv;

    ngx_gettimeofday(&tv);

    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;

    return (ngx_msec_t) sec * 1000 + msec;
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

    ctx->shm_zone = shm_zone;
    ctx->shm_name = name;
    ctx->shm_size = size;
    shm_zone->init = ngx_http_vhost_traffic_status_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_vhost_traffic_status_dump(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_vhost_traffic_status_ctx_t  *ctx = conf;

    ngx_int_t   rc;
    ngx_str_t  *value;

    value = cf->args->elts;

    ctx->dump = 1;

    ctx->dump_file = value[1];

    /* second argument process */
    if (cf->args->nelts == 3) {
        rc = ngx_parse_time(&value[2], 0);
        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[2]);
            goto invalid;
        }
        ctx->dump_period = (ngx_msec_t) rc;
    }

    return NGX_CONF_OK;

invalid:

    return NGX_CONF_ERROR;
}


static char *
ngx_http_vhost_traffic_status_filter_max_node(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_vhost_traffic_status_ctx_t  *ctx = conf;

    ngx_str_t                                     *value;
    ngx_int_t                                      n;
    ngx_uint_t                                     i;
    ngx_array_t                                   *filter_max_node_matches;
    ngx_http_vhost_traffic_status_filter_match_t  *matches;

    filter_max_node_matches = ngx_array_create(cf->pool, 1,
                                  sizeof(ngx_http_vhost_traffic_status_filter_match_t));
    if (filter_max_node_matches == NULL) {
        goto invalid;
    }

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);
    if (n < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of filter_max_node \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    ctx->filter_max_node = (ngx_uint_t) n;

    /* arguments process */
    for (i = 2; i < cf->args->nelts; i++) {
        matches = ngx_array_push(filter_max_node_matches);
        if (matches == NULL) {
            goto invalid;
        }

        matches->match.data = value[i].data;
        matches->match.len = value[i].len;
    }

    ctx->filter_max_node_matches = filter_max_node_matches;

    return NGX_CONF_OK;

invalid:

    return NGX_CONF_ERROR;
}


static char *
ngx_http_vhost_traffic_status_average_method(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    char       *rv;
    ngx_int_t   rc;
    ngx_str_t  *value;

    value = cf->args->elts;

    cmd->offset = offsetof(ngx_http_vhost_traffic_status_loc_conf_t, average_method);
    cmd->post = &ngx_http_vhost_traffic_status_average_method_post;

    rv = ngx_conf_set_enum_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[1]);
        goto invalid;
    }

    /* second argument process */
    if (cf->args->nelts == 3) {
        rc = ngx_parse_time(&value[2], 0);
        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[2]);
            goto invalid;
        }
        vtscf->average_period = (ngx_msec_t) rc;
    }

    return NGX_CONF_OK;

invalid:

    return NGX_CONF_ERROR;
}


static char *
ngx_http_vhost_traffic_status_histogram_buckets(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    ngx_str_t                                       *value;
    ngx_int_t                                        n;
    ngx_uint_t                                       i;
    ngx_array_t                                     *histogram_buckets;
    ngx_http_vhost_traffic_status_node_histogram_t  *buckets;

    histogram_buckets = ngx_array_create(cf->pool, 1,
                            sizeof(ngx_http_vhost_traffic_status_node_histogram_t));
    if (histogram_buckets == NULL) {
        goto invalid;
    }

    value = cf->args->elts;

    /* arguments process */
    for (i = 1; i < cf->args->nelts; i++) {
        if (i > NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "histogram bucket size exceeds %d",
                               NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN);
            break;
        }

        n = ngx_atofp(value[i].data, value[i].len, 3);
        if (n == NGX_ERROR || n == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);
            goto invalid;
        }

        buckets = ngx_array_push(histogram_buckets);
        if (buckets == NULL) {
            goto invalid;
        }

        buckets->msec = (ngx_msec_int_t) n;
    }

    vtscf->histogram_buckets = histogram_buckets;

    return NGX_CONF_OK;

invalid:

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_http_vhost_traffic_status_preconfiguration(ngx_conf_t *cf)
{
    return ngx_http_vhost_traffic_status_add_variables(cf);
}


static ngx_int_t
ngx_http_vhost_traffic_status_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts init");

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* limit handler */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_vhost_traffic_status_limit_handler;

    /* set handler */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_vhost_traffic_status_set_handler;

    /* vts handler */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_vhost_traffic_status_handler;

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

    /*
     * set by ngx_pcalloc():
     *
     *     ctx->rbtree = { NULL, ... };
     *     ctx->filter_keys = { NULL, ... };
     *     ctx->limit_traffics = { NULL, ... };
     *     ctx->limit_filter_traffics = { NULL, ... };
     *
     *     ctx->filter_max_node_matches = { NULL, ... };
     *     ctx->filter_max_node = 0;
     *
     *     ctx->enable = 0;
     *     ctx->filter_check_duplicate = 0;
     *     ctx->limit_check_duplicate = 0;
     *     ctx->shm_zone = { NULL, ... };
     *     ctx->shm_name = { 0, NULL };
     *     ctx->shm_size = 0;
     *
     *     ctx->dump = 0;
     *     ctx->dump_file = { 0, NULL };
     *     ctx->dump_period = 0;
     *     ctx->dump_event = { NULL, ... };
     */

    ctx->filter_max_node = NGX_CONF_UNSET_UINT;
    ctx->enable = NGX_CONF_UNSET;
    ctx->filter_check_duplicate = NGX_CONF_UNSET;
    ctx->limit_check_duplicate = NGX_CONF_UNSET;
    ctx->dump = NGX_CONF_UNSET;
    ctx->dump_period = NGX_CONF_UNSET_MSEC;

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

    ngx_conf_init_uint_value(ctx->filter_max_node, 0);
    ngx_conf_init_value(ctx->enable, 0);
    ngx_conf_init_value(ctx->filter_check_duplicate, vtscf->filter_check_duplicate);
    ngx_conf_init_value(ctx->limit_check_duplicate, vtscf->limit_check_duplicate);
    ngx_conf_init_value(ctx->dump, 0);
    ngx_conf_merge_msec_value(ctx->dump_period, ctx->dump_period,
                              NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_DUMP_PERIOD * 1000);

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

    /*
     * set by ngx_pcalloc():
     *
     *     conf->shm_zone = { NULL, ... };
     *     conf->shm_name = { 0, NULL };
     *     conf->enable = 0;
     *     conf->filter = 0;
     *     conf->filter_host = 0;
     *     conf->filter_check_duplicate = 0;
     *     conf->filter_keys = { NULL, ... };
     *     conf->filter_vars = { NULL, ... };
     *
     *     conf->limit = 0;
     *     conf->limit_check_duplicate = 0;
     *     conf->limit_traffics = { NULL, ... };
     *     conf->limit_filter_traffics = { NULL, ... };
     *
     *     conf->stats = { 0, ... };
     *     conf->start_msec = 0;
     *     conf->format = 0;
     *     conf->jsonp = { 0, NULL };
     *     conf->sum_key = { 0, NULL };
     *     conf->average_method = 0;
     *     conf->average_period = 0;
     *     conf->histogram_buckets = { NULL, ... };
     *     conf->bypass_limit = 0;
     *     conf->bypass_stats = 0;
     */

    conf->shm_zone = NGX_CONF_UNSET_PTR;
    conf->enable = NGX_CONF_UNSET;
    conf->filter = NGX_CONF_UNSET;
    conf->filter_host = NGX_CONF_UNSET;
    conf->filter_check_duplicate = NGX_CONF_UNSET;
    conf->filter_vars = NGX_CONF_UNSET_PTR;

    conf->limit = NGX_CONF_UNSET;
    conf->limit_check_duplicate = NGX_CONF_UNSET;

    conf->start_msec = ngx_http_vhost_traffic_status_current_msec();
    conf->format = NGX_CONF_UNSET;
    conf->average_method = NGX_CONF_UNSET;
    conf->average_period = NGX_CONF_UNSET_MSEC;
    conf->histogram_buckets = NGX_CONF_UNSET_PTR;
    conf->bypass_limit = NGX_CONF_UNSET;
    conf->bypass_stats = NGX_CONF_UNSET;

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

    ngx_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);
    ngx_conf_merge_value(conf->enable, prev->enable, 1);
    ngx_conf_merge_value(conf->filter, prev->filter, 1);
    ngx_conf_merge_value(conf->filter_host, prev->filter_host, 0);
    ngx_conf_merge_value(conf->filter_check_duplicate, prev->filter_check_duplicate, 1);
    ngx_conf_merge_value(conf->limit, prev->limit, 1);
    ngx_conf_merge_value(conf->limit_check_duplicate, prev->limit_check_duplicate, 1);
    ngx_conf_merge_ptr_value(conf->filter_vars, prev->filter_vars, NULL);

    ngx_conf_merge_value(conf->format, prev->format,
                         NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON);
    ngx_conf_merge_str_value(conf->jsonp, prev->jsonp,
                             NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_JSONP);
    ngx_conf_merge_str_value(conf->sum_key, prev->sum_key,
                             NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SUM_KEY);
    ngx_conf_merge_value(conf->average_method, prev->average_method,
                         NGX_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_AMM);
    ngx_conf_merge_msec_value(conf->average_period, prev->average_period,
                              NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_AVG_PERIOD * 1000);
    ngx_conf_merge_ptr_value(conf->histogram_buckets, prev->histogram_buckets, NULL);

    ngx_conf_merge_value(conf->bypass_limit, prev->bypass_limit, 0);
    ngx_conf_merge_value(conf->bypass_stats, prev->bypass_stats, 0);

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
ngx_http_vhost_traffic_status_init_worker(ngx_cycle_t *cycle)
{
    ngx_event_t                          *dump_event;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                   "http vts init worker");

    ctx = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_vhost_traffic_status_module);

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                       "vts::init_worker(): is bypassed due to no http block in configure file");
        return NGX_OK;
    }

    if (!(ctx->enable & ctx->dump) || ctx->rbtree == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                       "vts::init_worker(): is bypassed");
        return NGX_OK;
    }

    /* dumper */
    dump_event = &ctx->dump_event;
    dump_event->handler = ngx_http_vhost_traffic_status_dump_handler;
    dump_event->log = ngx_cycle->log;
    dump_event->data = ctx;
    ngx_add_timer(dump_event, 1000);

    /* restore */
    ngx_http_vhost_traffic_status_dump_restore(dump_event);

    return NGX_OK;
}


static void
ngx_http_vhost_traffic_status_exit_worker(ngx_cycle_t *cycle)
{
    ngx_event_t                          *dump_event;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                   "http vts exit worker");

    ctx = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_vhost_traffic_status_module);

    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                       "vts::exit_worker(): is bypassed due to no http block in configure file");
        return;
    }

    if (!(ctx->enable & ctx->dump) || ctx->rbtree == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                       "vts::exit_worker(): is bypassed");
        return;
    }

    /* dump */
    dump_event = &ctx->dump_event;
    dump_event->log = ngx_cycle->log;
    dump_event->data = ctx;
    ngx_http_vhost_traffic_status_dump_execute(dump_event);
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
