
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_filter.h"
#include "ngx_http_vhost_traffic_status_shm.h"


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


void
ngx_http_vhost_traffic_status_shm_info_node(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_shm_info_t *shm_info,
    ngx_rbtree_node_t *node)
{
    ngx_str_t                              filter;
    ngx_uint_t                             size;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        size = offsetof(ngx_rbtree_node_t, color)
               + offsetof(ngx_http_vhost_traffic_status_node_t, data)
               + vtsn->len;

        shm_info->used_size += size;
        shm_info->used_node++;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            filter.data = vtsn->data;
            filter.len = vtsn->len;

            (void) ngx_http_vhost_traffic_status_node_position_key(&filter, 1);

            if (ngx_http_vhost_traffic_status_filter_max_node_match(r, &filter) == NGX_OK) {
                shm_info->filter_used_size += size;
                shm_info->filter_used_node++;
            }
        }

        ngx_http_vhost_traffic_status_shm_info_node(r, shm_info, node->left);
        ngx_http_vhost_traffic_status_shm_info_node(r, shm_info, node->right);
    }
}


void
ngx_http_vhost_traffic_status_shm_info(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_shm_info_t *shm_info)
{
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    ngx_memzero(shm_info, sizeof(ngx_http_vhost_traffic_status_shm_info_t));

    shm_info->name = &ctx->shm_name;
    shm_info->max_size = ctx->shm_size;

    ngx_http_vhost_traffic_status_shm_info_node(r, shm_info, ctx->rbtree->root);
}


static ngx_int_t
ngx_http_vhost_traffic_status_shm_add_node(ngx_http_request_t *r,
    ngx_str_t *key, unsigned type)
{
    size_t                                     size;
    unsigned                                   init;
    uint32_t                                   hash;
    ngx_slab_pool_t                           *shpool;
    ngx_rbtree_node_t                         *node, *lrun;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_node_t      *vtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;
    ngx_http_vhost_traffic_status_shm_info_t  *shm_info;

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

        /* delete lru node */
        lrun = ngx_http_vhost_traffic_status_find_lru(r);
        if (lrun != NULL) {
            ngx_rbtree_delete(ctx->rbtree, lrun);
            ngx_slab_free_locked(shpool, lrun);
        }

        size = offsetof(ngx_rbtree_node_t, color)
               + offsetof(ngx_http_vhost_traffic_status_node_t, data)
               + key->len;

        node = ngx_slab_alloc_locked(shpool, size);
        if (node == NULL) {
            shm_info = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_shm_info_t));
            if (shm_info == NULL) {
                ngx_shmtx_unlock(&shpool->mutex);
                return NGX_ERROR;
            }

            ngx_http_vhost_traffic_status_shm_info(r, shm_info);

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "shm_add_node::ngx_slab_alloc_locked() failed: "
                          "used_size[%ui], used_node[%ui]",
                          shm_info->used_size, shm_info->used_node);

            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        node->key = hash;
        vtsn->len = (u_short) key->len;
        ngx_http_vhost_traffic_status_node_init(r, vtsn);
        vtsn->stat_upstream.type = type;
        ngx_memcpy(vtsn->data, key->data, key->len);

        ngx_rbtree_insert(ctx->rbtree, node);

    } else {
        init = NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_FIND;
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
        ngx_http_vhost_traffic_status_node_set(r, vtsn);
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
    ngx_msec_int_t                             ms;
    ngx_http_vhost_traffic_status_node_t       ovtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    ovtsn = *vtsn;
    ms = ngx_http_vhost_traffic_status_upstream_response_time(r);

    ngx_http_vhost_traffic_status_node_time_queue_insert(&vtsn->stat_upstream.response_times,
                                                         ms);
    ngx_http_vhost_traffic_status_node_histogram_observe(&vtsn->stat_upstream.response_buckets,
                                                         ms);

    if (init == NGX_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE) {
        vtsn->stat_upstream.response_time_counter = (ngx_atomic_uint_t) ms;
        vtsn->stat_upstream.response_time = (ngx_msec_t) ms;

    } else {
        vtsn->stat_upstream.response_time_counter += (ngx_atomic_uint_t) ms;
        vtsn->stat_upstream.response_time = ngx_http_vhost_traffic_status_node_time_queue_average(
                                                &vtsn->stat_upstream.response_times,
                                                vtscf->average_method, vtscf->average_period);

        if (ovtsn.stat_upstream.response_time_counter > vtsn->stat_upstream.response_time_counter)
        { 
            vtsn->stat_response_time_counter_oc++;
        }
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

    /*
     * If max_size in proxy_cache_path directive is not specified,
     * the system dependent value NGX_MAX_OFF_T_VALUE is assigned by default.
     *
     * proxy_cache_path ... keys_zone=name:size [max_size=size] ...
     *
     *     keys_zone's shared memory size:
     *         cache->shm_zone->shm.size
     *
     *     max_size's size:
     *         cache->max_size
     */

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
        if (filters[i].filter_key.value.len <= 0) {
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


ngx_int_t
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


ngx_int_t
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


ngx_int_t
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

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0
        || r->upstream->state == NULL)
    {
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

        /* routine for proxy_pass|fastcgi_pass|... $variables */
        uscf = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_srv_conf_t));
        if (uscf == NULL) {
            return NGX_ERROR;
        }

        uscf->host = u->resolved->host;
        uscf->port = u->resolved->port;
    }

found:

    state = u->state;
    if (state->peer == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shm_add_upstream::peer failed");
        return NGX_ERROR;
    }

    dst.len = (uscf->port ? 0 : uscf->host.len + sizeof("@") - 1) + state->peer->len;
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    p = dst.data;
    if (uscf->port) {
        p = ngx_cpymem(p, state->peer->data, state->peer->len);
        type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;

    } else {
        p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
        *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
        p = ngx_cpymem(p, state->peer->data, state->peer->len);
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

ngx_int_t
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

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
