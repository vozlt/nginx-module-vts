
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_control.h"
#include "ngx_http_vhost_traffic_status_display_json.h"
#include "ngx_http_vhost_traffic_status_display.h"


static void ngx_http_vhost_traffic_status_node_status_all(
    ngx_http_vhost_traffic_status_control_t *control);
static void ngx_http_vhost_traffic_status_node_status_group(
    ngx_http_vhost_traffic_status_control_t *control);
static void ngx_http_vhost_traffic_status_node_status_zone(
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

static void ngx_http_vhost_traffic_status_node_reset_all(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_rbtree_node_t *node);
static void ngx_http_vhost_traffic_status_node_reset_group(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_rbtree_node_t *node);
static void ngx_http_vhost_traffic_status_node_reset_zone(
    ngx_http_vhost_traffic_status_control_t *control);


void
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
        if (uscf->servers == NULL && uscf->port != 0) {
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


void
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
            if (ngx_strncmp(control->zone->data, "*", 1) == 0) {
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

#if (NGX_HTTP_CACHE)
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
        *control->buf = ngx_sprintf(*control->buf,
                                    NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE_S);
        s = *control->buf;
        *control->buf = ngx_http_vhost_traffic_status_display_set_cache(
                            control->r, *control->buf, node);
        break;
#endif

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

    if (control->group == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO
        && control->zone->len == 6
        && ngx_strncasecmp(control->zone->data, (u_char *) "::main", 6) == 0)
    {
        *control->buf = ngx_sprintf(*control->buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);
        *control->buf = ngx_http_vhost_traffic_status_display_set_main(control->r,
                            *control->buf);
        (*control->buf)--;
         *control->buf = ngx_sprintf(*control->buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);

        control->count++;

        return;
    }

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

#if (NGX_HTTP_CACHE)
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
        *control->buf = ngx_http_vhost_traffic_status_display_set_cache_node(control->r,
                            *control->buf, vtsn);
        break;
#endif

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


void
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


void
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
                                ngx_http_vhost_traffic_status_boolean_to_string(1),
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


void
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
                                ngx_http_vhost_traffic_status_boolean_to_string(1),
                                control->arg_cmd, control->arg_group,
                                control->arg_zone, control->count);
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
