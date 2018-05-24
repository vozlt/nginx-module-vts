
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_variables.h"


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

    { ngx_string("vts_request_time_counter"), NULL,
      ngx_http_vhost_traffic_status_node_variable,
      offsetof(ngx_http_vhost_traffic_status_node_t, stat_request_time_counter),
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


ngx_int_t
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


ngx_int_t
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

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
