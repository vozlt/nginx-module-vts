
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_variables.h"


ngx_int_t
ngx_http_vhost_traffic_status_node_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                                    *p;
    unsigned                                   type;
    ngx_int_t                                  rc;
    ngx_str_t                                  key, dst;
    ngx_atomic_t                               value;
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

    if (data == offsetof(ngx_http_vhost_traffic_status_node_t, stat_request_times)) {

        /* the queue is the value, there is no counter kept for it */

        value = (ngx_atomic_t) ngx_http_vhost_traffic_status_node_time_queue_average(
                                   &vtsn->stat_request_times, vtscf->average_method,
                                   vtscf->average_period);

    } else {
        value = *((ngx_atomic_t *) ((char *) vtsn + data));
    }

    v->len = ngx_sprintf(p, "%uA", value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    goto done;

not_found:

    v->not_found = 1;

done:


    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


/*
 * The variables are the members of a node that carry a `variable` name in the
 * table in node.h, which is also where the offset each of them reads comes
 * from. They used to be a list of their own, so a field could be given a
 * variable here and a set_by_filter name there without the two ever meeting.
 */

ngx_int_t
ngx_http_vhost_traffic_status_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t                     *var;
    ngx_http_vhost_traffic_status_member_t  *m;

    for (m = ngx_http_vhost_traffic_status_members;
         m->limit.len || m->filter.len || m->variable.len;
         m++)
    {
        /* a field with no variable to read it by */

        if (m->variable.len == 0) {
            continue;
        }

        var = ngx_http_add_variable(cf, &m->variable,
                                    NGX_HTTP_VAR_NOCACHEABLE);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = ngx_http_vhost_traffic_status_node_variable;
        var->data = (uintptr_t) m->offset;
    }

    return NGX_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
