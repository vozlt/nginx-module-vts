
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_control.h"
#include "ngx_http_vhost_traffic_status_set.h"


static ngx_int_t ngx_http_vhost_traffic_status_set_init(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_control_t *control);

static ngx_atomic_uint_t ngx_http_vhost_traffic_status_set_by_filter_node_member(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_http_vhost_traffic_status_node_t *vtsn,
    ngx_http_upstream_server_t *us);
static ngx_int_t ngx_http_vhost_traffic_status_set_by_filter_init(
    ngx_http_vhost_traffic_status_control_t *control, ngx_str_t *uri);
static ngx_int_t ngx_http_vhost_traffic_status_set_by_filter_node(
    ngx_http_vhost_traffic_status_control_t *control, ngx_str_t *buf);
static ngx_int_t ngx_http_vhost_traffic_status_set_by_filter_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_vhost_traffic_status_set_by_filter_variables(
    ngx_http_request_t *r);


ngx_int_t
ngx_http_vhost_traffic_status_set_handler(ngx_http_request_t *r)
{
    ngx_int_t                                  rc;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (!ctx->enable || !vtscf->filter) {
        return NGX_DECLINED;
    }

    rc = ngx_http_vhost_traffic_status_set_by_filter_variables(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "set_handler::set_by_filter_variables() failed");
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_vhost_traffic_status_set_init(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_control_t *control)
{
    control->r = r;
    control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE;
    control->group = -2;
    control->zone = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    control->arg_group = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    control->arg_zone = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    control->arg_name = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    control->range = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_NONE;
    control->count = 0;

    if (control->zone == NULL || control->arg_group == NULL
        || control->arg_zone == NULL || control->arg_name == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_atomic_uint_t
ngx_http_vhost_traffic_status_set_by_filter_node_member(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_http_vhost_traffic_status_node_t *vtsn,
    ngx_http_upstream_server_t *us)
{
    ngx_str_t  *member;

    member = control->arg_name;

    if (ngx_http_vhost_traffic_status_node_member_cmp(member, "requestCounter") == 0)
    {
        return vtsn->stat_request_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "requestMsecCounter") == 0)
    {
        return vtsn->stat_request_time_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "requestMsec") == 0)
    {
        return vtsn->stat_request_time;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "responseMsecCounter") == 0)
    {
        return vtsn->stat_upstream.response_time_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "responseMsec") == 0)
    {
        return vtsn->stat_upstream.response_time;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "inBytes") == 0)
    {
        return vtsn->stat_in_bytes;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "outBytes") == 0)
    {
        return vtsn->stat_out_bytes;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "1xx") == 0)
    {
        return vtsn->stat_1xx_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "2xx") == 0)
    {
        return vtsn->stat_2xx_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "3xx") == 0)
    {
        return vtsn->stat_3xx_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "4xx") == 0)
    {
        return vtsn->stat_4xx_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "5xx") == 0)
    {
        return vtsn->stat_5xx_counter;
    }

#if (NGX_HTTP_CACHE)
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cacheMaxSize") == 0)
    {
        return vtsn->stat_cache_max_size;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cacheUsedSize") == 0)
    {
        return vtsn->stat_cache_used_size;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cacheMiss") == 0)
    {
        return vtsn->stat_cache_miss_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cacheBypass") == 0)
    {
        return vtsn->stat_cache_bypass_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cacheExpired") == 0)
    {
        return vtsn->stat_cache_expired_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cacheStale") == 0)
    {
        return vtsn->stat_cache_stale_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cacheUpdating") == 0)
    {
        return vtsn->stat_cache_updating_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cacheRevalidated") == 0)
    {
        return vtsn->stat_cache_revalidated_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cacheHit") == 0)
    {
        return vtsn->stat_cache_hit_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cacheScarce") == 0)
    {
        return vtsn->stat_cache_scarce_counter;
    }
#endif

    switch (control->group) {

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:

        if (ngx_http_vhost_traffic_status_node_member_cmp(member, "weight") == 0)
        {
            return us->weight;
        }
        else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "maxFails") == 0)
        {
            return us->max_fails;
        }
        else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "failTimeout") == 0)
        {
            return us->fail_timeout;
        }
        else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "backup") == 0)
        {
            return us->backup;
        }
        else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "down") == 0)
        {
            return us->down;
        }

        break;
    }

    return 0;
}


static ngx_int_t
ngx_http_vhost_traffic_status_set_by_filter_init(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_str_t *uri)
{
    u_char              *p;
    ngx_int_t            rc;
    ngx_str_t           *arg_group, *arg_zone, *arg_name, alpha, slash;
    ngx_http_request_t  *r;

    control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_STATUS;
    arg_group = control->arg_group;
    arg_zone = control->arg_zone;
    arg_name = control->arg_name;

    r = control->r;

    /* parse: group */
    p = (u_char *) ngx_strchr(uri->data, '/');
    if (p == NULL) {
        return NGX_ERROR;
    }

    arg_group->data = uri->data;
    arg_group->len = p - uri->data;

    /* parse: zone */
    arg_zone->data = p + 1;
    p = (u_char *) ngx_strchr(arg_zone->data, '/');
    if (p == NULL) {
        return NGX_ERROR;
    }

    arg_zone->len = p - arg_zone->data;

    /* parse: name */
    arg_name->data = p + 1;
    arg_name->len = uri->data + uri->len - arg_name->data;

    /* set: control->group */
    if (arg_group->len == 6
            && ngx_strncasecmp(arg_group->data, (u_char *) "server", 6) == 0)
    {
        control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;
    }
    else if (arg_group->len == 14
            && ngx_strncasecmp(arg_group->data, (u_char *) "upstream@alone", 14) == 0)
    {
        control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;
    }
    else if (arg_group->len == 14
            && ngx_strncasecmp(arg_group->data, (u_char *) "upstream@group", 14) == 0)
    {
        control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;
    }
    else if (arg_group->len == 5
            && ngx_strncasecmp(arg_group->data, (u_char *) "cache", 5) == 0)
    {
        control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC;
    }
    else if (arg_group->len == 6
            && ngx_strncasecmp(arg_group->data, (u_char *) "filter", 6) == 0)
    {
        control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG;
    }
    else {
        return NGX_ERROR;
    }

    /* set: control->zone */
    rc = ngx_http_vhost_traffic_status_copy_str(r->pool, control->zone, arg_zone);
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

    ngx_str_set(&slash, "[:slash:]");
    rc = ngx_http_vhost_traffic_status_replace_strc(control->zone, &slash, '/');
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_handler_control::replace_strc() failed");
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_set_by_filter_node(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_str_t *buf)
{
    u_char                                *p;
    ngx_int_t                              rc;
    ngx_str_t                              key;
    ngx_rbtree_node_t                     *node;
    ngx_http_request_t                    *r;
    ngx_http_upstream_server_t             us;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    r = control->r;

    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, control->zone,
                                                         control->group);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "node_status_zone::node_generate_key(\"%V\") failed", &key);

        return NGX_ERROR;
    }

    node = ngx_http_vhost_traffic_status_find_node(r, &key, control->group, 0);
    if (node == NULL) {
        return NGX_ERROR;
    }

    vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

    p = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    buf->data = p;

    ngx_memzero(&us, sizeof(ngx_http_upstream_server_t));

    switch (control->group) {

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO:
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG:
        buf->len = ngx_sprintf(p, "%uA", ngx_http_vhost_traffic_status_set_by_filter_node_member(
                                             control, vtsn, &us)) - p;
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:
        ngx_http_vhost_traffic_status_node_upstream_lookup(control, &us);
        if (control->count) {
            buf->len = ngx_sprintf(p, "%uA", ngx_http_vhost_traffic_status_set_by_filter_node_member(
                                                 control, vtsn, &us)) - p;
        } else {
            return NGX_ERROR;
        }
        break;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_set_by_filter_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "vts filter variable");

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_vhost_traffic_status_set_by_filter_variables(ngx_http_request_t *r)
{
    ngx_int_t                                         rc;
    ngx_str_t                                         val, buf;
    ngx_http_variable_t                              *v;
    ngx_http_variable_value_t                        *vv;
    ngx_http_vhost_traffic_status_control_t          *control;
    ngx_http_vhost_traffic_status_loc_conf_t         *vtscf;
    ngx_http_vhost_traffic_status_filter_variable_t  *fv, *last;
    ngx_http_core_main_conf_t                        *cmcf;

    control = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_control_t));
    if (control == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_http_vhost_traffic_status_set_init(r, control);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "vts set filter variables");

    if (vtscf->filter_vars == NULL) {
        return NGX_OK;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    v = cmcf->variables.elts;

    fv = vtscf->filter_vars->elts;
    last = fv + vtscf->filter_vars->nelts;

    while (fv < last) {

        vv = &r->variables[fv->index];

        if (ngx_http_complex_value(r, &fv->value, &val)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        rc = ngx_http_vhost_traffic_status_set_by_filter_init(control, &val);

        if (rc != NGX_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "set_by_filter_variables::filter_init() failed");

            goto not_found;
        }

        ngx_memzero(&buf, sizeof(ngx_str_t));

        rc = ngx_http_vhost_traffic_status_set_by_filter_node(control, &buf);
        if (rc != NGX_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "set_by_filter_variables::filter_node() node not found");

            goto not_found;
        }

        vv->valid = 1;
        vv->not_found = 0;

        vv->data = buf.data;
        vv->len = buf.len;

        goto found;

not_found:

        vv->not_found = 1;

found:

        if (fv->set_handler) {
            fv->set_handler(r, vv, v[fv->index].data);
        }

        fv++;
    }

    return NGX_OK;
}


char *
ngx_http_vhost_traffic_status_set_by_filter(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    ngx_str_t                                        *value;
    ngx_http_variable_t                              *v;
    ngx_http_vhost_traffic_status_filter_variable_t  *fv;
    ngx_http_compile_complex_value_t                  ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    if (vtscf->filter_vars == NGX_CONF_UNSET_PTR) {
        vtscf->filter_vars = ngx_array_create(cf->pool, 1,
                                 sizeof(ngx_http_vhost_traffic_status_filter_variable_t));
        if (vtscf->filter_vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    fv = ngx_array_push(vtscf->filter_vars);
    if (fv == NULL) {
        return NGX_CONF_ERROR;
    }

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    fv->index = ngx_http_get_variable_index(cf, &value[1]);
    if (fv->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = ngx_http_vhost_traffic_status_set_by_filter_variable;
        v->data = (uintptr_t) fv;
    }

    fv->set_handler = v->set_handler;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &fv->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
