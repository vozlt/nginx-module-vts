
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module_html.h"
#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_shm.h"
#include "ngx_http_vhost_traffic_status_display_prometheus.h"
#include "ngx_http_vhost_traffic_status_display_json.h"
#include "ngx_http_vhost_traffic_status_display.h"
#include "ngx_http_vhost_traffic_status_control.h"


static ngx_int_t ngx_http_vhost_traffic_status_display_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_vhost_traffic_status_display_handler_control(ngx_http_request_t *r);
static ngx_int_t ngx_http_vhost_traffic_status_display_handler_default(ngx_http_request_t *r);


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

    p = (u_char *) ngx_strlchr(r->uri.data, r->uri.data + r->uri.len, '/');

    if (p) {
        p = (u_char *) ngx_strlchr(p + 1, r->uri.data + r->uri.len, '/');
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
    ngx_int_t                                  size, rc;
    ngx_str_t                                  type, alpha, arg_cmd, arg_group, arg_zone;
    ngx_buf_t                                 *b;
    ngx_chain_t                                out;
    ngx_slab_pool_t                           *shpool;
    ngx_http_vhost_traffic_status_control_t   *control;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    /* init control */
    control = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_control_t));
    if (control == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    control->r = r;
    control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE;
    control->group = -2;

    control->zone = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    if (control->zone == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

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
        size = ngx_http_vhost_traffic_status_display_get_size(r,
                   NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON);
        if (size == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "display_handler_control::display_get_size() failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        size = sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CONTROL)
               + arg_cmd.len + arg_group.len + arg_zone.len + ngx_pagesize;
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
                                    ngx_http_vhost_traffic_status_boolean_to_string(0),
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
    size_t                                     len;
    u_char                                    *o, *s, *p;
    ngx_str_t                                  uri, euri, type;
    ngx_int_t                                  size, format, rc;
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

            if (ngx_strncasecmp(s, (u_char *) "jsonp", sizeof("jsonp") - 1) == 0) {
                format = NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSONP;

            } else if (ngx_strncasecmp(s, (u_char *) "json", sizeof("json") - 1) == 0) {
                format = NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON;

            } else if (ngx_strncasecmp(s, (u_char *) "html", sizeof("html") - 1) == 0) {
                format = NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML;

            } else if (ngx_strncasecmp(s, (u_char *) "prometheus", sizeof("prometheus") - 1) == 0) {
                format = NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS;

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
        ngx_str_set(&type, "application/json");

    } else if (format == NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSONP) {
        ngx_str_set(&type, "application/javascript");

    } else if (format == NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS) {
        ngx_str_set(&type, "text/plain");

    } else {
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

    size = ngx_http_vhost_traffic_status_display_get_size(r, format);
    if (size == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_handler_default::display_get_size() failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_handler_default::ngx_create_temp_buf() failed");
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

    } else if (format == NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSONP) {
        shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;
        ngx_shmtx_lock(&shpool->mutex);
        b->last = ngx_sprintf(b->last, "%V", &vtscf->jsonp);
        b->last = ngx_sprintf(b->last, "(");
        b->last = ngx_http_vhost_traffic_status_display_set(r, b->last);
        b->last = ngx_sprintf(b->last, ")");
        ngx_shmtx_unlock(&shpool->mutex);

    } else if (format == NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS) {
        shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;
        ngx_shmtx_lock(&shpool->mutex);
        b->last = ngx_http_vhost_traffic_status_display_prometheus_set(r, b->last);
        ngx_shmtx_unlock(&shpool->mutex);

        if (b->last == b->pos) {
            b->last = ngx_sprintf(b->last, "#");
        }

    }
    else {
        euri = uri;
        len = ngx_escape_html(NULL, uri.data, uri.len);

        if (len) {
            p = ngx_pnalloc(r->pool, uri.len + len);
            if (p == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_handler_default::ngx_pnalloc() failed");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            (void) ngx_escape_html(p, uri.data, uri.len);
            euri.data = p;
            euri.len = uri.len + len;
        }

        b->last = ngx_sprintf(b->last, NGX_HTTP_VHOST_TRAFFIC_STATUS_HTML_DATA, &euri, &euri);
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


ngx_int_t
ngx_http_vhost_traffic_status_display_get_upstream_nelts(ngx_http_request_t *r)
{
    ngx_uint_t                      i, j, n;
    ngx_http_upstream_server_t     *us;
#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_http_upstream_rr_peer_t    *peer;
    ngx_http_upstream_rr_peers_t   *peers;
#endif
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0, j = 0, n = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        /* groups */
        if (uscf->servers && !uscf->port) {
            us = uscf->servers->elts;

#if (NGX_HTTP_UPSTREAM_ZONE)
            if (uscf->shm_zone == NULL) {
                goto not_supported;
            }

            peers = uscf->peer.data;

            ngx_http_upstream_rr_peers_rlock(peers);

            for (peer = peers->peer; peer; peer = peer->next) {
                n++;
            }

            ngx_http_upstream_rr_peers_unlock(peers);

not_supported:

#endif

            for (j = 0; j < uscf->servers->nelts; j++) {
                n += us[j].naddrs;
            }
        }
    }

    return n;
}


ngx_int_t
ngx_http_vhost_traffic_status_display_get_size(ngx_http_request_t *r,
    ngx_int_t format)
{
    ngx_uint_t                                 size, un;
    ngx_http_vhost_traffic_status_shm_info_t  *shm_info;

    shm_info = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_shm_info_t));
    if (shm_info == NULL) {
        return NGX_ERROR;
    }

    ngx_http_vhost_traffic_status_shm_info(r, shm_info);

    /* allocate memory for the upstream groups even if upstream node not exists */
    un = shm_info->used_node
         + (ngx_uint_t) ngx_http_vhost_traffic_status_display_get_upstream_nelts(r);

    size = 0;

    switch (format) {

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON:
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSONP:
    case NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS:
        size = sizeof(ngx_http_vhost_traffic_status_node_t) / NGX_PTR_SIZE
               * NGX_ATOMIC_T_LEN * un  /* values size */
               + (un * 1024)            /* names  size */
               + 4096;                  /* main   size */
        break;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML:
        size = sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_HTML_DATA) + ngx_pagesize;
        break;
    }

    if (size <= 0) {
        size = shm_info->max_size;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "vts::display_get_size(): size[%ui] used_size[%ui], used_node[%ui]",
                   size, shm_info->used_size, shm_info->used_node);

    return size;
}


u_char *
ngx_http_vhost_traffic_status_display_get_time_queue(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_time_queue_t *q,
    ngx_uint_t offset)
{
    u_char     *p, *s;
    ngx_int_t   i;

    if (q->front == q->rear) {
        return (u_char *) "";
    }

    p = ngx_pcalloc(r->pool, q->len * NGX_INT_T_LEN);
    if (p == NULL) {
        return (u_char *) "";
    }

    s = p;

    for (i = q->front; i != q->rear; i = (i + 1) % q->len) {
        s = ngx_sprintf(s, "%M,", *((ngx_msec_t *) ((char *) &(q->times[i]) + offset)));
    }

    if (s > p) {
       *(s - 1) = '\0';
    }

    return p;
}


u_char *
ngx_http_vhost_traffic_status_display_get_time_queue_times(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_time_queue_t *q)
{
    return ngx_http_vhost_traffic_status_display_get_time_queue(r, q,
               offsetof(ngx_http_vhost_traffic_status_node_time_t, time));
}


u_char *
ngx_http_vhost_traffic_status_display_get_time_queue_msecs(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_time_queue_t *q)
{
    return ngx_http_vhost_traffic_status_display_get_time_queue(r, q,
               offsetof(ngx_http_vhost_traffic_status_node_time_t, msec));
}

    
u_char *
ngx_http_vhost_traffic_status_display_get_histogram_bucket(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_histogram_bucket_t *b,
    ngx_uint_t offset,
    const char *fmt)
{
    char        *dst;
    u_char      *p, *s;
    ngx_uint_t   i, n;

    n = b->len;

    if (n == 0) {
        return (u_char *) "";
    }

    p = ngx_pcalloc(r->pool, n * NGX_INT_T_LEN);
    if (p == NULL) {
        return (u_char *) "";
    }

    s = p;

    for (i = 0; i < n; i++) {
        dst = (char *) &(b->buckets[i]) + offset;

        if (ngx_strncmp(fmt, "%M", 2) == 0) {
            s = ngx_sprintf(s, fmt, *((ngx_msec_t *) dst));

        } else if (ngx_strncmp(fmt, "%uA", 3) == 0) {
            s = ngx_sprintf(s, fmt, *((ngx_atomic_uint_t *) dst));
        }
    }

    if (s > p) {
       *(s - 1) = '\0';
    }

    return p;
}


u_char *
ngx_http_vhost_traffic_status_display_get_histogram_bucket_msecs(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_histogram_bucket_t *b)
{
    return ngx_http_vhost_traffic_status_display_get_histogram_bucket(r, b,
               offsetof(ngx_http_vhost_traffic_status_node_histogram_t, msec), "%M,");
}


u_char *
ngx_http_vhost_traffic_status_display_get_histogram_bucket_counters(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_histogram_bucket_t *b)
{
    return ngx_http_vhost_traffic_status_display_get_histogram_bucket(r, b,
               offsetof(ngx_http_vhost_traffic_status_node_histogram_t, counter), "%uA,");
}


char *
ngx_http_vhost_traffic_status_display(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_vhost_traffic_status_display_handler;

    return NGX_CONF_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
