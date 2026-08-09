
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

static ngx_uint_t ngx_http_vhost_traffic_status_display_node_name_repeat(
    ngx_http_request_t *r, ngx_int_t format);
static size_t ngx_http_vhost_traffic_status_display_node_fixed_size(
    ngx_http_request_t *r, ngx_int_t format);
static void ngx_http_vhost_traffic_status_display_get_size_node(
    ngx_http_request_t *r, ngx_rbtree_node_t *node, ngx_int_t format,
    size_t *size);


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
    ngx_int_t                                  size, rc, expire;
    ngx_str_t                                  type, alpha, encoded_ch, arg_cmd, arg_group, arg_zone, arg_expire;
    ngx_buf_t                                 *b;
    ngx_chain_t                                out;
    ngx_slab_pool_t                           *shpool;
    ngx_http_vhost_traffic_status_control_t   *control;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf->display_buf_end = NULL;

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

            if ((arg_group.len == 1 && ngx_strncmp(arg_group.data, "*", 1) == 0)
                     || (arg_group.len == 3 && ngx_strncasecmp(arg_group.data, (u_char *) "%2A", 3) == 0))
            {
                control->group = -1;
            }
            else if (arg_group.len == 6
                     && ngx_strncasecmp(arg_group.data, (u_char *) "server", 6) == 0)
            {
                control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;
            }
            else if ((arg_group.len == 14
                     && ngx_strncasecmp(arg_group.data, (u_char *) "upstream@alone", 14) == 0)
                     || (arg_group.len == 16
                     && ngx_strncasecmp(arg_group.data, (u_char *) "upstream%40alone", 16) == 0))
            {
                control->group = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;
            }
            else if ((arg_group.len == 14
                     && ngx_strncasecmp(arg_group.data, (u_char *) "upstream@group", 14) == 0)
                     || (arg_group.len == 16
                     && ngx_strncasecmp(arg_group.data, (u_char *) "upstream%40group", 16) == 0))
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

            ngx_str_set(&encoded_ch, "%2A");

            rc = ngx_http_vhost_traffic_status_replace_strc(control->zone, &encoded_ch, '*');
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_handler_control::replace_strc() failed");
            }

            ngx_str_set(&encoded_ch, "%2a");

            rc = ngx_http_vhost_traffic_status_replace_strc(control->zone, &encoded_ch, '*');
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_handler_control::replace_strc() failed");
            }

            ngx_str_set(&encoded_ch, "%3A");

            rc = ngx_http_vhost_traffic_status_replace_strc(control->zone, &encoded_ch, ':');
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_handler_control::replace_strc() failed");
            }

            ngx_str_set(&encoded_ch, "%3a");

            rc = ngx_http_vhost_traffic_status_replace_strc(control->zone, &encoded_ch, ':');
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_handler_control::replace_strc() failed");
            }

            ngx_str_set(&encoded_ch, "%40");

            rc = ngx_http_vhost_traffic_status_replace_strc(control->zone, &encoded_ch, '@');
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_handler_control::replace_strc() failed");
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

        /*
         * expire selects, among what group and zone already match, the nodes
         * whose last request is older than the given number of seconds. A
         * value that does not parse leaves the command undone rather than
         * falling back to deleting everything the selection matches.
         */

        if (ngx_http_arg(r, (u_char *) "expire", 6, &arg_expire) == NGX_OK) {
            expire = ngx_atoi(arg_expire.data, arg_expire.len);

            if (expire == NGX_ERROR || expire < 0) {
                control->command = NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE;

            } else {
                control->expire = (ngx_msec_t) expire * 1000;
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

    vtscf->display_buf_end = b->end;

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
    u_char                                    *o, *s, *p, *last_symbol;
    ngx_str_t                                  uri, euri, type;
    ngx_int_t                                  size, format, rc;
    ngx_buf_t                                 *b;
    ngx_chain_t                                out;
    ngx_slab_pool_t                           *shpool;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf->display_buf_end = NULL;

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

        last_symbol = r->uri.data + r->uri.len;

        if ((s = (u_char *) ngx_strlchr(++s, last_symbol, '/')) == NULL) {
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

    vtscf->display_buf_end = b->end;

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
        /* the link of the page appends to this, so it may not end in a slash */

        while (uri.len && uri.data[uri.len - 1] == '/') {
            uri.len--;
        }

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

        if ((size_t)(b->end - b->last) >= sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_HTML_DATA) + euri.len) {
            b->last = ngx_sprintf(b->last, NGX_HTTP_VHOST_TRAFFIC_STATUS_HTML_DATA, &euri);
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "display_handler_default: not enough buffer for HTML data");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
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


/*
 * Returns how many times the name of a single node can appear in the output
 * of that node.
 */
static ngx_uint_t
ngx_http_vhost_traffic_status_display_node_name_repeat(ngx_http_request_t *r,
    ngx_int_t format)
{
    ngx_uint_t                                 nb, nsc, n;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    if (format != NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS) {
        /*
         * json/jsonp: once for the node itself and once more for the
         * filterZones group the node belongs to.
         */
        return 2;
    }

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    nb = (vtscf->histogram_buckets != NULL) ? vtscf->histogram_buckets->nelts : 0;
    nsc = (ctx->measure_status_codes != NULL) ? ctx->measure_status_codes->nelts + 1 : 0;

    /*
     * Number of metric lines a single node emits, each of them carrying the
     * name of the node at most once (the label pairs of the filterZones and
     * upstreamZones lines are disjoint substrings of the same key):
     *
     *     serverZone   : 9 + 8 (cache) + status codes + (histogram + 3)
     *     filterZone   : 9 + 8 (cache) + (histogram + 3)
     *     upstreamZone : 11 + 2 * (histogram + 3)
     *     cacheZone    : 12
     */
    n = 17 + nsc;

    if (nb) {
        n += 2 * (nb + 3);
    }

    return n;
}


/*
 * Returns the size of the output of a single node, name excluded.
 */
static size_t
ngx_http_vhost_traffic_status_display_node_fixed_size(ngx_http_request_t *r,
    ngx_int_t format)
{
    ngx_uint_t                                 nb, nsc;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    if (format == NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS) {
        return ngx_http_vhost_traffic_status_display_node_name_repeat(r, format)
               * NGX_HTTP_VHOST_TRAFFIC_STATUS_DISPLAY_PROMETHEUS_LINE;
    }

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    nb = (vtscf->histogram_buckets != NULL) ? vtscf->histogram_buckets->nelts : 0;
    nsc = (ctx->measure_status_codes != NULL) ? ctx->measure_status_codes->nelts + 1 : 0;

    /* json/jsonp: the numeric payload of one node */
    return 4 * NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN
             * (NGX_ATOMIC_T_LEN + 1)                    /* time queues       */
           + 4 * nb * (NGX_ATOMIC_T_LEN + 1)             /* histogram buckets */
           + 64 * (NGX_ATOMIC_T_LEN + 1)                 /* counters          */
           + nsc * (NGX_ATOMIC_T_LEN + sizeof(",\"999\":") - 1)  /* statusCodes */
           + 1024;                                       /* literal text      */
}


/*
 * Returns the size that a node whose name is `name_len` bytes long takes in
 * the output. `name_len` is the length of the name *after* escaping.
 */
size_t
ngx_http_vhost_traffic_status_display_node_size(ngx_http_request_t *r,
    size_t name_len, ngx_int_t format)
{
    return ngx_http_vhost_traffic_status_display_node_fixed_size(r, format)
           + name_len
             * ngx_http_vhost_traffic_status_display_node_name_repeat(r, format);
}


/*
 * Returns NGX_OK if the node whose name is `name_len` bytes long still fits
 * into the display buffer. The display handlers size the buffer with
 * ngx_http_vhost_traffic_status_display_get_size(), so this is a safety net
 * against that accounting ever getting out of sync with the writers: the
 * caller must skip the node instead of writing past the end of the buffer.
 */
ngx_int_t
ngx_http_vhost_traffic_status_display_buffer_check(ngx_http_request_t *r,
    u_char *buf, size_t name_len, ngx_int_t format)
{
    size_t                                     need;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    /* not called from a display handler */
    if (vtscf->display_buf_end == NULL) {
        return NGX_OK;
    }

    need = ngx_http_vhost_traffic_status_display_node_size(r, name_len, format);

    if (buf <= vtscf->display_buf_end
        && (size_t) (vtscf->display_buf_end - buf) >= need)
    {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "display_buffer_check::not enough buffer: "
                  "left[%z], need[%uz], name[%uz], format[%i]",
                  (ssize_t) (vtscf->display_buf_end - buf), need, name_len,
                  format);

    return NGX_ERROR;
}


static void
ngx_http_vhost_traffic_status_display_get_size_node(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_int_t format, size_t *size)
{
    size_t                                 len;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node == ctx->rbtree->sentinel) {
        return;
    }

    vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

    if (format == NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS) {
        len = ngx_http_vhost_traffic_status_escape_prometheus_len(vtsn->data,
                                                                  vtsn->len);
    } else {
        len = ngx_http_vhost_traffic_status_escape_json_len(vtsn->data,
                                                            vtsn->len);
    }

    *size += ngx_http_vhost_traffic_status_display_node_size(r, len, format);

    ngx_http_vhost_traffic_status_display_get_size_node(r, node->left, format, size);
    ngx_http_vhost_traffic_status_display_get_size_node(r, node->right, format, size);
}


ngx_int_t
ngx_http_vhost_traffic_status_display_get_size(ngx_http_request_t *r,
    ngx_int_t format)
{
    size_t                                     size;
    ngx_uint_t                                 un;
    ngx_slab_pool_t                           *shpool;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;
    ngx_http_vhost_traffic_status_shm_info_t  *shm_info;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);
    shpool = (ngx_slab_pool_t *) vtscf->shm_zone->shm.addr;

    shm_info = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_shm_info_t));
    if (shm_info == NULL) {
        return NGX_ERROR;
    }

    size = 0;

    switch (format) {

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML:

        /*
         * The page carries the uri of the request, escaped. The handler takes
         * it from r->uri and only ever shortens it, so the whole of it escaped
         * is the bound.
         */

        return sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_HTML_DATA)
               + r->uri.len + ngx_escape_html(NULL, r->uri.data, r->uri.len)
               + ngx_pagesize;

    case NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSONP:
        size += vtscf->jsonp.len + sizeof("()") - 1;
        break;

    default:
        break;
    }

    /* Caveat: Do not use duplicate ngx_shmtx_lock() before this function. */
    ngx_shmtx_lock(&shpool->mutex);

    ngx_http_vhost_traffic_status_shm_info(r, shm_info);

    /*
     * The names of the nodes are taken from the request (Host header, the
     * variables of vhost_traffic_status_filter_by_set_key, ...) and are not
     * length limited, so the size of the output has to be derived from the
     * keys actually stored in the shared memory rather than from a fixed
     * per node allowance.
     */
    ngx_http_vhost_traffic_status_display_get_size_node(r, ctx->rbtree->root,
                                                        format, &size);

    ngx_shmtx_unlock(&shpool->mutex);

    /* the "*" summary node of the serverZones */
    size += ngx_http_vhost_traffic_status_display_node_size(r,
                vtscf->sum_key.len * NGX_HTTP_VHOST_TRAFFIC_STATUS_DISPLAY_JSON_ESCAPE,
                format);

    /* allocate memory for the upstream groups even if upstream node not exists */
    un = (ngx_uint_t) ngx_http_vhost_traffic_status_display_get_upstream_nelts(r);

    size += un * ngx_http_vhost_traffic_status_display_node_size(r,
                     NGX_HTTP_VHOST_TRAFFIC_STATUS_DISPLAY_CONF_NAME_LEN, format);

    /* main, connections, sharedZones and the section headers */
    size += NGX_HTTP_VHOST_TRAFFIC_STATUS_DISPLAY_MAIN_LEN;

    if (size > (size_t) NGX_MAX_INT_T_VALUE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_get_size::size[%uz] too large", size);
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "vts::display_get_size(): size[%uz] used_size[%ui], used_node[%ui]",
                   size, shm_info->used_size, shm_info->used_node);

    return (ngx_int_t) size;
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

    /* NGX_ATOMIC_T_LEN digits and the ',' separator per entry */
    p = ngx_pcalloc(r->pool, q->len * (NGX_ATOMIC_T_LEN + 1));
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

    /* NGX_ATOMIC_T_LEN digits and the ',' separator per bucket */
    p = ngx_pcalloc(r->pool, n * (NGX_ATOMIC_T_LEN + 1));
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
