
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_shm.h"
#include "ngx_http_vhost_traffic_status_filter.h"
#include "ngx_http_vhost_traffic_status_display_json.h"
#include "ngx_http_vhost_traffic_status_display.h"

#if (NGX_HTTP_UPSTREAM_CHECK)
#include "ngx_http_upstream_check_module.h"
#endif


/*
 * The `resolve` parameter of the upstream server directive is available since
 * nginx 1.27.3 and needs an upstream zone. It came with the peers `resolve`
 * list and with NGX_HTTP_UPSTREAM_MODIFY, freenginx has neither of them.
 */
#if (NGX_HTTP_UPSTREAM_ZONE) && (nginx_version >= 1027003)                     \
    && defined(NGX_HTTP_UPSTREAM_MODIFY) && !(defined freenginx)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_RESOLVE  1

/* an upstream group whose names are resolved at run time */
typedef struct {
    ngx_str_t     host;
    ngx_array_t  *names;  /* ngx_str_t, the peers the group has right now */
    ngx_array_t  *gone;   /* ngx_http_vhost_traffic_status_gone_peer_t */
} ngx_http_vhost_traffic_status_resolve_t;


/* a node whose peer does not belong to its upstream group any more */
typedef struct {
    ngx_str_t                              name;
    ngx_http_vhost_traffic_status_node_t  *node;
} ngx_http_vhost_traffic_status_gone_peer_t;


static ngx_array_t *ngx_http_vhost_traffic_status_display_resolves(
    ngx_http_request_t *r);
static ngx_array_t *ngx_http_vhost_traffic_status_display_upstream_peer_names(
    ngx_http_request_t *r, ngx_http_upstream_rr_peers_t *peers);
static ngx_uint_t ngx_http_vhost_traffic_status_display_upstream_peer_exists(
    ngx_array_t *names, ngx_str_t *name);
static ngx_http_vhost_traffic_status_resolve_t *
    ngx_http_vhost_traffic_status_display_resolve_lookup(ngx_array_t *resolves,
    ngx_str_t *host);
static void ngx_http_vhost_traffic_status_display_collect_gone_peers(
    ngx_http_request_t *r, ngx_rbtree_node_t *node, ngx_array_t *resolves);
static u_char *ngx_http_vhost_traffic_status_display_set_upstream_gone(
    ngx_http_request_t *r, u_char *buf, ngx_array_t *gone);
#endif

u_char *
ngx_http_vhost_traffic_status_display_set_main(ngx_http_request_t *r,
    u_char *buf)
{
    ngx_atomic_int_t                           ap, hn, ac, rq, rd, wr, wa;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;
    ngx_http_vhost_traffic_status_shm_info_t  *shm_info;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;
    wa = *ngx_stat_waiting;

    shm_info = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_shm_info_t));
    if (shm_info == NULL) {
        return buf;
    }

    ngx_http_vhost_traffic_status_shm_info(r, shm_info);

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_MAIN, &ngx_cycle->hostname,
                      NGX_HTTP_VTS_MODULE_VERSION, NGINX_VERSION, vtscf->start_msec,
                      ngx_http_vhost_traffic_status_current_msec(),
                      ac, rd, wr, wa, ap, hn, rq,
                      shm_info->name, shm_info->max_size,
                      shm_info->used_size, shm_info->used_node,
                      shm_info->free_size);

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_set_server_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    u_char                                    *p, *c;
    ngx_int_t                                  rc;
    ngx_uint_t                                 i;
    ngx_str_t                                  tmp, dst;
    ngx_uint_t                                *status_codes;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    tmp = *key;

    rc = ngx_http_vhost_traffic_status_node_position_key(&tmp, 1);
    if (rc != NGX_OK) {
        /* 
         * If this function is called in the
         * ngx_http_vhost_traffic_status_display_set_filter_node() function,
         * there is no NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR in key->data.
         * It is normal.
         */
        p = ngx_strlchr(key->data, key->data + key->len, NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR);
        if (p != NULL) {
            p = ngx_pnalloc(r->pool, key->len * 2 + 1);
            c = ngx_hex_dump(p, key->data, key->len);
            *c = '\0';
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "display_set_server_node::node_position_key() key[%s:%p:%d], tmp[:%p:%d] failed",
                          p, key->data, key->len, tmp.data, tmp.len);
        }
    }

    rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &dst, &tmp);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_set_server_node::escape_json_pool() failed");
    }

    if (ngx_http_vhost_traffic_status_display_buffer_check(r, buf, dst.len,
            NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON) != NGX_OK)
    {
        return buf;
    }

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_START,
        &dst, vtsn->stat_request_counter,
        vtsn->stat_in_bytes,
        vtsn->stat_out_bytes);

    if (ctx->measure_status_codes != NULL && vtsn->stat_status_code_counter != NULL) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_STATUS_CODE_START);

        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_OTHER_STATUS_CODE,
            vtsn->stat_status_code_counter[0]);

        status_codes = (ngx_uint_t *) ctx->measure_status_codes->elts;

        for (i = 0; i < ctx->measure_status_codes->nelts; i++) {
            if (vtsn->stat_status_code_counter[i+1] == 0 && ctx->measure_all_status_codes) {
                continue;
            }
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_STATUS_CODE,
                status_codes[i], vtsn->stat_status_code_counter[i+1]);
        }

        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_STATUS_CODE_END);
    }

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_MIDDLE,
        vtsn->stat_1xx_counter,
        vtsn->stat_2xx_counter,
        vtsn->stat_3xx_counter,
        vtsn->stat_4xx_counter,
        vtsn->stat_5xx_counter);


#if (NGX_HTTP_CACHE)
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_END,
                      vtsn->stat_cache_miss_counter,
                      vtsn->stat_cache_bypass_counter,
                      vtsn->stat_cache_expired_counter,
                      vtsn->stat_cache_stale_counter,
                      vtsn->stat_cache_updating_counter,
                      vtsn->stat_cache_revalidated_counter,
                      vtsn->stat_cache_hit_counter,
                      vtsn->stat_cache_scarce_counter,
                      vtsn->stat_request_time_counter,
                      ngx_http_vhost_traffic_status_node_time_queue_average(
                          &vtsn->stat_request_times, vtscf->average_method,
                          vtscf->average_period),
                      ngx_http_vhost_traffic_status_display_get_time_queue_times(r,
                          &vtsn->stat_request_times),
                      ngx_http_vhost_traffic_status_display_get_time_queue_msecs(r,
                          &vtsn->stat_request_times),
                      ngx_http_vhost_traffic_status_display_get_histogram_bucket_msecs(r,
                          &vtsn->stat_request_buckets),
                      ngx_http_vhost_traffic_status_display_get_histogram_bucket_counters(r,
                          &vtsn->stat_request_buckets),
                      ngx_http_vhost_traffic_status_max_integer,
                      vtsn->stat_request_counter_oc,
                      vtsn->stat_in_bytes_oc,
                      vtsn->stat_out_bytes_oc,
                      vtsn->stat_1xx_counter_oc,
                      vtsn->stat_2xx_counter_oc,
                      vtsn->stat_3xx_counter_oc,
                      vtsn->stat_4xx_counter_oc,
                      vtsn->stat_5xx_counter_oc,
                      vtsn->stat_cache_miss_counter_oc,
                      vtsn->stat_cache_bypass_counter_oc,
                      vtsn->stat_cache_expired_counter_oc,
                      vtsn->stat_cache_stale_counter_oc,
                      vtsn->stat_cache_updating_counter_oc,
                      vtsn->stat_cache_revalidated_counter_oc,
                      vtsn->stat_cache_hit_counter_oc,
                      vtsn->stat_cache_scarce_counter_oc,
                      vtsn->stat_request_time_counter_oc);
#else
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_END,
                      vtsn->stat_request_time_counter,
                      ngx_http_vhost_traffic_status_node_time_queue_average(
                          &vtsn->stat_request_times, vtscf->average_method,
                          vtscf->average_period),
                      ngx_http_vhost_traffic_status_display_get_time_queue_times(r,
                          &vtsn->stat_request_times),
                      ngx_http_vhost_traffic_status_display_get_time_queue_msecs(r,
                          &vtsn->stat_request_times),
                      ngx_http_vhost_traffic_status_display_get_histogram_bucket_msecs(r,
                          &vtsn->stat_request_buckets),
                      ngx_http_vhost_traffic_status_display_get_histogram_bucket_counters(r,
                          &vtsn->stat_request_buckets),
                      ngx_http_vhost_traffic_status_max_integer,
                      vtsn->stat_request_counter_oc,
                      vtsn->stat_in_bytes_oc,
                      vtsn->stat_out_bytes_oc,
                      vtsn->stat_1xx_counter_oc,
                      vtsn->stat_2xx_counter_oc,
                      vtsn->stat_3xx_counter_oc,
                      vtsn->stat_4xx_counter_oc,
                      vtsn->stat_5xx_counter_oc,
                      vtsn->stat_request_time_counter_oc);
#endif

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_set_server(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_str_t                                  key;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_node_t      *vtsn, ovtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            ovtsn = vtscf->stats;

            buf = ngx_http_vhost_traffic_status_display_set_server_node(r, buf, &key, vtsn);

            /* calculates the sum */
            vtscf->stats.stat_request_counter += vtsn->stat_request_counter;
            vtscf->stats.stat_in_bytes += vtsn->stat_in_bytes;
            vtscf->stats.stat_out_bytes += vtsn->stat_out_bytes;
            vtscf->stats.stat_1xx_counter += vtsn->stat_1xx_counter;
            vtscf->stats.stat_2xx_counter += vtsn->stat_2xx_counter;
            vtscf->stats.stat_3xx_counter += vtsn->stat_3xx_counter;
            vtscf->stats.stat_4xx_counter += vtsn->stat_4xx_counter;
            vtscf->stats.stat_5xx_counter += vtsn->stat_5xx_counter;
            vtscf->stats.stat_request_time_counter += vtsn->stat_request_time_counter;
            ngx_http_vhost_traffic_status_node_time_queue_merge(
                &vtscf->stats.stat_request_times,
                &vtsn->stat_request_times, vtscf->average_period);

            if (ctx->measure_status_codes != NULL && vtsn->stat_status_code_counter != NULL) {
                ngx_http_vhost_traffic_status_status_code_merge(
                    vtscf->stats.stat_status_code_counter,
                    vtsn->stat_status_code_counter, ctx->measure_status_codes->nelts+1);
            }

            vtscf->stats.stat_request_counter_oc += vtsn->stat_request_counter_oc;
            vtscf->stats.stat_in_bytes_oc += vtsn->stat_in_bytes_oc;
            vtscf->stats.stat_out_bytes_oc += vtsn->stat_out_bytes_oc;
            vtscf->stats.stat_1xx_counter_oc += vtsn->stat_1xx_counter_oc;
            vtscf->stats.stat_2xx_counter_oc += vtsn->stat_2xx_counter_oc;
            vtscf->stats.stat_3xx_counter_oc += vtsn->stat_3xx_counter_oc;
            vtscf->stats.stat_4xx_counter_oc += vtsn->stat_4xx_counter_oc;
            vtscf->stats.stat_5xx_counter_oc += vtsn->stat_5xx_counter_oc;
            vtscf->stats.stat_request_time_counter_oc += vtsn->stat_request_time_counter_oc;

#if (NGX_HTTP_CACHE)
            vtscf->stats.stat_cache_miss_counter +=
                                       vtsn->stat_cache_miss_counter;
            vtscf->stats.stat_cache_bypass_counter +=
                                       vtsn->stat_cache_bypass_counter;
            vtscf->stats.stat_cache_expired_counter +=
                                       vtsn->stat_cache_expired_counter;
            vtscf->stats.stat_cache_stale_counter +=
                                       vtsn->stat_cache_stale_counter;
            vtscf->stats.stat_cache_updating_counter +=
                                       vtsn->stat_cache_updating_counter;
            vtscf->stats.stat_cache_revalidated_counter +=
                                       vtsn->stat_cache_revalidated_counter;
            vtscf->stats.stat_cache_hit_counter +=
                                       vtsn->stat_cache_hit_counter;
            vtscf->stats.stat_cache_scarce_counter +=
                                       vtsn->stat_cache_scarce_counter;

            vtscf->stats.stat_cache_miss_counter_oc +=
                                       vtsn->stat_cache_miss_counter_oc;
            vtscf->stats.stat_cache_bypass_counter_oc +=
                                       vtsn->stat_cache_bypass_counter_oc;
            vtscf->stats.stat_cache_expired_counter_oc +=
                                       vtsn->stat_cache_expired_counter_oc;
            vtscf->stats.stat_cache_stale_counter_oc +=
                                       vtsn->stat_cache_stale_counter_oc;
            vtscf->stats.stat_cache_updating_counter_oc +=
                                       vtsn->stat_cache_updating_counter_oc;
            vtscf->stats.stat_cache_revalidated_counter_oc +=
                                       vtsn->stat_cache_revalidated_counter_oc;
            vtscf->stats.stat_cache_hit_counter_oc +=
                                       vtsn->stat_cache_hit_counter_oc;
            vtscf->stats.stat_cache_scarce_counter_oc +=
                                       vtsn->stat_cache_scarce_counter_oc;
#endif

            ngx_http_vhost_traffic_status_add_oc((&ovtsn), (&vtscf->stats));
        }

        buf = ngx_http_vhost_traffic_status_display_set_server(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_display_set_server(r, buf, node->right);
    }

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_set_filter_node(ngx_http_request_t *r,
    u_char *buf, ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_str_t   key;

    key.data = vtsn->data;
    key.len = vtsn->len;

    (void) ngx_http_vhost_traffic_status_node_position_key(&key, 2);

    return ngx_http_vhost_traffic_status_display_set_server_node(r, buf, &key, vtsn);
}

u_char *
ngx_http_vhost_traffic_status_display_set_filter(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    u_char                                       *o, *s;
    ngx_str_t                                     key, filter;
    ngx_uint_t                                    i, j, n, rc;
    ngx_array_t                                  *filter_keys, *filter_nodes;
    ngx_http_vhost_traffic_status_filter_key_t   *keys;
    ngx_http_vhost_traffic_status_filter_node_t  *nodes;

    /* init array */
    filter_keys = NULL;
    filter_nodes = NULL;

    rc = ngx_http_vhost_traffic_status_filter_get_keys(r, &filter_keys, node);

    if (filter_keys != NULL && rc == NGX_OK) {
        keys = filter_keys->elts;
        n = filter_keys->nelts;

        if (n > 1) {
            ngx_qsort(keys, (size_t) n,
                      sizeof(ngx_http_vhost_traffic_status_filter_key_t),
                      ngx_http_traffic_status_filter_cmp_keys);
        }

        ngx_memzero(&key, sizeof(ngx_str_t));

        for (i = 0; i < n; i++) {
            if (keys[i].key.len == key.len) {
                if (ngx_strncmp(keys[i].key.data, key.data, key.len) == 0) {
                    continue;
                }
            }
            key = keys[i].key;

            rc = ngx_http_vhost_traffic_status_filter_get_nodes(r, &filter_nodes, &key, node);

            if (filter_nodes != NULL && rc == NGX_OK) {
                rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &filter, &keys[i].key);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "display_set_filter::escape_json_pool() failed");
                }

                if (ngx_http_vhost_traffic_status_display_buffer_check(r, buf,
                        filter.len, NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON)
                    != NGX_OK)
                {
                    break;
                }

                o = buf;

                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_S,
                                  &filter);

                s = buf;

                nodes = filter_nodes->elts;
                for (j = 0; j < filter_nodes->nelts; j++) {
                    buf = ngx_http_vhost_traffic_status_display_set_filter_node(r, buf,
                              nodes[j].node);
                }

                /* all the nodes of this group have been skipped */
                if (s == buf) {
                    buf = o;
                    filter_nodes = NULL;
                    continue;
                }

                buf--;
                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_E);
                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);

                /* destroy array to prevent duplication */
                filter_nodes = NULL;
            }

        }

        /* destroy array */
        for (i = 0; i < n; i++) {
             if (keys[i].key.data != NULL) {
                 ngx_pfree(r->pool, keys[i].key.data);
             }
        }
        filter_keys = NULL;
    }

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_set_upstream_node(ngx_http_request_t *r,
     u_char *buf, ngx_http_upstream_server_t *us,
#if nginx_version > 1007001
     ngx_http_vhost_traffic_status_node_t *vtsn
#else
     ngx_http_vhost_traffic_status_node_t *vtsn, ngx_str_t *name
#endif
     )
{
    ngx_int_t                                  rc;
    ngx_str_t                                  key;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

#if nginx_version > 1007001
    rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &key, &us->name);
#else
    rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &key, name);
#endif

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_set_upstream_node::escape_json_pool() failed");
    }

    if (ngx_http_vhost_traffic_status_display_buffer_check(r, buf, key.len,
            NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON) != NGX_OK)
    {
        return buf;
    }

    if (vtsn != NULL) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM,
                &key, vtsn->stat_request_counter,
                vtsn->stat_in_bytes, vtsn->stat_out_bytes,
                vtsn->stat_1xx_counter, vtsn->stat_2xx_counter,
                vtsn->stat_3xx_counter, vtsn->stat_4xx_counter,
                vtsn->stat_5xx_counter,
                vtsn->stat_request_time_counter,
                ngx_http_vhost_traffic_status_node_time_queue_average(
                    &vtsn->stat_request_times, vtscf->average_method,
                    vtscf->average_period),
                ngx_http_vhost_traffic_status_display_get_time_queue_times(r,
                    &vtsn->stat_request_times),
                ngx_http_vhost_traffic_status_display_get_time_queue_msecs(r,
                    &vtsn->stat_request_times),
                ngx_http_vhost_traffic_status_display_get_histogram_bucket_msecs(r,
                    &vtsn->stat_request_buckets),
                ngx_http_vhost_traffic_status_display_get_histogram_bucket_counters(r,
                    &vtsn->stat_request_buckets),
                vtsn->stat_upstream.response_time_counter,
                ngx_http_vhost_traffic_status_node_time_queue_average(
                    &vtsn->stat_upstream.response_times, vtscf->average_method,
                    vtscf->average_period),
                ngx_http_vhost_traffic_status_display_get_time_queue_times(r,
                    &vtsn->stat_upstream.response_times),
                ngx_http_vhost_traffic_status_display_get_time_queue_msecs(r,
                    &vtsn->stat_upstream.response_times),
                ngx_http_vhost_traffic_status_display_get_histogram_bucket_msecs(r,
                    &vtsn->stat_upstream.response_buckets),
                ngx_http_vhost_traffic_status_display_get_histogram_bucket_counters(r,
                    &vtsn->stat_upstream.response_buckets),
                us->weight, us->max_fails,
                us->fail_timeout,
                ngx_http_vhost_traffic_status_boolean_to_string(us->backup),
                ngx_http_vhost_traffic_status_boolean_to_string(us->down),
                ngx_http_vhost_traffic_status_max_integer,
                vtsn->stat_request_counter_oc, vtsn->stat_in_bytes_oc,
                vtsn->stat_out_bytes_oc, vtsn->stat_1xx_counter_oc,
                vtsn->stat_2xx_counter_oc, vtsn->stat_3xx_counter_oc,
                vtsn->stat_4xx_counter_oc, vtsn->stat_5xx_counter_oc,
                vtsn->stat_request_time_counter_oc, vtsn->stat_response_time_counter_oc);

    } else {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM,
                &key, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0,
                (ngx_msec_t) 0,
                (u_char *) "", (u_char *) "",
                (u_char *) "", (u_char *) "",
                (ngx_atomic_uint_t) 0,
                (ngx_msec_t) 0,
                (u_char *) "", (u_char *) "",
                (u_char *) "", (u_char *) "",
                us->weight, us->max_fails,
                us->fail_timeout,
                ngx_http_vhost_traffic_status_boolean_to_string(us->backup),
                ngx_http_vhost_traffic_status_boolean_to_string(us->down),
                ngx_http_vhost_traffic_status_max_integer,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0,
                (ngx_atomic_uint_t) 0, (ngx_atomic_uint_t) 0);
    }

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_set_upstream_alone(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    unsigned                               type;
    ngx_str_t                              key;
    ngx_http_upstream_server_t             us;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == type) {
            key.len = vtsn->len;
            key.data = vtsn->data;

            (void) ngx_http_vhost_traffic_status_node_position_key(&key, 1);

#if nginx_version > 1007001
            us.name = key;
#endif
            us.weight = 0;
            us.max_fails = 0;
            us.fail_timeout = 0;
            us.down = 0;
            us.backup = 0;

#if nginx_version > 1007001
            buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &us, vtsn);
#else
            buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &us, vtsn, &key);
#endif
        }

        buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(r, buf, node->right);
    }

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_set_upstream_group(ngx_http_request_t *r,
    u_char *buf)
{
    u_char                                *p, *o, *s;
    uint32_t                               hash;
    unsigned                               type, zone;
    ngx_int_t                              rc;
    ngx_str_t                              key, dst;
    ngx_uint_t                             i, j, k;
    ngx_rbtree_node_t                     *node;
    ngx_http_upstream_server_t            *us, usn;
#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_uint_t                             backup;
    ngx_http_upstream_rr_peer_t           *peer;
    ngx_http_upstream_rr_peers_t          *peers;
#endif
#if (NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_RESOLVE)
    ngx_array_t                             *resolves;
    ngx_http_vhost_traffic_status_resolve_t *rs;
#endif
    ngx_http_upstream_srv_conf_t          *uscf, **uscfp;
    ngx_http_upstream_main_conf_t         *umcf;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    /*
     * The key of a peer is the name of its group, the separator and the name
     * of the peer. This used to be built in one buffer held for the whole
     * walk, sized for the longest group name and an address and a port, on
     * the reading that a peer is never named anything longer. A unix socket
     * is named by its path, which passes that easily, and the overflow did
     * more than run off the end: node_generate_key() takes the key from the
     * same pool with ngx_pcalloc, which zeroes a region overlapping the tail
     * just written, so the name was cut short, the lookup missed, and the
     * peer read as though it had served nothing (#378).
     *
     * Each key is now given the room it needs where it is built.
     */

#if (NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_RESOLVE)
    /*
     * The nodes of the peers that a re-resolve took out of their upstream
     * group are collected in one pass over the tree, walking it once per
     * group would cost as many passes as there are groups.
     */
    resolves = ngx_http_vhost_traffic_status_display_resolves(r);

    if (resolves != NULL) {
        ngx_http_vhost_traffic_status_display_collect_gone_peers(r,
            ctx->rbtree->root, resolves);
    }
#endif

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        /* groups */
        if (uscf->servers && !uscf->port) {
            us = uscf->servers->elts;

            type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;

            o = buf;

            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S,
                              &uscf->host);
            s = buf;

            zone = 0;

#if (NGX_HTTP_UPSTREAM_ZONE)
            if (uscf->shm_zone == NULL) {
                goto not_supported;
            }

            zone = 1;

            peers = uscf->peer.data;

            /*
             * A peer that a `resolve` line makes at run time is not named by
             * any server line, and nginx builds a resolve list for the backup
             * servers too. Both lists are walked, and the flag comes from the
             * one the peer was found in - the server lines cannot say it here.
             */
            for (backup = 0; peers; peers = peers->next, backup = 1) {

                ngx_http_upstream_rr_peers_rlock(peers);

                for (peer = peers->peer; peer; peer = peer->next) {
                    dst.len = uscf->host.len + sizeof("@") - 1 + peer->name.len;
                    dst.data = ngx_pnalloc(r->pool, dst.len);
                    if (dst.data == NULL) {
                        ngx_http_upstream_rr_peers_unlock(peers);
                        return buf;
                    }

                    p = dst.data;
                    p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
                    *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
                    p = ngx_cpymem(p, peer->name.data, peer->name.len);

                    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
                    if (rc != NGX_OK) {
                        ngx_http_upstream_rr_peers_unlock(peers);
                        return buf;
                    }

                    hash = ngx_crc32_short(key.data, key.len);
                    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

                    usn.weight = peer->weight;
                    usn.max_fails = peer->max_fails;
                    usn.fail_timeout = peer->fail_timeout;
                    usn.backup = backup;
#if (NGX_HTTP_UPSTREAM_CHECK)
                    if (ngx_http_upstream_check_peer_down(peer->check_index)) {
                        usn.down = 1;

                    } else {
                        usn.down = 0;
                    }
#else
                    /*
                     * max_fails 0 turns the counting off, which nginx reads as
                     * never taking the peer out; without the guard the comparison
                     * holds from the first request and every such peer is called
                     * down
                     */
                    usn.down = (peer->down
                                || (peer->max_fails
                                    && peer->fails >= peer->max_fails));
#endif

#if nginx_version > 1007001
                    usn.name = peer->name;
#endif

                    if (node != NULL) {
                        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
#if nginx_version > 1007001
                        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn);
#else
                        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn, &peer->name);
#endif

                    } else {
#if nginx_version > 1007001
                        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL);
#else
                        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL, &peer->name);
#endif
                    }

                }

                ngx_http_upstream_rr_peers_unlock(peers);
            }

#if (NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_RESOLVE)
            /*
             * The peers of an upstream that resolves the names at run time are
             * replaced whenever the names are re-resolved. The nodes of the
             * peers that are not part of the group any more still hold their
             * statistics, add them after the current peers.
             */
            if (resolves != NULL) {
                rs = ngx_http_vhost_traffic_status_display_resolve_lookup(
                         resolves, &uscf->host);

                if (rs != NULL && rs->gone != NULL) {
                    buf = ngx_http_vhost_traffic_status_display_set_upstream_gone(
                              r, buf, rs->gone);
                }
            }
#endif

not_supported:

#endif

            /*
             * The server lines are read only when there is no zone to read
             * instead. They used to supply the backup peers, which is where
             * a resolving line went missing: it leaves an address whose name
             * was never set, so what came out was an empty server name.
             */
            for (j = 0; !zone && j < uscf->servers->nelts; j++) {
                usn = us[j];

                /* for all A records */
                for (k = 0; k < usn.naddrs; k++) {
                    dst.len = uscf->host.len + sizeof("@") - 1
                              + usn.addrs[k].name.len;
                    dst.data = ngx_pnalloc(r->pool, dst.len);
                    if (dst.data == NULL) {
                        return buf;
                    }

                    p = dst.data;
                    p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
                    *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
                    p = ngx_cpymem(p, usn.addrs[k].name.data, usn.addrs[k].name.len);

                    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
                    if (rc != NGX_OK) {
                        return buf;
                    }

                    hash = ngx_crc32_short(key.data, key.len);
                    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

#if nginx_version > 1007001
                    usn.name = usn.addrs[k].name;
#endif

                    if (node != NULL) {
                        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;
#if nginx_version > 1007001
                        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn);
#else
                        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn, &usn.addrs[k].name);
#endif

                    } else {
#if nginx_version > 1007001
                        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL);
#else
                        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL, &usn.addrs[k].name);
#endif
                    }

                }
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

    buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(r, buf, ctx->rbtree->root);

    if (s == buf) {
        buf = o;

    } else {
        buf--;
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    return buf;
}


#if (NGX_HTTP_CACHE)

u_char
*ngx_http_vhost_traffic_status_display_set_cache_node(ngx_http_request_t *r,
    u_char *buf, ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_int_t  rc;
    ngx_str_t  key, dst;

    dst.data = vtsn->data;
    dst.len = vtsn->len;

    (void) ngx_http_vhost_traffic_status_node_position_key(&dst, 1);

    rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &key, &dst);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_set_cache_node::escape_json_pool() failed");
    }

    if (ngx_http_vhost_traffic_status_display_buffer_check(r, buf, key.len,
            NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON) != NGX_OK)
    {
        return buf;
    }

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE,
                      &key, vtsn->stat_cache_max_size,
                      vtsn->stat_cache_used_size,
                      vtsn->stat_in_bytes,
                      vtsn->stat_out_bytes,
                      vtsn->stat_cache_miss_counter,
                      vtsn->stat_cache_bypass_counter,
                      vtsn->stat_cache_expired_counter,
                      vtsn->stat_cache_stale_counter,
                      vtsn->stat_cache_updating_counter,
                      vtsn->stat_cache_revalidated_counter,
                      vtsn->stat_cache_hit_counter,
                      vtsn->stat_cache_scarce_counter,
                      ngx_http_vhost_traffic_status_max_integer,
                      vtsn->stat_request_counter_oc,
                      vtsn->stat_in_bytes_oc,
                      vtsn->stat_out_bytes_oc,
                      vtsn->stat_1xx_counter_oc,
                      vtsn->stat_2xx_counter_oc,
                      vtsn->stat_3xx_counter_oc,
                      vtsn->stat_4xx_counter_oc,
                      vtsn->stat_5xx_counter_oc,
                      vtsn->stat_cache_miss_counter_oc,
                      vtsn->stat_cache_bypass_counter_oc,
                      vtsn->stat_cache_expired_counter_oc,
                      vtsn->stat_cache_stale_counter_oc,
                      vtsn->stat_cache_updating_counter_oc,
                      vtsn->stat_cache_revalidated_counter_oc,
                      vtsn->stat_cache_hit_counter_oc,
                      vtsn->stat_cache_scarce_counter_oc);

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_set_cache(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC) {
            buf = ngx_http_vhost_traffic_status_display_set_cache_node(r, buf, vtsn);
        }

        buf = ngx_http_vhost_traffic_status_display_set_cache(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_display_set_cache(r, buf, node->right);
    }

    return buf;
}

#endif


u_char *
ngx_http_vhost_traffic_status_display_set(ngx_http_request_t *r,
    u_char *buf)
{
    u_char                                    *o, *s;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;

    /* init stats */
    ngx_memzero(&vtscf->stats, sizeof(vtscf->stats));
    ngx_http_vhost_traffic_status_node_time_queue_init(&vtscf->stats.stat_request_times);

    if (ctx->measure_status_codes != NULL) {
        vtscf->stats.stat_status_code_counter = ngx_pcalloc(r->pool, sizeof(ngx_atomic_t) * (ctx->measure_status_codes->nelts +1));
        vtscf->stats.stat_status_code_length = ctx->measure_status_codes->nelts;
    }

    /* main & connections */
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);

    buf = ngx_http_vhost_traffic_status_display_set_main(r, buf);

    /* serverZones */
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S);

    buf = ngx_http_vhost_traffic_status_display_set_server(r, buf, node);

    buf = ngx_http_vhost_traffic_status_display_set_server_node(r, buf, &vtscf->sum_key,
                                                                &vtscf->stats);

    buf--;
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
    if (vtscf->stats_by_upstream) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    /* filterZones */
    o = buf;

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER_S);

    s = buf;

    buf = ngx_http_vhost_traffic_status_display_set_filter(r, buf, node);

    if (s == buf) {
        buf = o;

    } else {
        buf--;
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
        if (vtscf->stats_by_upstream) {
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
        }
    }

    /* upstreamZones */
    if (vtscf->stats_by_upstream) {
        o = buf;

        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S);

        s = buf;

        buf = ngx_http_vhost_traffic_status_display_set_upstream_group(r, buf);

        if (s == buf) {
            buf = o;
            buf--;

        } else {
            buf--;
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
        }
    }

#if (NGX_HTTP_CACHE)
    /* cacheZones */
    o = buf;

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE_S);

    s = buf;

    buf = ngx_http_vhost_traffic_status_display_set_cache(r, buf, node);

    if (s == buf) {
        buf = o;

    } else {
        buf--;
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
    }
#endif

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);

    return buf;
}

#if (NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_RESOLVE)

static int ngx_libc_cdecl
ngx_http_vhost_traffic_status_display_resolve_cmp(const void *one,
    const void *two)
{
    ngx_http_vhost_traffic_status_resolve_t  *first, *second;

    first = (ngx_http_vhost_traffic_status_resolve_t *) one;
    second = (ngx_http_vhost_traffic_status_resolve_t *) two;

    return (int) ngx_memn2cmp(first->host.data, second->host.data,
                              first->host.len, second->host.len);
}


/*
 * Returns the upstream groups that resolve their names at run time together
 * with the peers they have right now, sorted by host so that a node can be
 * matched to its group with a binary search. NULL when there is none, which
 * is the usual case.
 */
static ngx_array_t *
ngx_http_vhost_traffic_status_display_resolves(ngx_http_request_t *r)
{
    ngx_uint_t                                i;
    ngx_array_t                              *resolves;
    ngx_http_upstream_rr_peers_t             *peers, *rpeers;
    ngx_http_upstream_srv_conf_t             *uscf, **uscfp;
    ngx_http_upstream_main_conf_t            *umcf;
    ngx_http_vhost_traffic_status_resolve_t  *rs;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    resolves = NULL;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        if (uscf->servers == NULL || uscf->port || uscf->shm_zone == NULL) {
            continue;
        }

        /*
         * Either list can be the one that resolves: nginx builds a resolve
         * list for the backup servers as well, so a group whose only
         * resolving line is a backup has peers->resolve == NULL and a
         * peers->next->resolve. Reading the primary list alone skips such a
         * group, and what a replaced backup served stays in the tree with
         * nothing pointing at it.
         */

        peers = uscf->peer.data;

        for (rpeers = peers; rpeers; rpeers = rpeers->next) {
            if (rpeers->resolve != NULL) {
                break;
            }
        }

        if (rpeers == NULL) {
            continue;
        }

        if (resolves == NULL) {
            resolves = ngx_array_create(r->pool, 2,
                           sizeof(ngx_http_vhost_traffic_status_resolve_t));
            if (resolves == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_resolves::ngx_array_create() failed");
                return NULL;
            }
        }

        rs = ngx_array_push(resolves);
        if (rs == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "display_resolves::ngx_array_push() failed");
            return NULL;
        }

        rs->host = uscf->host;
        rs->gone = NULL;
        rs->names = ngx_http_vhost_traffic_status_display_upstream_peer_names(r,
                        peers);

        if (rs->names == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "display_resolves::upstream_peer_names() failed");
            return NULL;
        }
    }

    if (resolves != NULL && resolves->nelts > 1) {
        ngx_qsort(resolves->elts, (size_t) resolves->nelts,
                  sizeof(ngx_http_vhost_traffic_status_resolve_t),
                  ngx_http_vhost_traffic_status_display_resolve_cmp);
    }

    return resolves;
}


/*
 * Returns the names of the peers that currently belong to the upstream group,
 * backup peers included. The names are copied because the peers themselves may
 * be replaced by a re-resolve as soon as the lock is released.
 */
static ngx_array_t *
ngx_http_vhost_traffic_status_display_upstream_peer_names(ngx_http_request_t *r,
    ngx_http_upstream_rr_peers_t *peers)
{
    u_char                       *p;
    ngx_str_t                    *name;
    ngx_array_t                  *names;
    ngx_http_upstream_rr_peer_t  *peer;

    names = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
    if (names == NULL) {
        return NULL;
    }

    for ( /* void */ ; peers; peers = peers->next) {

        ngx_http_upstream_rr_peers_rlock(peers);

        for (peer = peers->peer; peer; peer = peer->next) {

            name = ngx_array_push(names);
            if (name == NULL) {
                ngx_http_upstream_rr_peers_unlock(peers);
                return NULL;
            }

            p = ngx_pnalloc(r->pool, peer->name.len);
            if (p == NULL) {
                ngx_http_upstream_rr_peers_unlock(peers);
                return NULL;
            }

            ngx_memcpy(p, peer->name.data, peer->name.len);

            name->data = p;
            name->len = peer->name.len;
        }

        ngx_http_upstream_rr_peers_unlock(peers);
    }

    return names;
}


static ngx_uint_t
ngx_http_vhost_traffic_status_display_upstream_peer_exists(ngx_array_t *names,
    ngx_str_t *name)
{
    ngx_str_t   *n;
    ngx_uint_t   i;

    n = names->elts;

    for (i = 0; i < names->nelts; i++) {
        if (n[i].len == name->len
            && ngx_memcmp(n[i].data, name->data, name->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static ngx_http_vhost_traffic_status_resolve_t *
ngx_http_vhost_traffic_status_display_resolve_lookup(ngx_array_t *resolves,
    ngx_str_t *host)
{
    ngx_int_t                                 rc, l, m, h;
    ngx_http_vhost_traffic_status_resolve_t  *rs;

    rs = resolves->elts;

    l = 0;
    h = (ngx_int_t) resolves->nelts - 1;

    while (l <= h) {
        m = l + (h - l) / 2;

        rc = ngx_memn2cmp(host->data, rs[m].host.data,
                          host->len, rs[m].host.len);

        if (rc == 0) {
            return &rs[m];
        }

        if (rc < 0) {
            h = m - 1;

        } else {
            l = m + 1;
        }
    }

    return NULL;
}


/*
 * Walks the tree once and hands every upstream group node whose peer is not
 * part of its group any more to that group.
 */
static void
ngx_http_vhost_traffic_status_display_collect_gone_peers(ngx_http_request_t *r,
    ngx_rbtree_node_t *node, ngx_array_t *resolves)
{
    u_char                                    *p, *last;
    ngx_str_t                                  host, name;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_node_t      *vtsn;
    ngx_http_vhost_traffic_status_resolve_t   *rs;
    ngx_http_vhost_traffic_status_gone_peer_t *gone;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node == ctx->rbtree->sentinel) {
        return;
    }

    vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

    /* the key of an upstream group node is "UG" 0x1f host 0x1f peer */

    if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG
        && vtsn->len > NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_KEY_LEN)
    {
        last = vtsn->data + vtsn->len;
        host.data = vtsn->data
                    + NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_PREFIX_LEN;

        p = ngx_strlchr(host.data, last,
                        NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR);

        if (p != NULL && p + 1 < last) {
            host.len = p - host.data;
            name.data = p + 1;
            name.len = last - name.data;

            rs = ngx_http_vhost_traffic_status_display_resolve_lookup(resolves,
                     &host);

            if (rs != NULL
                && !ngx_http_vhost_traffic_status_display_upstream_peer_exists(
                        rs->names, &name))
            {
                if (rs->gone == NULL) {
                    rs->gone = ngx_array_create(r->pool, 1,
                          sizeof(ngx_http_vhost_traffic_status_gone_peer_t));
                }

                if (rs->gone != NULL) {
                    gone = ngx_array_push(rs->gone);

                    if (gone != NULL) {
                        gone->name = name;
                        gone->node = vtsn;

                    } else {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "collect_gone_peers::ngx_array_push() "
                                      "failed");
                    }
                }
            }
        }
    }

    ngx_http_vhost_traffic_status_display_collect_gone_peers(r, node->left,
        resolves);
    ngx_http_vhost_traffic_status_display_collect_gone_peers(r, node->right,
        resolves);
}


static u_char *
ngx_http_vhost_traffic_status_display_set_upstream_gone(ngx_http_request_t *r,
    u_char *buf, ngx_array_t *gone)
{
    ngx_uint_t                                  i;
    ngx_http_upstream_server_t                  usn;
    ngx_http_vhost_traffic_status_gone_peer_t  *peers;

    peers = gone->elts;

    for (i = 0; i < gone->nelts; i++) {

        ngx_memzero(&usn, sizeof(ngx_http_upstream_server_t));

        usn.name = peers[i].name;

        /* the peer does not take any request any more */
        usn.down = 1;

        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf,
                  &usn, peers[i].node);
    }

    return buf;
}

#endif

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
