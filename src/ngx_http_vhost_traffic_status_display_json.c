
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
                      shm_info->used_size, shm_info->used_node);

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_set_server_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_int_t                                  rc;
    ngx_str_t                                  tmp, dst;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    tmp = *key;

    (void) ngx_http_vhost_traffic_status_node_position_key(&tmp, 1);

    rc = ngx_http_vhost_traffic_status_escape_json_pool(r->pool, &dst, &tmp);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "display_set_server_node::escape_json_pool() failed");
    }

#if (NGX_HTTP_CACHE)
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER,
                      &dst, vtsn->stat_request_counter,
                      vtsn->stat_in_bytes,
                      vtsn->stat_out_bytes,
                      vtsn->stat_1xx_counter,
                      vtsn->stat_2xx_counter,
                      vtsn->stat_3xx_counter,
                      vtsn->stat_4xx_counter,
                      vtsn->stat_5xx_counter,
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
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER,
                      key, vtsn->stat_request_counter,
                      vtsn->stat_in_bytes,
                      vtsn->stat_out_bytes,
                      vtsn->stat_1xx_counter,
                      vtsn->stat_2xx_counter,
                      vtsn->stat_3xx_counter,
                      vtsn->stat_4xx_counter,
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

                buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_S,
                                  &filter);

                nodes = filter_nodes->elts;
                for (j = 0; j < filter_nodes->nelts; j++) {
                    buf = ngx_http_vhost_traffic_status_display_set_filter_node(r, buf,
                              nodes[j].node);
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
    size_t                                 len;
    u_char                                *p, *o, *s;
    uint32_t                               hash;
    unsigned                               type, zone;
    ngx_int_t                              rc;
    ngx_str_t                              key, dst;
    ngx_uint_t                             i, j, k;
    ngx_rbtree_node_t                     *node;
    ngx_http_upstream_server_t            *us, usn;
#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_http_upstream_rr_peer_t           *peer;
    ngx_http_upstream_rr_peers_t          *peers;
#endif
    ngx_http_upstream_srv_conf_t          *uscf, **uscfp;
    ngx_http_upstream_main_conf_t         *umcf;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    len = 0;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];
        len = ngx_max(uscf->host.len, len);
    }

    dst.len = len + sizeof("@[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535") - 1;
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return buf;
    }

    p = dst.data;

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

            ngx_http_upstream_rr_peers_rlock(peers);

            for (peer = peers->peer; peer; peer = peer->next) {
                p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
                *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
                p = ngx_cpymem(p, peer->name.data, peer->name.len);

                dst.len = uscf->host.len + sizeof("@") - 1 + peer->name.len;

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
                usn.backup = 0;
#if (NGX_HTTP_UPSTREAM_CHECK)
                if (ngx_http_upstream_check_peer_down(peer->check_index)) {
                    usn.down = 1;

                } else {
                    usn.down = 0;
                }
#else
                usn.down = (peer->fails >= peer->max_fails || peer->down);
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

                p = dst.data;
            }

            ngx_http_upstream_rr_peers_unlock(peers);

not_supported:

#endif

            for (j = 0; j < uscf->servers->nelts; j++) {
                usn = us[j];

                if (zone && usn.backup != 1) {
                    continue;
                }

                /* for all A records */
                for (k = 0; k < usn.naddrs; k++) {
                    p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
                    *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
                    p = ngx_cpymem(p, usn.addrs[k].name.data, usn.addrs[k].name.len);

                    dst.len = uscf->host.len + sizeof("@") - 1 + usn.addrs[k].name.len;

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

                    p = dst.data;
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
    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);

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
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    /* upstreamZones */
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

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
