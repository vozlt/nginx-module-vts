
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 *
 * Patched for t10s: every individual metric family is gated behind its own
 * on/off directive (32 flags total -- see
 * ngx_http_vhost_traffic_status_module.h). server_bytes_total is no longer
 * a hard drop -- it now has its own flag too (display_server_bytes_total,
 * default off), since it's still a pure duplicate of
 * sum(filter_bytes_total{filter="status::$host"}).
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_shm.h"
#include "ngx_http_vhost_traffic_status_display.h"
#include "ngx_http_vhost_traffic_status_display_prometheus.h"


u_char *
ngx_http_vhost_traffic_status_display_prometheus_set_main(ngx_http_request_t *r,
    u_char *buf)
{
    ngx_atomic_int_t                           ap, hn, ac, rq, rd, wr, wa;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;
    ngx_http_vhost_traffic_status_shm_info_t  *shm_info;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (vtscf->display_info) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_INFO_S);
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_INFO,
                          &ngx_cycle->hostname, NGX_HTTP_VTS_MODULE_VERSION, NGINX_VERSION);
    }

    if (vtscf->display_start_time_seconds) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_START_TIME_S);
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_START_TIME,
                          (double) vtscf->start_msec / 1000);
    }

    if (vtscf->display_main_connections) {
        ap = *ngx_stat_accepted;
        hn = *ngx_stat_handled;
        ac = *ngx_stat_active;
        rq = *ngx_stat_requests;
        rd = *ngx_stat_reading;
        wr = *ngx_stat_writing;
        wa = *ngx_stat_waiting;

        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_MAIN_CONNECTIONS_S);
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_MAIN_CONNECTIONS,
                          ap, ac, hn, rd, rq, wa, wr);
    }

    if (vtscf->display_main_shm_usage_bytes) {
        shm_info = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_shm_info_t));
        if (shm_info == NULL) {
            return buf;
        }

        ngx_http_vhost_traffic_status_shm_info(r, shm_info);

        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_MAIN_SHM_S,
                          shm_info->name);
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_MAIN_SHM,
                          shm_info->max_size, shm_info->used_size, shm_info->used_node,
                          shm_info->free_size);
    }

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_prometheus_set_server_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_str_t                                               server;
    ngx_uint_t                                              i, n;
    ngx_http_vhost_traffic_status_loc_conf_t               *vtscf;
    ngx_http_vhost_traffic_status_ctx_t                    *ctx;
    ngx_http_vhost_traffic_status_node_histogram_bucket_t  *b;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    server = *key;

    (void) ngx_http_vhost_traffic_status_node_position_key(&server, 1);

    if (ngx_http_vhost_traffic_status_display_buffer_check(r, buf, key->len,
            NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS) != NGX_OK)
    {
        return buf;
    }

    /* HELP/TYPE headers for every metric below are printed once, up front,
     * by set() -- not here, since this function runs once per node (would
     * otherwise repeat "# HELP ..." for every single host/filter/upstream
     * entry). Only value lines are gated+printed here. */

    /* status_code_requests_total has its own opt-in gate (the
     * vhost_traffic_status_measure_status_codes directive, reflected in
     * ctx->measure_status_codes) -- it doesn't need one of the 32 display
     * flags on top of that. */
    if (ctx->measure_status_codes != NULL && vtsn->stat_status_code_counter != NULL) {
        ngx_uint_t *status_codes = (ngx_uint_t *) ctx->measure_status_codes->elts;

        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_OTHER_STATUS_CODE,
            &server, vtsn->stat_status_code_counter[0]);

        for (i = 0; i < ctx->measure_status_codes->nelts; i++) {
            if (vtsn->stat_status_code_counter[i+1] == 0 && ctx->measure_all_status_codes) {
                continue;
            }

            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_STATUS_CODE,
                &server, status_codes[i], vtsn->stat_status_code_counter[i+1]);
        }
    }

    if (vtscf->display_server_bytes_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_BYTES,
                          &server, vtsn->stat_in_bytes,
                          &server, vtsn->stat_out_bytes);
    }

    if (vtscf->display_server_requests_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_REQUESTS,
                          &server, vtsn->stat_1xx_counter,
                          &server, vtsn->stat_2xx_counter,
                          &server, vtsn->stat_3xx_counter,
                          &server, vtsn->stat_4xx_counter,
                          &server, vtsn->stat_5xx_counter);
    }

    if (vtscf->display_server_request_seconds_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_SECONDS_TOTAL,
                          &server, (double) vtsn->stat_request_time_counter / 1000);
    }

    if (vtscf->display_server_request_seconds) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_SECONDS,
                          &server, (double) ngx_http_vhost_traffic_status_node_time_queue_average(
                                       &vtsn->stat_request_times, vtscf->average_method,
                                       vtscf->average_period) / 1000);
    }

    {
        b = &vtsn->stat_request_buckets;
        n = b->len;

        if (n > 0) {

            if (vtscf->display_server_request_duration_bucket) {
                for (i = 0; i < n; i++) {
                    buf = ngx_sprintf(buf,
                              NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET,
                              &server, (double) b->buckets[i].msec / 1000, b->buckets[i].counter);
                }

                buf = ngx_sprintf(buf,
                          NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET_E,
                          &server, b->observed);
            }

            if (vtscf->display_server_request_duration_sum) {
                buf = ngx_sprintf(buf,
                          NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_SUM,
                          &server, (double) vtsn->stat_request_time_counter / 1000);
            }

            if (vtscf->display_server_request_duration_count) {
                buf = ngx_sprintf(buf,
                          NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_COUNT,
                          &server, vtsn->stat_request_counter);
            }
        }
    }

#if (NGX_HTTP_CACHE)
    if (vtscf->display_server_cache_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_CACHE,
                          &server, vtsn->stat_cache_miss_counter,
                          &server, vtsn->stat_cache_bypass_counter,
                          &server, vtsn->stat_cache_expired_counter,
                          &server, vtsn->stat_cache_stale_counter,
                          &server, vtsn->stat_cache_updating_counter,
                          &server, vtsn->stat_cache_revalidated_counter,
                          &server, vtsn->stat_cache_hit_counter,
                          &server, vtsn->stat_cache_scarce_counter);
    }
#endif

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_prometheus_set_server(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_str_t                                  key, escaped_key;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_node_t      *vtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            ngx_http_vhost_traffic_status_escape_prometheus(r->pool, &escaped_key, key.data, key.len);
            buf = ngx_http_vhost_traffic_status_display_prometheus_set_server_node(r, buf, &escaped_key, vtsn);

            /* calculates the sum -- harmless to always accumulate even
             * when a given field's flag is off (it'll just sum zeros) */
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
                ngx_http_vhost_traffic_status_status_code_merge(vtscf->stats.stat_status_code_counter,
                    vtsn->stat_status_code_counter, ctx->measure_status_codes->nelts+1);
            }

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
#endif
        }

        buf = ngx_http_vhost_traffic_status_display_prometheus_set_server(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_display_prometheus_set_server(r, buf, node->right);
    }

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_prometheus_set_filter_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_str_t                                               filter, filter_name;
    ngx_uint_t                                              i, n;
    ngx_http_vhost_traffic_status_loc_conf_t               *vtscf;
    ngx_http_vhost_traffic_status_node_histogram_bucket_t  *b;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    filter = filter_name = *key;

    (void) ngx_http_vhost_traffic_status_node_position_key(&filter, 1);
    (void) ngx_http_vhost_traffic_status_node_position_key(&filter_name, 2);

    if (ngx_http_vhost_traffic_status_display_buffer_check(r, buf, key->len,
            NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS) != NGX_OK)
    {
        return buf;
    }

    /* HELP/TYPE headers printed once up front by set() -- see comment in
     * set_server_node() above. */

    if (vtscf->display_filter_bytes_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_BYTES,
                          &filter, &filter_name, vtsn->stat_in_bytes,
                          &filter, &filter_name, vtsn->stat_out_bytes);
    }

    if (vtscf->display_filter_requests_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_REQUESTS,
                          &filter, &filter_name, vtsn->stat_1xx_counter,
                          &filter, &filter_name, vtsn->stat_2xx_counter,
                          &filter, &filter_name, vtsn->stat_3xx_counter,
                          &filter, &filter_name, vtsn->stat_4xx_counter,
                          &filter, &filter_name, vtsn->stat_5xx_counter);
    }

    if (vtscf->display_filter_request_seconds_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_SECONDS_TOTAL,
                          &filter, &filter_name, (double) vtsn->stat_request_time_counter / 1000);
    }

    if (vtscf->display_filter_request_seconds) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_SECONDS,
                          &filter, &filter_name,
                          (double) ngx_http_vhost_traffic_status_node_time_queue_average(
                              &vtsn->stat_request_times, vtscf->average_method,
                              vtscf->average_period) / 1000);
    }

    {
        b = &vtsn->stat_request_buckets;
        n = b->len;

        if (n > 0) {

            if (vtscf->display_filter_request_duration_bucket) {
                for (i = 0; i < n; i++) {
                    buf = ngx_sprintf(buf,
                              NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET,
                              &filter, &filter_name, (double) b->buckets[i].msec / 1000,
                              b->buckets[i].counter);
                }

                buf = ngx_sprintf(buf,
                          NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET_E,
                          &filter, &filter_name, b->observed);
            }

            if (vtscf->display_filter_request_duration_sum) {
                buf = ngx_sprintf(buf,
                          NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_SUM,
                          &filter, &filter_name, (double) vtsn->stat_request_time_counter / 1000);
            }

            if (vtscf->display_filter_request_duration_count) {
                buf = ngx_sprintf(buf,
                          NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_COUNT,
                          &filter, &filter_name, vtsn->stat_request_counter);
            }
        }
    }

#if (NGX_HTTP_CACHE)
    if (vtscf->display_filter_cache_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_CACHE,
                          &filter, &filter_name, vtsn->stat_cache_miss_counter,
                          &filter, &filter_name, vtsn->stat_cache_bypass_counter,
                          &filter, &filter_name, vtsn->stat_cache_expired_counter,
                          &filter, &filter_name, vtsn->stat_cache_stale_counter,
                          &filter, &filter_name, vtsn->stat_cache_updating_counter,
                          &filter, &filter_name, vtsn->stat_cache_revalidated_counter,
                          &filter, &filter_name, vtsn->stat_cache_hit_counter,
                          &filter, &filter_name, vtsn->stat_cache_scarce_counter);
    }
#endif

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_prometheus_set_filter(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_str_t                              key, escaped_key;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            ngx_http_vhost_traffic_status_escape_prometheus(r->pool, &escaped_key, key.data, key.len);
            buf = ngx_http_vhost_traffic_status_display_prometheus_set_filter_node(r, buf, &escaped_key, vtsn);
        }

        buf = ngx_http_vhost_traffic_status_display_prometheus_set_filter(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_display_prometheus_set_filter(r, buf, node->right);
    }

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_prometheus_set_upstream_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_str_t                                               target, upstream, upstream_server;
    ngx_uint_t                                              i, n;
    ngx_http_vhost_traffic_status_loc_conf_t               *vtscf;
    ngx_http_vhost_traffic_status_node_histogram_bucket_t  *b;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    upstream = upstream_server = *key;

    if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG) {
        (void) ngx_http_vhost_traffic_status_node_position_key(&upstream, 1);
        (void) ngx_http_vhost_traffic_status_node_position_key(&upstream_server, 2);

    } else if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA) {
        ngx_str_set(&upstream, "::nogroups");
        (void) ngx_http_vhost_traffic_status_node_position_key(&upstream_server, 1);
    }

    if (ngx_http_vhost_traffic_status_display_buffer_check(r, buf,
            key->len + sizeof("::nogroups") - 1,
            NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS) != NGX_OK)
    {
        return buf;
    }

    /* HELP/TYPE headers printed once up front by set() -- see comment in
     * set_server_node() above. */

    if (vtscf->display_upstream_bytes_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_BYTES,
                          &upstream, &upstream_server, vtsn->stat_in_bytes,
                          &upstream, &upstream_server, vtsn->stat_out_bytes);
    }

    if (vtscf->display_upstream_requests_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_REQUESTS,
                          &upstream, &upstream_server, vtsn->stat_1xx_counter,
                          &upstream, &upstream_server, vtsn->stat_2xx_counter,
                          &upstream, &upstream_server, vtsn->stat_3xx_counter,
                          &upstream, &upstream_server, vtsn->stat_4xx_counter,
                          &upstream, &upstream_server, vtsn->stat_5xx_counter);
    }

    if (vtscf->display_upstream_request_seconds_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_REQUEST_SECONDS_TOTAL,
                          &upstream, &upstream_server, (double) vtsn->stat_request_time_counter / 1000);
    }

    if (vtscf->display_upstream_request_seconds) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_REQUEST_SECONDS,
                          &upstream, &upstream_server,
                          (double) ngx_http_vhost_traffic_status_node_time_queue_average(
                              &vtsn->stat_request_times, vtscf->average_method,
                              vtscf->average_period) / 1000);
    }

    if (vtscf->display_upstream_response_seconds_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_RESPONSE_SECONDS_TOTAL,
                          &upstream, &upstream_server, (double) vtsn->stat_upstream.response_time_counter / 1000);
    }

    if (vtscf->display_upstream_response_seconds) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_RESPONSE_SECONDS,
                          &upstream, &upstream_server,
                          (double) ngx_http_vhost_traffic_status_node_time_queue_average(
                              &vtsn->stat_upstream.response_times, vtscf->average_method,
                              vtscf->average_period) / 1000);
    }

    /* request-side histogram (bucket/sum/count independently toggleable) */
    {
        ngx_str_set(&target, "request");
        b = &vtsn->stat_request_buckets;
        n = b->len;

        if (n > 0) {

            if (vtscf->display_upstream_request_duration_bucket) {
                for (i = 0; i < n; i++) {
                    buf = ngx_sprintf(buf,
                            NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET,
                            &target, &upstream, &upstream_server, (double) b->buckets[i].msec / 1000,
                            b->buckets[i].counter);
                }

                buf = ngx_sprintf(buf,
                        NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET_E,
                        &target, &upstream, &upstream_server, b->observed);
            }

            if (vtscf->display_upstream_request_duration_sum) {
                buf = ngx_sprintf(buf,
                        NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_SUM,
                        &target, &upstream, &upstream_server, (double) vtsn->stat_request_time_counter / 1000);
            }

            if (vtscf->display_upstream_request_duration_count) {
                buf = ngx_sprintf(buf,
                        NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_COUNT,
                        &target, &upstream, &upstream_server, vtsn->stat_request_counter);
            }
        }
    }

    /* response-side histogram (bucket/sum/count independently toggleable;
     * +Inf uses b->observed to stay internally consistent with the finite
     * buckets -- see the same reasoning in node.c/shm.c comments) */
    {
        ngx_str_set(&target, "response");
        b = &vtsn->stat_upstream.response_buckets;
        n = b->len;

        if (n > 0) {

            if (vtscf->display_upstream_response_duration_bucket) {
                for (i = 0; i < n; i++) {
                    buf = ngx_sprintf(buf,
                            NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET,
                            &target, &upstream, &upstream_server, (double) b->buckets[i].msec / 1000,
                            b->buckets[i].counter);
                }

                buf = ngx_sprintf(buf,
                        NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET_E,
                        &target, &upstream, &upstream_server, b->observed);
            }

            if (vtscf->display_upstream_response_duration_sum) {
                buf = ngx_sprintf(buf,
                        NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_SUM,
                        &target, &upstream, &upstream_server,
                        (double) vtsn->stat_upstream.response_time_counter / 1000);
            }

            if (vtscf->display_upstream_response_duration_count) {
                buf = ngx_sprintf(buf,
                        NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_COUNT,
                        &target, &upstream, &upstream_server, vtsn->stat_request_counter);
            }
        }
    }

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_prometheus_set_upstream(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_str_t                              key, escaped_key;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG
            || vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA)
        {
            key.data = vtsn->data;
            key.len = vtsn->len;

            ngx_http_vhost_traffic_status_escape_prometheus(r->pool, &escaped_key, key.data, key.len);
            buf = ngx_http_vhost_traffic_status_display_prometheus_set_upstream_node(r, buf, &escaped_key, vtsn);
        }

        buf = ngx_http_vhost_traffic_status_display_prometheus_set_upstream(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_display_prometheus_set_upstream(r, buf, node->right);
    }

    return buf;
}


#if (NGX_HTTP_CACHE)

u_char *
ngx_http_vhost_traffic_status_display_prometheus_set_cache_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_str_t  cache;

    cache = *key;

    (void) ngx_http_vhost_traffic_status_node_position_key(&cache, 1);

    if (ngx_http_vhost_traffic_status_display_buffer_check(r, buf, key->len,
            NGX_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS) != NGX_OK)
    {
        return buf;
    }

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_CACHE,
                      &cache, vtsn->stat_cache_max_size,
                      &cache, vtsn->stat_cache_used_size,
                      &cache, vtsn->stat_in_bytes,
                      &cache, vtsn->stat_out_bytes,
                      &cache, vtsn->stat_cache_miss_counter,
                      &cache, vtsn->stat_cache_bypass_counter,
                      &cache, vtsn->stat_cache_expired_counter,
                      &cache, vtsn->stat_cache_stale_counter,
                      &cache, vtsn->stat_cache_updating_counter,
                      &cache, vtsn->stat_cache_revalidated_counter,
                      &cache, vtsn->stat_cache_hit_counter,
                      &cache, vtsn->stat_cache_scarce_counter);

    return buf;
}


u_char *
ngx_http_vhost_traffic_status_display_prometheus_set_cache(ngx_http_request_t *r,
    u_char *buf, ngx_rbtree_node_t *node)
{
    ngx_str_t                              key, escaped_key;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            ngx_http_vhost_traffic_status_escape_prometheus(r->pool, &escaped_key, key.data, key.len);
            buf = ngx_http_vhost_traffic_status_display_prometheus_set_cache_node(r, buf, &escaped_key, vtsn);
        }

        buf = ngx_http_vhost_traffic_status_display_prometheus_set_cache(r, buf, node->left);
        buf = ngx_http_vhost_traffic_status_display_prometheus_set_cache(r, buf, node->right);
    }

    return buf;
}

#endif


u_char *
ngx_http_vhost_traffic_status_display_prometheus_set(ngx_http_request_t *r,
    u_char *buf)
{
    ngx_str_t                                 escaped_key;
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
        vtscf->stats.stat_status_code_counter = ngx_pcalloc(r->pool, sizeof(ngx_atomic_t) * (ctx->measure_status_codes->nelts+1));
        vtscf->stats.stat_status_code_length = ctx->measure_status_codes->nelts;
    }

    /* main & connections -- each line independently gated inside set_main() */
    buf = ngx_http_vhost_traffic_status_display_prometheus_set_main(r, buf);

    /* serverZones -- HELP/TYPE printed once here (per metric, gated by the
     * same flag the per-node function checks for its value line); the
     * per-node functions below print ONLY value lines. */
    if (vtscf->display_server_bytes_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_BYTES_S);
    }
    if (vtscf->display_server_requests_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_REQUESTS_S);
    }
    if (vtscf->display_server_request_seconds_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_SECONDS_TOTAL_S);
    }
    if (vtscf->display_server_request_seconds) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_SECONDS_S);
    }
    if (vtscf->display_server_request_duration_bucket
        || vtscf->display_server_request_duration_sum
        || vtscf->display_server_request_duration_count)
    {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_S);
    }
#if (NGX_HTTP_CACHE)
    if (vtscf->display_server_cache_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_CACHE_S);
    }
#endif

    buf = ngx_http_vhost_traffic_status_display_prometheus_set_server(r, buf, node);

    ngx_http_vhost_traffic_status_escape_prometheus(r->pool, &escaped_key, vtscf->sum_key.data, vtscf->sum_key.len);
    buf = ngx_http_vhost_traffic_status_display_prometheus_set_server_node(r, buf, &escaped_key, &vtscf->stats);

    /* filterZones */
    o = buf;

    if (vtscf->display_filter_bytes_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_BYTES_S);
    }
    if (vtscf->display_filter_requests_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_REQUESTS_S);
    }
    if (vtscf->display_filter_request_seconds_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_SECONDS_TOTAL_S);
    }
    if (vtscf->display_filter_request_seconds) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_SECONDS_S);
    }
    if (vtscf->display_filter_request_duration_bucket
        || vtscf->display_filter_request_duration_sum
        || vtscf->display_filter_request_duration_count)
    {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_S);
    }
#if (NGX_HTTP_CACHE)
    if (vtscf->display_filter_cache_total) {
        buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_CACHE_S);
    }
#endif

    s = buf;

    buf = ngx_http_vhost_traffic_status_display_prometheus_set_filter(r, buf, node);

    if (s == buf) {
        buf = o;
    }

    /* upstreamZones */
    if (vtscf->stats_by_upstream) {
        o = buf;

        if (vtscf->display_upstream_bytes_total) {
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_BYTES_S);
        }
        if (vtscf->display_upstream_requests_total) {
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_REQUESTS_S);
        }
        if (vtscf->display_upstream_request_duration_bucket
            || vtscf->display_upstream_request_duration_sum
            || vtscf->display_upstream_request_duration_count)
        {
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_REQUEST_HISTOGRAM_S);
        }
        if (vtscf->display_upstream_response_duration_bucket
            || vtscf->display_upstream_response_duration_sum
            || vtscf->display_upstream_response_duration_count)
        {
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_RESPONSE_HISTOGRAM_S);
        }
        if (vtscf->display_upstream_request_seconds_total) {
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_REQUEST_SECONDS_TOTAL_S);
        }
        if (vtscf->display_upstream_request_seconds) {
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_REQUEST_SECONDS_S);
        }
        if (vtscf->display_upstream_response_seconds_total) {
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_RESPONSE_SECONDS_TOTAL_S);
        }
        if (vtscf->display_upstream_response_seconds) {
            buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_RESPONSE_SECONDS_S);
        }

        s = buf;

        buf = ngx_http_vhost_traffic_status_display_prometheus_set_upstream(r, buf, node);

        if (s == buf) {
            buf = o;
        }
    }

#if (NGX_HTTP_CACHE)
    /* cacheZones */
    o = buf;

    buf = ngx_sprintf(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_CACHE_S);

    s = buf;

    buf = ngx_http_vhost_traffic_status_display_prometheus_set_cache(r, buf, node);

    if (s == buf) {
        buf = o;
    }
#endif

    return buf;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
