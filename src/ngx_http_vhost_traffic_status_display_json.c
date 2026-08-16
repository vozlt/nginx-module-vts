
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_shm.h"
#include "ngx_http_vhost_traffic_status_filter.h"
#include "ngx_http_vhost_traffic_status_display_json.h"
#include "ngx_http_vhost_traffic_status_display.h"
#include "ngx_http_vhost_traffic_status_upstream.h"


/*
 * An upstream group is written out of its `server` lines and, where there is a
 * zone, out of the peers the group holds. A node keyed under the group whose
 * peer is in neither is never reached, and its statistics sit in the tree with
 * nothing pointing at them. Three things put a peer there:
 *
 *   - a balancer_by_lua block picks an address of its own (#155)
 *   - a re-resolve replaces the peers of a resolving group (#357)
 *   - a server line is taken out of the configuration
 *
 * They are one case, and the peers of every group are collected in one pass
 * over the tree: walking it once per group would cost as many passes as there
 * are groups.
 */

/* an upstream group, and the peers of it that no longer exist */
typedef struct {
    ngx_str_t     host;
    ngx_array_t  *names;  /* ngx_str_t, the peers the group has right now */
    ngx_array_t  *gone;   /* ngx_http_vhost_traffic_status_gone_peer_t */
} ngx_http_vhost_traffic_status_upstream_group_t;


/* a node whose peer does not belong to its upstream group any more */
typedef struct {
    ngx_str_t                              name;
    ngx_http_vhost_traffic_status_node_t  *node;
} ngx_http_vhost_traffic_status_gone_peer_t;


/* what set_upstream_group() carries through the walk of one group */
typedef struct {
    u_char                               *buf;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;
} ngx_http_vhost_traffic_status_display_upstream_t;


static ngx_int_t ngx_http_vhost_traffic_status_display_set_upstream_peer(
    ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf, ngx_str_t *name,
    ngx_http_upstream_server_t *usn, void *data);
static ngx_int_t ngx_http_vhost_traffic_status_display_keep_upstream_peer(
    ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf, ngx_str_t *name,
    ngx_http_upstream_server_t *usn, void *data);
static ngx_array_t *ngx_http_vhost_traffic_status_display_upstream_groups(
    ngx_http_request_t *r);
static ngx_array_t *ngx_http_vhost_traffic_status_display_upstream_peer_names(
    ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf);
static ngx_uint_t ngx_http_vhost_traffic_status_display_upstream_peer_exists(
    ngx_array_t *names, ngx_str_t *name);
static ngx_http_vhost_traffic_status_upstream_group_t *
    ngx_http_vhost_traffic_status_display_upstream_group_lookup(
    ngx_array_t *groups, ngx_str_t *host);
static void ngx_http_vhost_traffic_status_display_collect_gone_peers(
    ngx_http_request_t *r, ngx_rbtree_node_t *node, ngx_array_t *groups);
static u_char *ngx_http_vhost_traffic_status_display_set_upstream_gone(
    ngx_http_request_t *r, u_char *buf, ngx_array_t *gone);

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


/*
 * Writes one peer of an upstream group.
 *
 * The key of a peer is the name of its group, the separator and the name of
 * the peer. This used to be built in one buffer held for the whole walk,
 * sized for the longest group name and an address and a port, on the reading
 * that a peer is never named anything longer. A unix socket is named by its
 * path, which passes that easily, and the overflow did more than run off the
 * end: node_generate_key() takes the key from the same pool with ngx_pcalloc,
 * which zeroes a region overlapping the tail just written, so the name was cut
 * short, the lookup missed, and the peer read as though it had served nothing
 * (#378).
 *
 * Each key is now given the room it needs where it is built.
 */

static ngx_int_t
ngx_http_vhost_traffic_status_display_set_upstream_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_str_t *name,
    ngx_http_upstream_server_t *usn, void *data)
{
    u_char                                *p;
    uint32_t                               hash;
    ngx_int_t                              rc;
    ngx_str_t                              key, dst;
    ngx_rbtree_node_t                     *node;
    ngx_http_vhost_traffic_status_node_t  *vtsn;
    ngx_http_vhost_traffic_status_display_upstream_t  *u = data;

    dst.len = uscf->host.len + sizeof("@") - 1 + name->len;
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    p = dst.data;
    p = ngx_cpymem(p, uscf->host.data, uscf->host.len);
    *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
    p = ngx_cpymem(p, name->data, name->len);

    rc = ngx_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst,
             NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(key.data, key.len);
    node = ngx_http_vhost_traffic_status_node_lookup(u->ctx->rbtree, &key, hash);

    /* a peer that has served nothing yet is written with the zeros of no node */
    vtsn = (node != NULL)
           ? (ngx_http_vhost_traffic_status_node_t *) &node->color
           : NULL;

#if nginx_version > 1007001
    u->buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, u->buf,
                 usn, vtsn);
#else
    u->buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, u->buf,
                 usn, vtsn, name);
#endif

    return NGX_OK;
}


u_char *
ngx_http_vhost_traffic_status_display_set_upstream_group(ngx_http_request_t *r,
    u_char *buf)
{
    u_char                                *o, *s;
    ngx_int_t                              rc;
    ngx_str_t                              key;
    ngx_uint_t                             i;
    ngx_array_t                           *groups;
    ngx_http_vhost_traffic_status_upstream_group_t  *ug;
    ngx_http_upstream_srv_conf_t          *uscf, **uscfp;
    ngx_http_upstream_main_conf_t         *umcf;
    ngx_http_vhost_traffic_status_display_upstream_t  u;

    u.buf = buf;
    u.ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    groups = ngx_http_vhost_traffic_status_display_upstream_groups(r);

    if (groups != NULL) {
        ngx_http_vhost_traffic_status_display_collect_gone_peers(r,
            u.ctx->rbtree->root, groups);
    }

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        /* groups */
        if (uscf->servers && !uscf->port) {

            o = u.buf;

            u.buf = ngx_sprintf(u.buf,
                                NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S,
                                &uscf->host);
            s = u.buf;

            rc = ngx_http_vhost_traffic_status_upstream_peers_walk(r, uscf,
                     ngx_http_vhost_traffic_status_display_set_upstream_peer,
                     &u);

            /* out of memory, and what has been written so far is all there is */
            if (rc != NGX_OK) {
                return u.buf;
            }

            /*
             * The nodes of the peers the group holds no longer, after the ones
             * it does. Written here rather than beside the peer lists so that
             * a group with no zone is covered as well.
             */

            if (groups != NULL) {
                ug = ngx_http_vhost_traffic_status_display_upstream_group_lookup(
                         groups, &uscf->host);

                if (ug != NULL && ug->gone != NULL) {
                    u.buf = ngx_http_vhost_traffic_status_display_set_upstream_gone(
                                r, u.buf, ug->gone);
                }
            }

            if (s == u.buf) {
                u.buf = o;

            } else {
                u.buf--;
                u.buf = ngx_sprintf(u.buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);
                u.buf = ngx_sprintf(u.buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
            }
        }
    }

    /* alones */
    o = u.buf;

    ngx_str_set(&key, "::nogroups");

    u.buf = ngx_sprintf(u.buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S, &key);

    s = u.buf;

    u.buf = ngx_http_vhost_traffic_status_display_set_upstream_alone(r, u.buf,
                u.ctx->rbtree->root);

    if (s == u.buf) {
        u.buf = o;

    } else {
        u.buf--;
        u.buf = ngx_sprintf(u.buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);
        u.buf = ngx_sprintf(u.buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    return u.buf;
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

static int ngx_libc_cdecl
ngx_http_vhost_traffic_status_display_upstream_group_cmp(const void *one,
    const void *two)
{
    ngx_http_vhost_traffic_status_upstream_group_t  *first, *second;

    first = (ngx_http_vhost_traffic_status_upstream_group_t *) one;
    second = (ngx_http_vhost_traffic_status_upstream_group_t *) two;

    return (int) ngx_memn2cmp(first->host.data, second->host.data,
                              first->host.len, second->host.len);
}


/*
 * Returns every upstream group of the configuration together with the peers it
 * holds right now, sorted by host so that a node can be matched to its group
 * with a binary search.
 *
 * NULL when the configuration has no group at all, and also when an allocation
 * on the way failed: the caller then writes the peers the groups do hold and
 * loses only the ones they do not, which is what it wrote before this existed.
 */
static ngx_array_t *
ngx_http_vhost_traffic_status_display_upstream_groups(ngx_http_request_t *r)
{
    ngx_uint_t                                       i;
    ngx_array_t                                     *groups;
    ngx_http_upstream_srv_conf_t                    *uscf, **uscfp;
    ngx_http_upstream_main_conf_t                   *umcf;
    ngx_http_vhost_traffic_status_upstream_group_t  *ug;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    groups = NULL;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        /* an upstream that carries a port rather than servers is not a group */
        if (uscf->servers == NULL || uscf->port) {
            continue;
        }

        if (groups == NULL) {
            groups = ngx_array_create(r->pool, 2,
                       sizeof(ngx_http_vhost_traffic_status_upstream_group_t));
            if (groups == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "display_upstream_groups::ngx_array_create() failed");
                return NULL;
            }
        }

        ug = ngx_array_push(groups);
        if (ug == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "display_upstream_groups::ngx_array_push() failed");
            return NULL;
        }

        ug->host = uscf->host;
        ug->gone = NULL;
        ug->names = ngx_http_vhost_traffic_status_display_upstream_peer_names(r,
                        uscf);

        if (ug->names == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "display_upstream_groups::upstream_peer_names() failed");
            return NULL;
        }
    }

    if (groups != NULL && groups->nelts > 1) {
        ngx_qsort(groups->elts, (size_t) groups->nelts,
                  sizeof(ngx_http_vhost_traffic_status_upstream_group_t),
                  ngx_http_vhost_traffic_status_display_upstream_group_cmp);
    }

    return groups;
}


/*
 * Keeps the name of one peer, copied so that the array outlives the walk: a
 * name held in the zone of the upstream can be given back to the slab by a
 * re-resolve as soon as the walk releases the lock.
 */

static ngx_int_t
ngx_http_vhost_traffic_status_display_keep_upstream_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf, ngx_str_t *name,
    ngx_http_upstream_server_t *usn, void *data)
{
    u_char       *p;
    ngx_str_t    *n;
    ngx_array_t  *names = data;

    n = ngx_array_push(names);
    if (n == NULL) {
        return NGX_ERROR;
    }

    n->len = name->len;
    n->data = NULL;

    /*
     * The placeholder a `resolve` line leaves behind has no name at all, and
     * ngx_memcpy() is not to be handed its NULL even for nothing.
     */

    if (name->len) {
        p = ngx_pnalloc(r->pool, name->len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, name->data, name->len);

        n->data = p;
    }

    return NGX_OK;
}


/*
 * Returns the names of the peers that belong to the upstream group now, from
 * the same walk the group is written out of.
 */
static ngx_array_t *
ngx_http_vhost_traffic_status_display_upstream_peer_names(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_array_t  *names;

    names = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
    if (names == NULL) {
        return NULL;
    }

    if (ngx_http_vhost_traffic_status_upstream_peers_walk(r, uscf,
            ngx_http_vhost_traffic_status_display_keep_upstream_peer, names)
        != NGX_OK)
    {
        return NULL;
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


static ngx_http_vhost_traffic_status_upstream_group_t *
ngx_http_vhost_traffic_status_display_upstream_group_lookup(ngx_array_t *groups,
    ngx_str_t *host)
{
    ngx_int_t                                 rc, l, m, h;
    ngx_http_vhost_traffic_status_upstream_group_t  *ug;

    ug = groups->elts;

    l = 0;
    h = (ngx_int_t) groups->nelts - 1;

    while (l <= h) {
        m = l + (h - l) / 2;

        rc = ngx_memn2cmp(host->data, ug[m].host.data,
                          host->len, ug[m].host.len);

        if (rc == 0) {
            return &ug[m];
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
    ngx_rbtree_node_t *node, ngx_array_t *groups)
{
    u_char                                    *p, *last;
    ngx_str_t                                  host, name;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_node_t      *vtsn;
    ngx_http_vhost_traffic_status_upstream_group_t   *ug;
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

            ug = ngx_http_vhost_traffic_status_display_upstream_group_lookup(groups,
                     &host);

            if (ug != NULL
                && !ngx_http_vhost_traffic_status_display_upstream_peer_exists(
                        ug->names, &name))
            {
                if (ug->gone == NULL) {
                    ug->gone = ngx_array_create(r->pool, 1,
                          sizeof(ngx_http_vhost_traffic_status_gone_peer_t));
                }

                if (ug->gone != NULL) {
                    gone = ngx_array_push(ug->gone);

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
        groups);
    ngx_http_vhost_traffic_status_display_collect_gone_peers(r, node->right,
        groups);
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

#if nginx_version > 1007001
        usn.name = peers[i].name;
#endif

        /*
         * Everything else is left at zero. Whether such a peer is down is not
         * knowable here: one a re-resolve took out cannot take a request, one
         * a balancer picked is taking them right now, and the node says the
         * same thing about both. `weight` and `max_fails` read 0 for the same
         * reason, and false is what that means for a flag.
         */

#if nginx_version > 1007001
        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf,
                  &usn, peers[i].node);
#else
        buf = ngx_http_vhost_traffic_status_display_set_upstream_node(r, buf,
                  &usn, peers[i].node, &peers[i].name);
#endif
    }

    return buf;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
