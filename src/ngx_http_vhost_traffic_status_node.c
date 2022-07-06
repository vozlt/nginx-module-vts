
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_filter.h"
#include "ngx_http_vhost_traffic_status_shm.h"
#include "ngx_http_vhost_traffic_status_node.h"


ngx_int_t
ngx_http_vhost_traffic_status_node_generate_key(ngx_pool_t *pool,
    ngx_str_t *buf, ngx_str_t *dst, unsigned type)
{
    size_t   len;
    u_char  *p;

    len = ngx_strlen(ngx_http_vhost_traffic_status_group_to_string(type));

    buf->len = len + sizeof("@") - 1 + dst->len;
    buf->data = ngx_pcalloc(pool, buf->len);
    if (buf->data == NULL) {
        *buf = *dst;
        return NGX_ERROR;
    }

    p = buf->data;

    p = ngx_cpymem(p, ngx_http_vhost_traffic_status_group_to_string(type), len);
    *p++ = NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
    p = ngx_cpymem(p, dst->data, dst->len);

    return NGX_OK;
}


ngx_int_t
ngx_http_vhost_traffic_status_node_position_key(ngx_str_t *buf, size_t pos)
{
    size_t   n, c, len;
    u_char  *p, *s;

    n = buf->len + 1;
    c = len = 0;
    p = s = buf->data;

    while (--n) {
        if (*p == NGX_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR) {
            if (pos == c) {
                break;
            }
            s = (p + 1);
            c++;
        }
        p++;
        len = (p - s);
    }

    if (pos > c || len == 0) {
        return NGX_ERROR;
    }

    buf->data = s;
    buf->len = len;

    return NGX_OK;
}


void
ngx_http_vhost_traffic_status_find_name(ngx_http_request_t *r,
    ngx_str_t *buf)
{
    ngx_http_core_srv_conf_t                  *cscf;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (vtscf->filter && vtscf->filter_host && r->headers_in.server.len) {
        /* set the key by host header */
        *buf = r->headers_in.server;

    } else {
        /* set the key by server_name variable */
        *buf = cscf->server_name;

        if (buf->len == 0) {
            buf->len = 1;
            buf->data = (u_char *) "_";
        }
    }
}


ngx_rbtree_node_t *
ngx_http_vhost_traffic_status_find_node(ngx_http_request_t *r,
    ngx_str_t *key, unsigned type, uint32_t key_hash)
{
    uint32_t                                   hash;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    hash = key_hash;

    if (hash == 0) {
        hash = ngx_crc32_short(key->data, key->len);
    }

    if (vtscf->node_caches[type] != NULL) {
        if (vtscf->node_caches[type]->key == hash) {
            node = vtscf->node_caches[type];
            goto found;
        }
    }

    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, key, hash);

found:

    return node;
}


ngx_rbtree_node_t *
ngx_http_vhost_traffic_status_find_lru(ngx_http_request_t *r)
{
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;
    ngx_http_vhost_traffic_status_shm_info_t  *shm_info;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    node = NULL;

    /* disabled */
    if (ctx->filter_max_node == 0) {
        return NULL;
    }

    shm_info = ngx_pcalloc(r->pool, sizeof(ngx_http_vhost_traffic_status_shm_info_t));

    if (shm_info == NULL) { 
        return NULL;
    }

    ngx_http_vhost_traffic_status_shm_info(r, shm_info);

    /* find */
    if (shm_info->filter_used_node >= ctx->filter_max_node) {
        node = ngx_http_vhost_traffic_status_find_lru_node(r, NULL, ctx->rbtree->root);
    }

    return node;
}


ngx_rbtree_node_t *
ngx_http_vhost_traffic_status_find_lru_node(ngx_http_request_t *r,
    ngx_rbtree_node_t *a, ngx_rbtree_node_t *b)
{
    ngx_str_t                              filter;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (b != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &b->color;

        if (vtsn->stat_upstream.type == NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            filter.data = vtsn->data;
            filter.len = vtsn->len;

            (void) ngx_http_vhost_traffic_status_node_position_key(&filter, 1);

            if (ngx_http_vhost_traffic_status_filter_max_node_match(r, &filter) == NGX_OK) {
                a = ngx_http_vhost_traffic_status_find_lru_node_cmp(r, a, b);
            }
        }

        a = ngx_http_vhost_traffic_status_find_lru_node(r, a, b->left);
        a = ngx_http_vhost_traffic_status_find_lru_node(r, a, b->right);
    }

    return a;
}


ngx_rbtree_node_t *
ngx_http_vhost_traffic_status_find_lru_node_cmp(ngx_http_request_t *r,
    ngx_rbtree_node_t *a, ngx_rbtree_node_t *b)
{
    ngx_int_t                                         ai, bi;
    ngx_http_vhost_traffic_status_node_t             *avtsn, *bvtsn;
    ngx_http_vhost_traffic_status_node_time_queue_t  *aq, *bq;

    if (a == NULL) {
        return b;
    }

    avtsn = (ngx_http_vhost_traffic_status_node_t *) &a->color;
    bvtsn = (ngx_http_vhost_traffic_status_node_t *) &b->color;

    aq = &avtsn->stat_request_times;
    bq = &bvtsn->stat_request_times;

    if (aq->front == aq->rear) {
        return a;
    }

    if (bq->front == bq->rear) {
        return b;
    }

    ai = ngx_http_vhost_traffic_status_node_time_queue_rear(aq);
    bi = ngx_http_vhost_traffic_status_node_time_queue_rear(bq);

    return (aq->times[ai].time < bq->times[bi].time) ? a : b;
}


ngx_rbtree_node_t *
ngx_http_vhost_traffic_status_node_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key,
    uint32_t hash)
{
    ngx_int_t                              rc;
    ngx_rbtree_node_t                     *node, *sentinel;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, vtsn->data, key->len, (size_t) vtsn->len);
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


void
ngx_http_vhost_traffic_status_node_zero(ngx_http_vhost_traffic_status_node_t *vtsn)
{
    vtsn->stat_request_counter = 0;
    vtsn->stat_in_bytes = 0;
    vtsn->stat_out_bytes = 0;
    vtsn->stat_1xx_counter = 0;
    vtsn->stat_2xx_counter = 0;
    vtsn->stat_3xx_counter = 0;
    vtsn->stat_4xx_counter = 0;
    vtsn->stat_5xx_counter = 0;

    vtsn->stat_request_time_counter = 0;
    vtsn->stat_request_time = 0;
    vtsn->stat_upstream.response_time_counter = 0;
    vtsn->stat_upstream.response_time = 0;

    vtsn->stat_request_counter_oc = 0;
    vtsn->stat_in_bytes_oc = 0;
    vtsn->stat_out_bytes_oc = 0;
    vtsn->stat_1xx_counter_oc = 0;
    vtsn->stat_2xx_counter_oc = 0;
    vtsn->stat_3xx_counter_oc = 0;
    vtsn->stat_4xx_counter_oc = 0;
    vtsn->stat_5xx_counter_oc = 0;
    vtsn->stat_request_time_counter_oc = 0;
    vtsn->stat_response_time_counter_oc = 0;

#if (NGX_HTTP_CACHE)
    vtsn->stat_cache_miss_counter = 0;
    vtsn->stat_cache_bypass_counter = 0;
    vtsn->stat_cache_expired_counter = 0;
    vtsn->stat_cache_stale_counter = 0;
    vtsn->stat_cache_updating_counter = 0;
    vtsn->stat_cache_revalidated_counter = 0;
    vtsn->stat_cache_hit_counter = 0;
    vtsn->stat_cache_scarce_counter = 0;

    vtsn->stat_cache_miss_counter_oc = 0;
    vtsn->stat_cache_bypass_counter_oc = 0;
    vtsn->stat_cache_expired_counter_oc = 0;
    vtsn->stat_cache_stale_counter_oc = 0;
    vtsn->stat_cache_updating_counter_oc = 0;
    vtsn->stat_cache_revalidated_counter_oc = 0;
    vtsn->stat_cache_hit_counter_oc = 0;
    vtsn->stat_cache_scarce_counter_oc = 0;
#endif

}


/*
   Initialize the node and update it with the first request.
   Set the `stat_request_time` to the time of the first request.
*/
void
ngx_http_vhost_traffic_status_node_init(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_msec_int_t  ms;

    /* init serverZone */
    ngx_http_vhost_traffic_status_node_zero(vtsn);
    ngx_http_vhost_traffic_status_node_time_queue_init(&vtsn->stat_request_times);
    ngx_http_vhost_traffic_status_node_histogram_bucket_init(r, &vtsn->stat_request_buckets);

    /* init upstreamZone */
    vtsn->stat_upstream.type = NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;
    vtsn->stat_upstream.response_time_counter = 0;
    vtsn->stat_upstream.response_time = 0;
    ngx_http_vhost_traffic_status_node_time_queue_init(&vtsn->stat_upstream.response_times);
    ngx_http_vhost_traffic_status_node_histogram_bucket_init(r,
        &vtsn->stat_upstream.response_buckets);

    /* set serverZone */
    ms = ngx_http_vhost_traffic_status_request_time(r);
    vtsn->stat_request_time = (ngx_msec_t) ms;

    ngx_http_vhost_traffic_status_node_update(r, vtsn, ms);
}


/*
   Update the node from a subsequent request. Now there is more than one request,
   calculate the average request time.
*/
void
ngx_http_vhost_traffic_status_node_set(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_msec_int_t                             ms;
    ngx_http_vhost_traffic_status_node_t       ovtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    ovtsn = *vtsn;

    ms = ngx_http_vhost_traffic_status_request_time(r);
    ngx_http_vhost_traffic_status_node_update(r, vtsn, ms);

    vtsn->stat_request_time = ngx_http_vhost_traffic_status_node_time_queue_average(
                                  &vtsn->stat_request_times, vtscf->average_method,
                                  vtscf->average_period);

    ngx_http_vhost_traffic_status_add_oc((&ovtsn), vtsn);
}


void
ngx_http_vhost_traffic_status_node_update(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, ngx_msec_int_t ms)
{
    ngx_uint_t status = r->headers_out.status;

    vtsn->stat_request_counter++;
    vtsn->stat_in_bytes += (ngx_atomic_uint_t) r->request_length;
    vtsn->stat_out_bytes += (ngx_atomic_uint_t) r->connection->sent;

    ngx_http_vhost_traffic_status_add_rc(status, vtsn);

    vtsn->stat_request_time_counter += (ngx_atomic_uint_t) ms;

    ngx_http_vhost_traffic_status_node_time_queue_insert(&vtsn->stat_request_times,
                                                         ms);

    ngx_http_vhost_traffic_status_node_histogram_observe(&vtsn->stat_request_buckets,
                                                         ms);

#if (NGX_HTTP_CACHE)
    if (r->upstream != NULL && r->upstream->cache_status != 0) {
        ngx_http_vhost_traffic_status_add_cc(r->upstream->cache_status, vtsn);
    }
#endif
}


void
ngx_http_vhost_traffic_status_node_time_queue_zero(
    ngx_http_vhost_traffic_status_node_time_queue_t *q)
{
    ngx_memzero(q, sizeof(ngx_http_vhost_traffic_status_node_time_queue_t));
}


void
ngx_http_vhost_traffic_status_node_time_queue_init(
    ngx_http_vhost_traffic_status_node_time_queue_t *q)
{
    ngx_http_vhost_traffic_status_node_time_queue_zero(q);
    q->rear = NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN - 1;
    q->len = NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN;
}


ngx_int_t
ngx_http_vhost_traffic_status_node_time_queue_push(
    ngx_http_vhost_traffic_status_node_time_queue_t *q,
    ngx_msec_int_t x)
{
    if ((q->rear + 1) % q->len == q->front) {
        return NGX_ERROR;
    }

    q->times[q->rear].time = ngx_http_vhost_traffic_status_current_msec();
    q->times[q->rear].msec = x;
    q->rear = (q->rear + 1) % q->len;

    return NGX_OK;
}


ngx_int_t
ngx_http_vhost_traffic_status_node_time_queue_pop(
    ngx_http_vhost_traffic_status_node_time_queue_t *q,
    ngx_http_vhost_traffic_status_node_time_t *x)
{
    if (q->front == q->rear) {
        return NGX_ERROR;
    }

    *x = q->times[q->front];
    q->front = (q->front + 1) % q->len;

    return NGX_OK;
}


ngx_int_t
ngx_http_vhost_traffic_status_node_time_queue_rear(
    ngx_http_vhost_traffic_status_node_time_queue_t *q)
{
    return (q->rear > 0) ? (q->rear - 1) : (NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN - 1);
}


void
ngx_http_vhost_traffic_status_node_time_queue_insert(
    ngx_http_vhost_traffic_status_node_time_queue_t *q,
    ngx_msec_int_t x)
{
    ngx_int_t                                  rc;
    ngx_http_vhost_traffic_status_node_time_t  rx;
    rc = ngx_http_vhost_traffic_status_node_time_queue_pop(q, &rx)
         | ngx_http_vhost_traffic_status_node_time_queue_push(q, x);

    if (rc != NGX_OK) {
        ngx_http_vhost_traffic_status_node_time_queue_init(q);
    }
}


ngx_msec_t
ngx_http_vhost_traffic_status_node_time_queue_average(
    ngx_http_vhost_traffic_status_node_time_queue_t *q,
    ngx_int_t method, ngx_msec_t period)
{
    ngx_msec_t  avg;

    if (method == NGX_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_AMM) {
        avg = ngx_http_vhost_traffic_status_node_time_queue_amm(q, period);
    } else {
        avg = ngx_http_vhost_traffic_status_node_time_queue_wma(q, period);
    }

    return avg;
}


ngx_msec_t
ngx_http_vhost_traffic_status_node_time_queue_amm(
    ngx_http_vhost_traffic_status_node_time_queue_t *q,
    ngx_msec_t period)
{
    ngx_int_t   c, i, j, k;
    ngx_msec_t  x, current_msec;

    current_msec = ngx_http_vhost_traffic_status_current_msec();

    c = 0;
    x = period ? (current_msec - period) : 0;

    for (i = q->front, j = 1, k = 0; i != q->rear; i = (i + 1) % q->len, j++) {
        if (x < q->times[i].time) {
            k += (ngx_int_t) q->times[i].msec;
            c++;
        }
    }

    if (j != q->len) {
        ngx_http_vhost_traffic_status_node_time_queue_init(q);
    }

    return (c == 0) ? (ngx_msec_t) 0 : (ngx_msec_t) (k / c);
}


ngx_msec_t
ngx_http_vhost_traffic_status_node_time_queue_wma(
    ngx_http_vhost_traffic_status_node_time_queue_t *q,
    ngx_msec_t period)
{
    ngx_int_t   c, i, j, k;
    ngx_msec_t  x, current_msec;

    current_msec = ngx_http_vhost_traffic_status_current_msec();

    c = 0;
    x = period ? (current_msec - period) : 0;

    for (i = q->front, j = 1, k = 0; i != q->rear; i = (i + 1) % q->len, j++) {
        if (x < q->times[i].time) {
            k += (ngx_int_t) q->times[i].msec * ++c;
        }
    }

    if (j != q->len) {
        ngx_http_vhost_traffic_status_node_time_queue_init(q);
    }

    return (c == 0) ? (ngx_msec_t) 0 : (ngx_msec_t)
           (k / (ngx_int_t) ngx_http_vhost_traffic_status_triangle(c));
}


void
ngx_http_vhost_traffic_status_node_time_queue_merge(
    ngx_http_vhost_traffic_status_node_time_queue_t *a,
    ngx_http_vhost_traffic_status_node_time_queue_t *b,
    ngx_msec_t period)
{
    ngx_int_t   i;
    ngx_msec_t  x, current_msec;

    current_msec = ngx_http_vhost_traffic_status_current_msec();

    x = period ? (current_msec - period) : 0;

    for (i = a->front; i != a->rear; i = (i + 1) % a->len) {
            a->times[i].time = (a->times[i].time > b->times[i].time)
                               ? a->times[i].time
                               : b->times[i].time;

            if (x < a->times[i].time) {
                a->times[i].msec = (a->times[i].msec + b->times[i].msec) / 2
                                   + (a->times[i].msec + b->times[i].msec) % 2;

            } else {
                a->times[i].msec = 0;
            }
    }
}


void
ngx_http_vhost_traffic_status_node_histogram_bucket_init(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_histogram_bucket_t *b)
{
    ngx_uint_t                                       i, n;
    ngx_http_vhost_traffic_status_loc_conf_t        *vtscf;
    ngx_http_vhost_traffic_status_node_histogram_t  *buckets;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    if (vtscf->histogram_buckets == NULL) {
        b->len = 0;
        return;
    }

    buckets = vtscf->histogram_buckets->elts;
    n = vtscf->histogram_buckets->nelts;
    b->len = n;

    for (i = 0; i < n; i++) {
        b->buckets[i].msec = buckets[i].msec;
        b->buckets[i].counter = 0;
    }
}


void
ngx_http_vhost_traffic_status_node_histogram_observe(
    ngx_http_vhost_traffic_status_node_histogram_bucket_t *b,
    ngx_msec_int_t x)
{
    ngx_uint_t  i, n;

    n = b->len;

    for (i = 0; i < n; i++) {
        if (x <= b->buckets[i].msec) {
            b->buckets[i].counter++;
        }
    }
}


ngx_int_t
ngx_http_vhost_traffic_status_node_member_cmp(ngx_str_t *member, const char *name)
{
    if (member->len == ngx_strlen(name) && ngx_strncmp(name, member->data, member->len) == 0) {
        return 0;
    }

    return 1;
}


ngx_atomic_uint_t
ngx_http_vhost_traffic_status_node_member(ngx_http_vhost_traffic_status_node_t *vtsn,
    ngx_str_t *member)
{
    if (ngx_http_vhost_traffic_status_node_member_cmp(member, "request") == 0)
    {
        return vtsn->stat_request_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "in") == 0)
    {
        return vtsn->stat_in_bytes;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "out") == 0)
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
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cache_miss") == 0)
    {
        return vtsn->stat_cache_miss_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cache_bypass") == 0)
    {
        return vtsn->stat_cache_bypass_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cache_expired") == 0)
    {
        return vtsn->stat_cache_expired_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cache_stale") == 0)
    {
        return vtsn->stat_cache_stale_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cache_updating") == 0)
    {
        return vtsn->stat_cache_updating_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cache_revalidated") == 0)
    {
        return vtsn->stat_cache_revalidated_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cache_hit") == 0)
    {
        return vtsn->stat_cache_hit_counter;
    }
    else if (ngx_http_vhost_traffic_status_node_member_cmp(member, "cache_scarce") == 0)
    {
        return vtsn->stat_cache_scarce_counter;
    }
#endif

    return 0;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
