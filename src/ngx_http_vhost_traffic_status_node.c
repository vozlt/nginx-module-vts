
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
    uint32_t                              hash;
    ngx_rbtree_node_t                    *node;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    hash = key_hash;

    if (hash == 0) {
        hash = ngx_crc32_short(key->data, key->len);
    }

    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, key, hash);

    return node;
}


/* whether this node is one of the ones the cap counts */

ngx_int_t
ngx_http_vhost_traffic_status_node_filter_counted(
    ngx_http_vhost_traffic_status_ctx_t *ctx,
    ngx_http_vhost_traffic_status_node_t *vtsn)
{
    ngx_str_t  filter;

    if (vtsn->stat_upstream.type != NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
        return NGX_DECLINED;
    }

    filter.data = vtsn->data;
    filter.len = vtsn->len;

    if (ngx_http_vhost_traffic_status_node_position_key(&filter, 1) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (ngx_http_vhost_traffic_status_filter_max_node_match_ctx(ctx, &filter)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


/*
 * Everything that puts a node into the tree or takes one out comes through
 * here, with the mutex of the zone held.
 *
 * The signature is checked on the way in rather than only where the count is
 * read. A reload is graceful: for a while the old workers and the new ones
 * are both serving from this zone, and they do not agree on which nodes the
 * cap counts. A worker that finds a count belonging to someone else's
 * configuration must not add to it or take from it - it gives up on the
 * count instead, and whoever reads it next builds a new one.
 */

void
ngx_http_vhost_traffic_status_node_filter_account(
    ngx_http_vhost_traffic_status_ctx_t *ctx,
    ngx_http_vhost_traffic_status_node_t *vtsn, ngx_int_t delta)
{
    if (ctx->shm == NULL) {
        return;
    }

    if (ctx->shm->signature != ctx->signature) {
        ctx->shm->signature = 0;
        return;
    }

    if (ngx_http_vhost_traffic_status_node_filter_counted(ctx, vtsn)
        != NGX_OK)
    {
        return;
    }

    if (delta > 0) {
        ctx->shm->filter_nodes++;

    } else if (ctx->shm->filter_nodes > 0) {
        ctx->shm->filter_nodes--;
    }
}


/* only for the count that a change of configuration has invalidated */

ngx_uint_t
ngx_http_vhost_traffic_status_node_filter_count(ngx_http_request_t *r,
    ngx_rbtree_node_t *node)
{
    ngx_uint_t                             n;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);

    if (node == ctx->rbtree->sentinel) {
        return 0;
    }

    vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

    n = ngx_http_vhost_traffic_status_node_filter_counted(ctx, vtsn) == NGX_OK
        ? 1 : 0;

    return n
           + ngx_http_vhost_traffic_status_node_filter_count(r, node->left)
           + ngx_http_vhost_traffic_status_node_filter_count(r, node->right);
}


ngx_rbtree_node_t *
ngx_http_vhost_traffic_status_find_lru(ngx_http_request_t *r, unsigned type,
    ngx_str_t *key)
{
    ngx_str_t                                  filter;
    ngx_uint_t                                 used;
    ngx_rbtree_node_t                         *node;
    ngx_http_vhost_traffic_status_ctx_t       *ctx;

    ctx = ngx_http_get_module_main_conf(r, ngx_http_vhost_traffic_status_module);
    node = NULL;

    /* disabled */
    if (ctx->filter_max_node == 0) {
        return NULL;
    }

    /*
     * The cap counts the nodes of the filter groups the directive names, so
     * only an insertion into one of those groups can take it over. A server
     * zone, an upstream peer, a cache or a filter of a group the directive
     * does not name has nothing to do with it, and dropping a node for one
     * of them loses a measurement while the zone still has room.
     */

    if (type != NGX_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
        return NULL;
    }

    filter = *key;

    if (ngx_http_vhost_traffic_status_node_position_key(&filter, 1) != NGX_OK) {
        return NULL;
    }

    if (ngx_http_vhost_traffic_status_filter_max_node_match(r, &filter) != NGX_OK) {
        return NULL;
    }

    /*
     * The count used to be made here, by walking the whole tree, before it
     * had even been compared against the cap - so the walk was paid on every
     * insertion whether or not the cap was anywhere near. It is kept in the
     * zone now, under the mutex this is already called with.
     */

    if (ctx->shm == NULL) {

        /* nowhere to keep it, so it is counted the way it always was */

        used = ngx_http_vhost_traffic_status_node_filter_count(r,
                   ctx->rbtree->root);

    } else {
        if (ctx->shm->signature != ctx->signature) {

            /* the configuration it was made under is not this one */

            ctx->shm->filter_nodes =
                ngx_http_vhost_traffic_status_node_filter_count(r,
                    ctx->rbtree->root);
            ctx->shm->signature = ctx->signature;
        }

        used = ctx->shm->filter_nodes;
    }

    /* find */
    if (used >= ctx->filter_max_node) {
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
    ngx_http_vhost_traffic_status_node_t  *avtsn, *bvtsn;

    if (a == NULL) {
        return b;
    }

    avtsn = (ngx_http_vhost_traffic_status_node_t *) &a->color;
    bvtsn = (ngx_http_vhost_traffic_status_node_t *) &b->color;

    /*
     * This used to read the last entry of the time queue, which a zone whose
     * statuses ignore_status excludes never fills, so such a zone was always
     * the one chosen to go however much traffic it was carrying.
     */

    return (avtsn->stat_last_seen < bvtsn->stat_last_seen) ? a : b;
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
    ngx_uint_t  i;

    vtsn->stat_request_counter = 0;
    vtsn->stat_in_bytes = 0;
    vtsn->stat_out_bytes = 0;
    vtsn->stat_1xx_counter = 0;
    vtsn->stat_2xx_counter = 0;
    vtsn->stat_3xx_counter = 0;
    vtsn->stat_4xx_counter = 0;
    vtsn->stat_5xx_counter = 0;

    vtsn->stat_request_time_counter = 0;
    vtsn->stat_last_seen = 0;
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

    for (i = 0; i < vtsn->stat_status_code_length; i++) {
        vtsn->stat_status_code_counter[i] = 0;
    }

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
*/
void
ngx_http_vhost_traffic_status_node_init(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, ngx_int_t status_code_slot,
    ngx_http_upstream_state_t *state)
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

    ngx_http_vhost_traffic_status_node_update(r, vtsn, ms, status_code_slot, state);
}


/*
   Update the node from a subsequent request. Now there is more than one request,
   calculate the average request time.
*/
void
ngx_http_vhost_traffic_status_node_set(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, ngx_int_t status_code_slot,
    ngx_http_upstream_state_t *state)
{
    ngx_msec_int_t                             ms;
    ngx_http_vhost_traffic_status_node_oc_t    ovtsn;
    ngx_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = ngx_http_get_module_loc_conf(r, ngx_http_vhost_traffic_status_module);

    ngx_http_vhost_traffic_status_copy_oc((&ovtsn), vtsn);

    vtsn->ignore_status = vtscf->ignore_status;
    ms = ngx_http_vhost_traffic_status_request_time(r);
    ngx_http_vhost_traffic_status_node_update(r, vtsn, ms, status_code_slot, state);

    /*
     * stat_request_time is not kept up to date here: averaging the queue on
     * every request costs a loop over the whole queue while the shared memory
     * is locked. The readers compute it when they need it.
     */

    ngx_http_vhost_traffic_status_add_oc((&ovtsn), vtsn);
}


void
ngx_http_vhost_traffic_status_node_update(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_t *vtsn, ngx_msec_int_t ms, ngx_int_t status_code_slot,
    ngx_http_upstream_state_t *state)
{
    /*
     * state is the attempt this call is counting, and it is set only where
     * proxy_next_upstream passed that attempt on to another peer. Everything
     * else - every server, filter and cache zone, and the attempt that did
     * serve the client - counts the client request and leaves it NULL.
     */

    ngx_uint_t status = (state != NULL) ? state->status : r->headers_out.status;

    /*
     * Before the check below: a status that is not counted still leaves the
     * node reached - the client request was served, or the attempt on this
     * peer was made - and being reached is what tells it apart from one
     * nothing has used in a long time. Being counted is not.
     */

    vtsn->stat_last_seen = ngx_http_vhost_traffic_status_current_msec();

    if (ngx_http_vhost_traffic_status_ignore_status(vtsn->ignore_status, status)) {
        return;
    }

    vtsn->stat_request_counter++;

    if (state != NULL && (status < 100 || status >= 600)) {

        /*
         * An attempt carries no status of its own where it produced no
         * response, and nginx leaves that 0. add_rc() puts anything below 200
         * in the 1xx bucket, so it must not be handed one - the attempt would
         * be reported as an informational response. The two other places that
         * read this status already say the same thing: shm_add_node() takes no
         * status code slot outside 100..599, and the response time helper
         * gives 0 for a state with no status.
         *
         * It was still an attempt on this peer, so the counter above stands.
         */

        return;
    }

    ngx_http_vhost_traffic_status_add_rc(status, vtsn);

    if (status_code_slot != -1 && vtsn->stat_status_code_counter != NULL ) {
        vtsn->stat_status_code_counter[status_code_slot]++;
    }

    if (state != NULL) {

        /*
         * The rest of this describes the client request: the bytes either
         * way, how long it took, what the cache did with it. An attempt that
         * was passed on served no client, so it has none of them to add. Its
         * own response time goes to the upstream queue in
         * ngx_http_vhost_traffic_status_shm_add_node_upstream().
         */

        return;
    }

    vtsn->stat_in_bytes += (ngx_atomic_uint_t) r->request_length;
    vtsn->stat_out_bytes += (ngx_atomic_uint_t) r->connection->sent;

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


/*
   Same as ngx_http_vhost_traffic_status_node_time_queue_average(), for the
   callers that do not hold the shared memory lock: the average reinitializes
   a queue it finds inconsistent, so it is given a copy to work on.

   The copy is not atomic and the queue may be initialized while it is taken,
   which leaves the length zero for a moment, so the snapshot is checked
   before it is walked: the average takes the index of an entry modulo the
   length.
*/
ngx_msec_t
ngx_http_vhost_traffic_status_node_time_queue_average_ro(
    ngx_http_vhost_traffic_status_node_time_queue_t *q,
    ngx_int_t method, ngx_msec_t period)
{
    ngx_http_vhost_traffic_status_node_time_queue_t  copy;

    copy = *q;

    if (copy.len != NGX_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN
        || copy.front < 0 || copy.front >= copy.len
        || copy.rear < 0 || copy.rear >= copy.len)
    {
        return 0;
    }

    return ngx_http_vhost_traffic_status_node_time_queue_average(&copy, method,
                                                                 period);
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
    ngx_int_t                                        i, j, k, n, len;
    ngx_msec_t                                       x, current_msec;
    ngx_http_vhost_traffic_status_node_time_queue_t  q;

    ngx_http_vhost_traffic_status_node_time_queue_init(&q);

    current_msec = ngx_http_vhost_traffic_status_current_msec();
    x = period ? (current_msec - period) : 0;
    len = q.len;

    for (i = a->rear, j = b->rear, k = q.rear, n = 0; n < len -1; ++n) {
        if (a->times[(i + len - 1) % len].time > b->times[(j + len - 1) % len].time) {
            if (x >= a->times[(i + len - 1) % len].time) {
                break;
            }
            q.times[(k + len - 1) % len].time = a->times[(i + len - 1) % len].time;
            q.times[(k + len - 1) % len].msec = a->times[(i + len - 1) % len].msec;
            i = (i + len - 1) % len;

        } else {
            if (x >= b->times[(j + len - 1) % len].time) {
                break;
            }
            q.times[(k + len - 1) % len].time = b->times[(j + len - 1) % len].time;
            q.times[(k + len - 1) % len].msec = b->times[(j + len - 1) % len].msec;
            j = (j + len - 1) % len;
        }
        k = (k + len - 1) % len;
    }
    (void) ngx_cpymem(a, &q, sizeof(q));
}

void ngx_http_vhost_traffic_status_status_code_merge(ngx_atomic_t *dst, ngx_atomic_t *src, ngx_uint_t n)
{
    ngx_uint_t i;

    for (i = 0; i < n; i++) {
        dst[i] += src[i];
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


/* the whole of what a node member is called, see node.h */

#define ngx_vts_member(f)  offsetof(ngx_http_vhost_traffic_status_node_t, f)

ngx_http_vhost_traffic_status_member_t
    ngx_http_vhost_traffic_status_members[] = {

    { ngx_string("request"), ngx_string("requestCounter"),
      ngx_string("vts_request_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_request_counter) },

    { ngx_string("in"), ngx_string("inBytes"), ngx_string("vts_in_bytes"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_in_bytes) },

    { ngx_string("out"), ngx_string("outBytes"), ngx_string("vts_out_bytes"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_out_bytes) },

    { ngx_string("1xx"), ngx_string("1xx"), ngx_string("vts_1xx_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_1xx_counter) },

    { ngx_string("2xx"), ngx_string("2xx"), ngx_string("vts_2xx_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_2xx_counter) },

    { ngx_string("3xx"), ngx_string("3xx"), ngx_string("vts_3xx_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_3xx_counter) },

    { ngx_string("4xx"), ngx_string("4xx"), ngx_string("vts_4xx_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_4xx_counter) },

    { ngx_string("5xx"), ngx_string("5xx"), ngx_string("vts_5xx_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_5xx_counter) },

    { ngx_null_string, ngx_string("requestMsecCounter"),
      ngx_string("vts_request_time_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_request_time_counter) },

    { ngx_null_string, ngx_string("requestMsec"),
      ngx_string("vts_request_time"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_QUEUE,
      ngx_vts_member(stat_request_times) },

    { ngx_null_string, ngx_string("responseMsecCounter"), ngx_null_string,
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_upstream.response_time_counter) },

    { ngx_null_string, ngx_string("responseMsec"), ngx_null_string,
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_QUEUE,
      ngx_vts_member(stat_upstream.response_times) },

#if (NGX_HTTP_CACHE)

    { ngx_null_string, ngx_string("cacheMaxSize"), ngx_null_string,
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_cache_max_size) },

    { ngx_null_string, ngx_string("cacheUsedSize"), ngx_null_string,
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_cache_used_size) },

    { ngx_string("cache_miss"), ngx_string("cacheMiss"),
      ngx_string("vts_cache_miss_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_cache_miss_counter) },

    { ngx_string("cache_bypass"), ngx_string("cacheBypass"),
      ngx_string("vts_cache_bypass_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_cache_bypass_counter) },

    { ngx_string("cache_expired"), ngx_string("cacheExpired"),
      ngx_string("vts_cache_expired_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_cache_expired_counter) },

    { ngx_string("cache_stale"), ngx_string("cacheStale"),
      ngx_string("vts_cache_stale_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_cache_stale_counter) },

    { ngx_string("cache_updating"), ngx_string("cacheUpdating"),
      ngx_string("vts_cache_updating_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_cache_updating_counter) },

    { ngx_string("cache_revalidated"), ngx_string("cacheRevalidated"),
      ngx_string("vts_cache_revalidated_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_cache_revalidated_counter) },

    { ngx_string("cache_hit"), ngx_string("cacheHit"),
      ngx_string("vts_cache_hit_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_cache_hit_counter) },

    { ngx_string("cache_scarce"), ngx_string("cacheScarce"),
      ngx_string("vts_cache_scarce_counter"),
      NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER,
      ngx_vts_member(stat_cache_scarce_counter) },

#endif

    { ngx_null_string, ngx_null_string, ngx_null_string, 0, 0 }
};


ngx_http_vhost_traffic_status_member_t *
ngx_http_vhost_traffic_status_member_lookup(ngx_str_t *name,
    ngx_uint_t vocabulary)
{
    ngx_str_t                               *n;
    ngx_http_vhost_traffic_status_member_t  *m;

    for (m = ngx_http_vhost_traffic_status_members;
         m->limit.len || m->filter.len || m->variable.len;
         m++)
    {
        n = (vocabulary == NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_LIMIT)
            ? &m->limit : &m->filter;

        /* a field this way in cannot ask for */

        if (n->len == 0) {
            continue;
        }

        if (n->len == name->len
            && ngx_strncmp(n->data, name->data, name->len) == 0)
        {
            return m;
        }
    }

    return NULL;
}


ngx_atomic_uint_t
ngx_http_vhost_traffic_status_node_member(ngx_http_vhost_traffic_status_node_t *vtsn,
    ngx_str_t *member)
{
    ngx_http_vhost_traffic_status_member_t  *m;

    m = ngx_http_vhost_traffic_status_member_lookup(member,
            NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_LIMIT);

    /*
     * A name the limit cannot be given reads 0, which is what it read before
     * this was a table. It is the same answer an untouched counter gives, so
     * a limit named after nothing is never reached rather than always.
     */

    if (m == NULL || m->kind != NGX_HTTP_VHOST_TRAFFIC_STATUS_MEMBER_COUNTER) {
        return 0;
    }

    return *((ngx_atomic_t *) ((char *) vtsn + m->offset));
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
