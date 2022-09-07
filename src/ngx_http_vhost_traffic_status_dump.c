
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_dump.h"


static u_char  NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_PAD[] = { 0x53, 0x54, 0x56 };


static ssize_t ngx_http_vhost_traffic_status_dump_header_read(ngx_file_t *file,
    ngx_http_vhost_traffic_status_dump_header_t *file_header);
static ssize_t ngx_http_vhost_traffic_status_dump_header_write(ngx_event_t *ev,
    ngx_file_t *file);
static void ngx_http_vhost_traffic_status_dump_node_write(ngx_event_t *ev,
    ngx_file_t *file, ngx_rbtree_node_t *node);
static ngx_int_t ngx_http_vhost_traffic_status_dump_update_valid(ngx_event_t *ev);
static ngx_int_t ngx_http_vhost_traffic_status_dump_restore_add_node(ngx_event_t *ev,
     ngx_http_vhost_traffic_status_node_t *ovtsn, ngx_str_t *key);


void
ngx_http_vhost_traffic_status_file_lock(ngx_file_t *file)
{
    ngx_err_t  err = ngx_lock_fd(file->fd);

    if (err == 0) {
        return;
    }

    ngx_log_error(NGX_LOG_ALERT, file->log, err,
                  ngx_lock_fd_n " \"%s\" failed", file->name.data);
}


void
ngx_http_vhost_traffic_status_file_unlock(ngx_file_t *file)
{
    ngx_err_t  err = ngx_unlock_fd(file->fd);

    if (err == 0) {
        return;
    }

    ngx_log_error(NGX_LOG_ALERT, file->log, err,
                  ngx_unlock_fd_n " \"%s\" failed", file->name.data);
}


void
ngx_http_vhost_traffic_status_file_close(ngx_file_t *file)
{
    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name.data);
    }
}


static ssize_t
ngx_http_vhost_traffic_status_dump_header_read(ngx_file_t *file,
    ngx_http_vhost_traffic_status_dump_header_t *file_header)
{
    ssize_t  n;

    ngx_memzero(file_header, sizeof(ngx_http_vhost_traffic_status_dump_header_t));

    n = ngx_read_file(file, (u_char *) file_header,
                      sizeof(ngx_http_vhost_traffic_status_dump_header_t), 0);

    return n;
}


static ssize_t
ngx_http_vhost_traffic_status_dump_header_write(ngx_event_t *ev, ngx_file_t *file)
{
    size_t                                        len;
    ssize_t                                       n;
    u_char                                       *p;
    ngx_http_vhost_traffic_status_ctx_t          *ctx;
    ngx_http_vhost_traffic_status_dump_header_t   file_header;

    ctx = ev->data;

    ngx_memzero(&file_header, sizeof(ngx_http_vhost_traffic_status_dump_header_t));

    len = (ctx->shm_name.len >= NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_HEADER_NAME_SIZE)
          ? NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_HEADER_NAME_SIZE - 1
          : ctx->shm_name.len;

    p = file_header.name;
    p = ngx_cpymem(p, ctx->shm_name.data, len);
    file_header.time = ngx_http_vhost_traffic_status_current_msec();
    file_header.version = nginx_version;

    n = ngx_write_fd(file->fd, &file_header, sizeof(ngx_http_vhost_traffic_status_dump_header_t));

    return n;
}


static void
ngx_http_vhost_traffic_status_dump_node_write(ngx_event_t *ev, ngx_file_t *file,
    ngx_rbtree_node_t *node)
{
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *volatile vtsn;

    ctx = ev->data;

    if (node != ctx->rbtree->sentinel) {
        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        (void) ngx_write_fd(file->fd, vtsn, sizeof(ngx_http_vhost_traffic_status_node_t));
        (void) ngx_write_fd(file->fd, vtsn->data, vtsn->len);
        (void) ngx_write_fd(file->fd, NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_PAD,
                            sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_PAD));

        ngx_http_vhost_traffic_status_dump_node_write(ev, file, node->left);
        ngx_http_vhost_traffic_status_dump_node_write(ev, file, node->right);
    }
}


static ngx_int_t
ngx_http_vhost_traffic_status_dump_update_valid(ngx_event_t *ev)
{
    size_t                                        len;
    ssize_t                                       n;
    ngx_fd_t                                      fd;
    ngx_int_t                                     rc;
    ngx_msec_t                                    current_msec;
    ngx_file_t                                    file;
    ngx_http_vhost_traffic_status_ctx_t          *ctx;
    ngx_http_vhost_traffic_status_dump_header_t   file_header;

    ctx = ev->data;

    fd = ngx_open_file(ctx->dump_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, ngx_errno,
                       ngx_open_file_n " \"%s\" failed", ctx->dump_file.data);
        return NGX_OK;
    }

    file.fd = fd;
    file.name = ctx->dump_file;
    file.log = ev->log;

    n = ngx_http_vhost_traffic_status_dump_header_read(&file, &file_header);

    ngx_http_vhost_traffic_status_file_close(&file);

    if (n != sizeof(ngx_http_vhost_traffic_status_dump_header_t)) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                      "dump_update_valid::dump_header_read() size:%z failed", n);
        return NGX_OK;
    }

    len = (ctx->shm_name.len >= NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_HEADER_NAME_SIZE)
          ? NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_HEADER_NAME_SIZE - 1
          : ctx->shm_name.len;

    if (ngx_strncmp(ctx->shm_name.data, file_header.name, len) != 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                      "dump_update_valid::dump_header_read() name[%z]:\"%s\" failed",
                      len, file_header.name);
        return NGX_OK;
    }

    current_msec = ngx_http_vhost_traffic_status_current_msec();

    rc = ((current_msec - file_header.time) > ctx->dump_period) ? NGX_OK : NGX_ERROR;

    return rc;
}


ngx_int_t
ngx_http_vhost_traffic_status_dump_execute(ngx_event_t *ev)
{
    u_char                               *name;
    ssize_t                               n;
    ngx_fd_t                              fd;
    ngx_file_t                            file;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = ev->data;

    name = ctx->dump_file.data;

    fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

    file.fd = fd;
    file.name = ctx->dump_file;
    file.log = ev->log;

    ngx_http_vhost_traffic_status_file_lock(&file);

    n = ngx_http_vhost_traffic_status_dump_header_write(ev, &file);
    if (n != sizeof(ngx_http_vhost_traffic_status_dump_header_t)) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "dump_execute::dump_header_write() failed");

        ngx_http_vhost_traffic_status_file_unlock(&file);
        ngx_http_vhost_traffic_status_file_close(&file);

        return NGX_ERROR;
    }

    ngx_http_vhost_traffic_status_dump_node_write(ev, &file, ctx->rbtree->root);

    ngx_http_vhost_traffic_status_file_unlock(&file);
    ngx_http_vhost_traffic_status_file_close(&file);

    return NGX_OK;
}


void
ngx_http_vhost_traffic_status_dump_handler(ngx_event_t *ev)
{
    ngx_int_t  rc;

    if (ngx_exiting) {
        return;
    }

    rc = ngx_http_vhost_traffic_status_dump_update_valid(ev);
    if (rc != NGX_OK) {
        goto invalid;
    }

    rc = ngx_http_vhost_traffic_status_dump_execute(ev);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "dump_handler::dump_header_execute() failed");
    }

invalid:

    ngx_add_timer(ev, 1000);
}


static ngx_int_t
ngx_http_vhost_traffic_status_dump_restore_add_node(ngx_event_t *ev,
     ngx_http_vhost_traffic_status_node_t *ovtsn, ngx_str_t *key)
{
    size_t                                 size;
    uint32_t                               hash;
    ngx_slab_pool_t                       *shpool;
    ngx_rbtree_node_t                     *node;
    ngx_http_vhost_traffic_status_ctx_t   *ctx;
    ngx_http_vhost_traffic_status_node_t  *vtsn;

    ctx = ev->data;

    if (key->len == 0) {
        return NGX_ERROR;
    }

    shpool = (ngx_slab_pool_t *) ctx->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    /* find node */
    hash = ngx_crc32_short(key->data, key->len);

    node = ngx_http_vhost_traffic_status_node_lookup(ctx->rbtree, key, hash);

    /* copy node */
    if (node == NULL) {
        size = offsetof(ngx_rbtree_node_t, color)
               + offsetof(ngx_http_vhost_traffic_status_node_t, data)
               + key->len;

        node = ngx_slab_alloc_locked(shpool, size);
        if (node == NULL) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "dump_restore_add_node::ngx_slab_alloc_locked() failed");

            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        vtsn = (ngx_http_vhost_traffic_status_node_t *) &node->color;

        node->key = hash;

        *vtsn = *ovtsn;

        ngx_memcpy(vtsn->data, key->data, key->len);

        ngx_rbtree_insert(ctx->rbtree, node);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


void
ngx_http_vhost_traffic_status_dump_restore(ngx_event_t *ev)
{
    off_t                                         offset;
    size_t                                        len;
    ssize_t                                       n;
    u_char                                       *buf, *pad;
    ngx_fd_t                                      fd;
    ngx_str_t                                     key;
    ngx_int_t                                     rc;
    ngx_file_t                                    file;
    ngx_http_vhost_traffic_status_ctx_t          *ctx;
    ngx_http_vhost_traffic_status_node_t          vtsn;
    ngx_http_vhost_traffic_status_dump_header_t   file_header;

    ctx = ev->data;

    fd = ngx_open_file(ctx->dump_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, ngx_errno,
                       ngx_open_file_n " \"%s\" failed", ctx->dump_file.data);
        return;
    }

    file.fd = fd;
    file.name = ctx->dump_file;
    file.log = ev->log;

    n = ngx_http_vhost_traffic_status_dump_header_read(&file, &file_header);

    if (n != sizeof(ngx_http_vhost_traffic_status_dump_header_t)) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                      "dump_restore::dump_header_read() size:%z failed", n);
        ngx_http_vhost_traffic_status_file_close(&file);
        return;
    }

    len = (ctx->shm_name.len >= NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_HEADER_NAME_SIZE)
          ? NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_HEADER_NAME_SIZE - 1
          : ctx->shm_name.len;

    if (ngx_strncmp(ctx->shm_name.data, file_header.name, len) != 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                      "dump_restore::dump_header_read() name[%z]:\"%s\" failed",
                      len, file_header.name);
        ngx_http_vhost_traffic_status_file_close(&file);
        return;
    }

    buf = ngx_pcalloc(ngx_cycle->pool, NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_BUF_SIZE);
    pad = ngx_pcalloc(ngx_cycle->pool, sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_PAD));
    if (buf == NULL || pad == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "dump_restore::ngx_pcalloc() failed");
        ngx_http_vhost_traffic_status_file_close(&file);
        return;
    }

    offset = n;

    for ( ;; ) {
        ngx_memzero(buf, NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_BUF_SIZE);

        /* read: node */
        n = ngx_read_file(&file, (u_char *) &vtsn,
                          sizeof(ngx_http_vhost_traffic_status_node_t), offset);

        if (n == NGX_ERROR || n == 0
            || n != sizeof(ngx_http_vhost_traffic_status_node_t)) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                          "dump_restore::ngx_read_file() node size:%z failed", n);
            break;
        }

        if (vtsn.len > NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_BUF_SIZE) {
            offset += vtsn.len + sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_PAD);
            continue;
        }

        /* read: data */
        offset += n;
        n = ngx_read_file(&file, buf, vtsn.len, offset);
        if (n != vtsn.len) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                          "dump_restore::ngx_read_file() read:%z, data:%z failed",
                          n, vtsn.len);
            break;
        }

        /* read: pad */
        offset += n;
        n = ngx_read_file(&file, pad,
                          sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_PAD),
                          offset);
        if (n == NGX_ERROR || n == 0
            || n != sizeof(NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_PAD))
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                          "dump_restore::ngx_read_file() pad size:%z failed", n);
            break;
        }

        if (ngx_memcmp(NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_PAD, pad, n) != 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                           "dump_restore::ngx_read_file() pad does not match");
            break;
        }

        /* push: node */
        key.len = vtsn.len;
        key.data = buf;

        rc = ngx_http_vhost_traffic_status_dump_restore_add_node(ev, &vtsn, &key);
        if (rc != NGX_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                           "dump_restore::dump_restore_add_node() failed");
            break;
        }

        offset += n;
    }

    ngx_http_vhost_traffic_status_file_close(&file);
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
