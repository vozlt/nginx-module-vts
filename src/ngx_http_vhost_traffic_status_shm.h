
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_SHM_H_INCLUDED_
#define _NGX_HTTP_VTS_SHM_H_INCLUDED_


typedef struct {
    ngx_str_t   *name;
    ngx_uint_t   max_size;
    ngx_uint_t   used_size;
    ngx_uint_t   used_node;

    ngx_uint_t   filter_used_size;
    ngx_uint_t   filter_used_node;
} ngx_http_vhost_traffic_status_shm_info_t;


ngx_int_t ngx_http_vhost_traffic_status_shm_add_server(ngx_http_request_t *r);
ngx_int_t ngx_http_vhost_traffic_status_shm_add_filter(ngx_http_request_t *r);
ngx_int_t ngx_http_vhost_traffic_status_shm_add_upstream(ngx_http_request_t *r);

#if (NGX_HTTP_CACHE)
ngx_int_t ngx_http_vhost_traffic_status_shm_add_cache(ngx_http_request_t *r);
#endif

void ngx_http_vhost_traffic_status_shm_info_node(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_shm_info_t *shm_info, ngx_rbtree_node_t *node);
void ngx_http_vhost_traffic_status_shm_info(ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_shm_info_t *shm_info);


#endif /* _NGX_HTTP_VTS_SHM_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
