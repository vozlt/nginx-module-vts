
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_SHM_H_INCLUDED_
#define _NGX_HTTP_VTS_SHM_H_INCLUDED_


ngx_int_t ngx_http_vhost_traffic_status_shm_add_server(ngx_http_request_t *r);
ngx_int_t ngx_http_vhost_traffic_status_shm_add_filter(ngx_http_request_t *r);
ngx_int_t ngx_http_vhost_traffic_status_shm_add_upstream(ngx_http_request_t *r);

#if (NGX_HTTP_CACHE)
ngx_int_t ngx_http_vhost_traffic_status_shm_add_cache(ngx_http_request_t *r);
#endif


#endif /* _NGX_HTTP_VTS_SHM_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
