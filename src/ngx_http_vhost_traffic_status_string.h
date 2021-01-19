
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_STRING_H_INCLUDED_
#define _NGX_HTTP_VTS_STRING_H_INCLUDED_


#if !defined(nginx_version) || nginx_version < 1007009
uintptr_t ngx_http_vhost_traffic_status_escape_json(u_char *dst, u_char *src, size_t size);
#endif
ngx_int_t ngx_http_vhost_traffic_status_escape_json_pool(ngx_pool_t *pool,
    ngx_str_t *buf, ngx_str_t *dst);
ngx_int_t ngx_http_vhost_traffic_status_copy_str(ngx_pool_t *pool,
    ngx_str_t *buf, ngx_str_t *dst);
ngx_int_t ngx_http_vhost_traffic_status_replace_chrc(ngx_str_t *buf,
    u_char in, u_char to);
ngx_int_t ngx_http_vhost_traffic_status_replace_strc(ngx_str_t *buf,
    ngx_str_t *dst, u_char c);
ngx_int_t ngx_http_vhost_traffic_status_escape_prometheus(ngx_pool_t *pool, ngx_str_t *buf,
	u_char *p, size_t n);

#endif /* _NGX_HTTP_VTS_STRING_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
