
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_SET_H_INCLUDED_
#define _NGX_HTTP_VTS_SET_H_INCLUDED_


typedef struct {
    ngx_int_t                  index;
    ngx_http_complex_value_t   value;
    ngx_http_set_variable_pt   set_handler;
} ngx_http_vhost_traffic_status_filter_variable_t;


ngx_int_t ngx_http_vhost_traffic_status_set_handler(ngx_http_request_t *r);
char *ngx_http_vhost_traffic_status_set_by_filter(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


#endif /* _NGX_HTTP_VTS_SET_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
