
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_VARIABLES_H_INCLUDED_
#define _NGX_HTTP_VTS_VARIABLES_H_INCLUDED_


ngx_int_t ngx_http_vhost_traffic_status_node_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t ngx_http_vhost_traffic_status_add_variables(ngx_conf_t *cf);


#endif /* _NGX_HTTP_VTS_VARIABLES_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
