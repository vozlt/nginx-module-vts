
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_DUMP_H_INCLUDED_
#define _NGX_HTTP_VTS_DUMP_H_INCLUDED_


#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_HEADER_NAME_SIZE  128
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_BUF_SIZE     1024

/*
 * This version is owned by the module, not by nginx. Bump it whenever
 * ngx_http_vhost_traffic_status_node_t changes layout, even when sizeof()
 * happens to stay the same.
 */
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_FORMAT_VERSION    1


typedef struct {
    u_char           name[NGX_HTTP_VHOST_TRAFFIC_STATUS_DUMP_HEADER_NAME_SIZE];
    ngx_msec_t       time;
    ngx_uint_t       version;
    ngx_uint_t       node_size;
} ngx_http_vhost_traffic_status_dump_header_t;


void ngx_http_vhost_traffic_status_file_lock(ngx_file_t *file);
void ngx_http_vhost_traffic_status_file_unlock(ngx_file_t *file);
void ngx_http_vhost_traffic_status_file_close(ngx_file_t *file);

ngx_int_t ngx_http_vhost_traffic_status_dump_execute(ngx_event_t *ev);
void ngx_http_vhost_traffic_status_dump_handler(ngx_event_t *ev);
void ngx_http_vhost_traffic_status_dump_restore(ngx_event_t *ev);


#endif /* _NGX_HTTP_VTS_DUMP_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
