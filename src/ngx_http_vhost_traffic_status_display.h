
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_DISPLAY_H_INCLUDED_
#define _NGX_HTTP_VTS_DISPLAY_H_INCLUDED_


/*
 * Size of the main/connections/sharedZones part and of the section headers.
 * The prometheus HELP/TYPE headers alone are slightly above 4k.
 */
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DISPLAY_MAIN_LEN         8192

/* assumed length of the names that come from the configuration */
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DISPLAY_CONF_NAME_LEN    1024

/* upper bound of one prometheus line without the node name */
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DISPLAY_PROMETHEUS_LINE  128

/* worst case expansion of ngx_http_vhost_traffic_status_escape_json_pool() */
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_DISPLAY_JSON_ESCAPE      6


ngx_int_t ngx_http_vhost_traffic_status_display_get_upstream_nelts(
    ngx_http_request_t *r);
ngx_int_t ngx_http_vhost_traffic_status_display_get_size(
    ngx_http_request_t *r, ngx_int_t format);

size_t ngx_http_vhost_traffic_status_display_node_size(ngx_http_request_t *r,
    size_t name_len, ngx_int_t format);
ngx_int_t ngx_http_vhost_traffic_status_display_buffer_check(
    ngx_http_request_t *r, u_char *buf, size_t name_len, ngx_int_t format);

u_char *ngx_http_vhost_traffic_status_display_get_time_queue(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_time_queue_t *q,
    ngx_uint_t offset);
u_char *ngx_http_vhost_traffic_status_display_get_time_queue_times(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_time_queue_t *q);
u_char *ngx_http_vhost_traffic_status_display_get_time_queue_msecs(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_time_queue_t *q);

u_char *ngx_http_vhost_traffic_status_display_get_histogram_bucket(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_histogram_bucket_t *b,
    ngx_uint_t offset, const char *fmt);
u_char *ngx_http_vhost_traffic_status_display_get_histogram_bucket_msecs(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_histogram_bucket_t *b);
u_char *ngx_http_vhost_traffic_status_display_get_histogram_bucket_counters(
    ngx_http_request_t *r,
    ngx_http_vhost_traffic_status_node_histogram_bucket_t *q);



char *ngx_http_vhost_traffic_status_display(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


#endif /* _NGX_HTTP_VTS_DISPLAY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
