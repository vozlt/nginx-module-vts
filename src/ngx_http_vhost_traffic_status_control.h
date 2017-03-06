
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_CONTROL_H_INCLUDED_
#define _NGX_HTTP_VTS_CONTROL_H_INCLUDED_


#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE     0
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_STATUS   1
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_DELETE   2
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_RESET    3

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_NONE   0
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL    1
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP  2
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE   3

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CONTROL "{"                     \
    "\"processingReturn\":%s,"                                                 \
    "\"processingCommandString\":\"%V\","                                      \
    "\"processingGroupString\":\"%V\","                                        \
    "\"processingZoneString\":\"%V\","                                         \
    "\"processingCounts\":%ui"                                                 \
    "}"


typedef struct {
    ngx_rbtree_node_t           *node;
} ngx_http_vhost_traffic_status_delete_t;


typedef struct {
    ngx_http_request_t          *r;
    ngx_uint_t                   command;
    ngx_int_t                    group;
    ngx_str_t                   *zone;
    ngx_str_t                   *arg_cmd;
    ngx_str_t                   *arg_group;
    ngx_str_t                   *arg_zone;
    ngx_str_t                   *arg_name;
    ngx_uint_t                   range;
    ngx_uint_t                   count;
    u_char                     **buf;
} ngx_http_vhost_traffic_status_control_t;


void ngx_http_vhost_traffic_status_node_control_range_set(
    ngx_http_vhost_traffic_status_control_t *control);
void ngx_http_vhost_traffic_status_node_status(
    ngx_http_vhost_traffic_status_control_t *control);
void ngx_http_vhost_traffic_status_node_delete(
    ngx_http_vhost_traffic_status_control_t *control);
void ngx_http_vhost_traffic_status_node_reset(
    ngx_http_vhost_traffic_status_control_t *control);

void ngx_http_vhost_traffic_status_node_upstream_lookup(
    ngx_http_vhost_traffic_status_control_t *control,
    ngx_http_upstream_server_t *us);

#endif /* _NGX_HTTP_VTS_CONTROL_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
