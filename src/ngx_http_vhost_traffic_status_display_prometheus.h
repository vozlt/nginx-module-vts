
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_DISPLAY_PROMETHEUS_H_INCLUDED_
#define _NGX_HTTP_VTS_DISPLAY_PROMETHEUS_H_INCLUDED_


#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_MAIN                      \
    "# HELP nginx_vts_info Nginx info\n"                                       \
    "# TYPE nginx_vts_info gauge\n"                                            \
    "nginx_vts_info{hostname=\"%V\",module_version=\"%s\",version=\"%s\"} 1\n" \
    "# HELP nginx_vts_start_time_seconds Nginx start time\n"                   \
    "# TYPE nginx_vts_start_time_seconds gauge\n"                              \
    "nginx_vts_start_time_seconds %.3f\n"                                      \
    "# HELP nginx_vts_main_connections Nginx connections\n"                    \
    "# TYPE nginx_vts_main_connections gauge\n"                                \
    "nginx_vts_main_connections{status=\"accepted\"} %uA\n"                    \
    "nginx_vts_main_connections{status=\"active\"} %uA\n"                      \
    "nginx_vts_main_connections{status=\"handled\"} %uA\n"                     \
    "nginx_vts_main_connections{status=\"reading\"} %uA\n"                     \
    "nginx_vts_main_connections{status=\"requests\"} %uA\n"                    \
    "nginx_vts_main_connections{status=\"waiting\"} %uA\n"                     \
    "nginx_vts_main_connections{status=\"writing\"} %uA\n"                     \
    "# HELP nginx_vts_main_shm_usage_bytes Shared memory [%V] info\n"          \
    "# TYPE nginx_vts_main_shm_usage_bytes gauge\n"                            \
    "nginx_vts_main_shm_usage_bytes{shared=\"max_size\"} %ui\n"                \
    "nginx_vts_main_shm_usage_bytes{shared=\"used_size\"} %ui\n"               \
    "nginx_vts_main_shm_usage_bytes{shared=\"used_node\"} %ui\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_S                  \
    "# HELP nginx_vts_server_bytes_total The request/response bytes\n"         \
    "# TYPE nginx_vts_server_bytes_total counter\n"                            \
    "# HELP nginx_vts_server_requests_total The requests counter\n"            \
    "# TYPE nginx_vts_server_requests_total counter\n"                         \
    "# HELP nginx_vts_server_request_seconds_total The request processing "    \
    "time in seconds\n"                                                        \
    "# TYPE nginx_vts_server_request_seconds_total counter\n"                  \
    "# HELP nginx_vts_server_request_seconds The average of request "          \
    "processing times in seconds\n"                                            \
    "# TYPE nginx_vts_server_request_seconds gauge\n"                          \
    "# HELP nginx_vts_server_request_duration_seconds The histogram of "       \
    "request processing time\n"                                                \
    "# TYPE nginx_vts_server_request_duration_seconds histogram\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER                    \
    "nginx_vts_server_bytes_total{host=\"%V\",direction=\"in\"} %uA\n"         \
    "nginx_vts_server_bytes_total{host=\"%V\",direction=\"out\"} %uA\n"        \
    "nginx_vts_server_requests_total{host=\"%V\",code=\"1xx\"} %uA\n"          \
    "nginx_vts_server_requests_total{host=\"%V\",code=\"2xx\"} %uA\n"          \
    "nginx_vts_server_requests_total{host=\"%V\",code=\"3xx\"} %uA\n"          \
    "nginx_vts_server_requests_total{host=\"%V\",code=\"4xx\"} %uA\n"          \
    "nginx_vts_server_requests_total{host=\"%V\",code=\"5xx\"} %uA\n"          \
    "nginx_vts_server_request_seconds_total{host=\"%V\"} %.3f\n"               \
    "nginx_vts_server_request_seconds{host=\"%V\"} %.3f\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET   \
    "nginx_vts_server_request_duration_seconds_bucket{host=\"%V\","            \
    "le=\"%.3f\"} %uA\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET_E \
    "nginx_vts_server_request_duration_seconds_bucket{host=\"%V\","            \
    "le=\"+Inf\"} %uA\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_SUM      \
    "nginx_vts_server_request_duration_seconds_sum{host=\"%V\"} %.3f\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_COUNT    \
    "nginx_vts_server_request_duration_seconds_count{host=\"%V\"} %uA\n"

#if (NGX_HTTP_CACHE)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_CACHE_S            \
    "# HELP nginx_vts_server_cache_total The requests cache counter\n"         \
    "# TYPE nginx_vts_server_cache_total counter\n"
 
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_CACHE              \
    "nginx_vts_server_cache_total{host=\"%V\",status=\"miss\"} %uA\n"          \
    "nginx_vts_server_cache_total{host=\"%V\",status=\"bypass\"} %uA\n"        \
    "nginx_vts_server_cache_total{host=\"%V\",status=\"expired\"} %uA\n"       \
    "nginx_vts_server_cache_total{host=\"%V\",status=\"stale\"} %uA\n"         \
    "nginx_vts_server_cache_total{host=\"%V\",status=\"updating\"} %uA\n"      \
    "nginx_vts_server_cache_total{host=\"%V\",status=\"revalidated\"} %uA\n"   \
    "nginx_vts_server_cache_total{host=\"%V\",status=\"hit\"} %uA\n"           \
    "nginx_vts_server_cache_total{host=\"%V\",status=\"scarce\"} %uA\n"
#endif

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_S                  \
    "# HELP nginx_vts_filter_bytes_total The request/response bytes\n"         \
    "# TYPE nginx_vts_filter_bytes_total counter\n"                            \
    "# HELP nginx_vts_filter_requests_total The requests counter\n"            \
    "# TYPE nginx_vts_filter_requests_total counter\n"                         \
    "# HELP nginx_vts_filter_request_seconds_total The request processing "    \
    "time in seconds counter\n"                                                \
    "# TYPE nginx_vts_filter_request_seconds_total counter\n"                  \
    "# HELP nginx_vts_filter_request_seconds The average of request "          \
    "processing times in seconds\n"                                            \
    "# TYPE nginx_vts_filter_request_seconds gauge\n"                          \
    "# HELP nginx_vts_filter_request_duration_seconds The histogram of "       \
    "request processing time\n"                                                \
    "# TYPE nginx_vts_filter_request_duration_seconds histogram\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER                    \
    "nginx_vts_filter_bytes_total{filter=\"%V\",filter_name=\"%V\","           \
    "direction=\"in\"} %uA\n"                                                  \
    "nginx_vts_filter_bytes_total{filter=\"%V\",filter_name=\"%V\","           \
    "direction=\"out\"} %uA\n"                                                 \
    "nginx_vts_filter_requests_total{filter=\"%V\",filter_name=\"%V\","        \
    "code=\"1xx\"} %uA\n"                                                      \
    "nginx_vts_filter_requests_total{filter=\"%V\",filter_name=\"%V\","        \
    "code=\"2xx\"} %uA\n"                                                      \
    "nginx_vts_filter_requests_total{filter=\"%V\",filter_name=\"%V\","        \
    "code=\"3xx\"} %uA\n"                                                      \
    "nginx_vts_filter_requests_total{filter=\"%V\",filter_name=\"%V\","        \
    "code=\"4xx\"} %uA\n"                                                      \
    "nginx_vts_filter_requests_total{filter=\"%V\",filter_name=\"%V\","        \
    "code=\"5xx\"} %uA\n"                                                      \
    "nginx_vts_filter_request_seconds_total{filter=\"%V\","                    \
    "filter_name=\"%V\"} %.3f\n"                                               \
    "nginx_vts_filter_request_seconds{filter=\"%V\",filter_name=\"%V\"} %.3f\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET   \
    "nginx_vts_filter_request_duration_seconds_bucket{filter=\"%V\","          \
    "filter_name=\"%V\",le=\"%.3f\"} %uA\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET_E \
    "nginx_vts_filter_request_duration_seconds_bucket{filter=\"%V\","          \
    "filter_name=\"%V\",le=\"+Inf\"} %uA\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_SUM      \
    "nginx_vts_filter_request_duration_seconds_sum{filter=\"%V\","             \
    "filter_name=\"%V\"} %.3f\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_COUNT    \
    "nginx_vts_filter_request_duration_seconds_count{filter=\"%V\","           \
    "filter_name=\"%V\"} %uA\n"

#if (NGX_HTTP_CACHE)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_CACHE_S            \
    "# HELP nginx_vts_filter_cache_total The requests cache counter\n"         \
    "# TYPE nginx_vts_filter_cache_total counter\n"
 
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_CACHE              \
    "nginx_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"miss\"} %uA\n"                                                   \
    "nginx_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"bypass\"} %uA\n"                                                 \
    "nginx_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"expired\"} %uA\n"                                                \
    "nginx_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"stale\"} %uA\n"                                                  \
    "nginx_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"updating\"} %uA\n"                                               \
    "nginx_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"revalidated\"} %uA\n"                                            \
    "nginx_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"hit\"} %uA\n"                                                    \
    "nginx_vts_filter_cache_total{filter=\"%V\",filter_name=\"%V\","           \
    "status=\"scarce\"} %uA\n"
#endif

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_S                \
    "# HELP nginx_vts_upstream_bytes_total The request/response bytes\n"       \
    "# TYPE nginx_vts_upstream_bytes_total counter\n"                          \
    "# HELP nginx_vts_upstream_requests_total The upstream requests counter\n" \
    "# TYPE nginx_vts_upstream_requests_total counter\n"                       \
    "# HELP nginx_vts_upstream_request_seconds_total The request Processing "  \
    "time including upstream in seconds\n"                                     \
    "# TYPE nginx_vts_upstream_request_seconds_total counter\n"                \
    "# HELP nginx_vts_upstream_request_seconds The average of request "        \
    "processing times including upstream in seconds\n"                         \
    "# TYPE nginx_vts_upstream_request_seconds gauge\n"                        \
    "# HELP nginx_vts_upstream_response_seconds_total The only upstream "      \
    "response processing time in seconds\n"                                    \
    "# TYPE nginx_vts_upstream_response_seconds_total counter\n"               \
    "# HELP nginx_vts_upstream_response_seconds The average of only "          \
    "upstream response processing times in seconds\n"                          \
    "# TYPE nginx_vts_upstream_response_seconds gauge\n"                       \
    "# HELP nginx_vts_upstream_request_duration_seconds The histogram of "     \
    "request processing time including upstream\n"                             \
    "# TYPE nginx_vts_upstream_request_duration_seconds histogram\n"           \
    "# HELP nginx_vts_upstream_response_duration_seconds The histogram of "    \
    "only upstream response processing time\n"                                 \
    "# TYPE nginx_vts_upstream_response_duration_seconds histogram\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM                  \
    "nginx_vts_upstream_bytes_total{upstream=\"%V\",backend=\"%V\","           \
    "direction=\"in\"} %uA\n"                                                  \
    "nginx_vts_upstream_bytes_total{upstream=\"%V\",backend=\"%V\","           \
    "direction=\"out\"} %uA\n"                                                 \
    "nginx_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"1xx\"} %uA\n"                                                      \
    "nginx_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"2xx\"} %uA\n"                                                      \
    "nginx_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"3xx\"} %uA\n"                                                      \
    "nginx_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"4xx\"} %uA\n"                                                      \
    "nginx_vts_upstream_requests_total{upstream=\"%V\",backend=\"%V\","        \
    "code=\"5xx\"} %uA\n"                                                      \
    "nginx_vts_upstream_request_seconds_total{upstream=\"%V\","                \
    "backend=\"%V\"} %.3f\n"                                                   \
    "nginx_vts_upstream_request_seconds{upstream=\"%V\","                      \
    "backend=\"%V\"} %.3f\n"                                                   \
    "nginx_vts_upstream_response_seconds_total{upstream=\"%V\","               \
    "backend=\"%V\"} %.3f\n"                                                   \
    "nginx_vts_upstream_response_seconds{upstream=\"%V\","                     \
    "backend=\"%V\"} %.3f\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET \
    "nginx_vts_upstream_%V_duration_seconds_bucket{upstream=\"%V\","           \
    "backend=\"%V\",le=\"%.3f\"} %uA\n"

#define                                                                        \
    NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET_E   \
    "nginx_vts_upstream_%V_duration_seconds_bucket{upstream=\"%V\","           \
    "backend=\"%V\",le=\"+Inf\"} %uA\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_SUM    \
    "nginx_vts_upstream_%V_duration_seconds_sum{upstream=\"%V\","              \
    "backend=\"%V\"} %.3f\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_COUNT  \
    "nginx_vts_upstream_%V_duration_seconds_count{upstream=\"%V\","            \
    "backend=\"%V\"} %uA\n"


#if (NGX_HTTP_CACHE)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_CACHE_S                   \
    "# HELP nginx_vts_cache_usage_bytes THe cache zones info\n"                \
    "# TYPE nginx_vts_cache_usage_bytes gauge\n"                               \
    "# HELP nginx_vts_cache_bytes_total The cache zones request/response "     \
    "bytes\n"                                                                  \
    "# TYPE nginx_vts_cache_bytes_total counter\n"                             \
    "# HELP nginx_vts_cache_requests_total The cache requests counter\n"       \
    "# TYPE nginx_vts_cache_requests_total counter\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_CACHE                     \
    "nginx_vts_cache_usage_bytes{cache_zone=\"%V\",cache_size=\"max\"} %uA\n"  \
    "nginx_vts_cache_usage_bytes{cache_zone=\"%V\",cache_size=\"used\"} %uA\n" \
    "nginx_vts_cache_bytes_total{cache_zone=\"%V\",direction=\"in\"} %uA\n"    \
    "nginx_vts_cache_bytes_total{cache_zone=\"%V\",direction=\"out\"} %uA\n"   \
    "nginx_vts_cache_requests_total{cache_zone=\"%V\",status=\"miss\"} %uA\n"  \
    "nginx_vts_cache_requests_total{cache_zone=\"%V\","                        \
    "status=\"bypass\"} %uA\n"                                                 \
    "nginx_vts_cache_requests_total{cache_zone=\"%V\","                        \
    "status=\"expired\"} %uA\n"                                                \
    "nginx_vts_cache_requests_total{cache_zone=\"%V\","                        \
    "status=\"stale\"} %uA\n"                                                  \
    "nginx_vts_cache_requests_total{cache_zone=\"%V\","                        \
    "status=\"updating\"} %uA\n"                                               \
    "nginx_vts_cache_requests_total{cache_zone=\"%V\","                        \
    "status=\"revalidated\"} %uA\n"                                            \
    "nginx_vts_cache_requests_total{cache_zone=\"%V\",status=\"hit\"} %uA\n"   \
    "nginx_vts_cache_requests_total{cache_zone=\"%V\",status=\"scarce\"} %uA\n"
#endif


u_char *ngx_http_vhost_traffic_status_display_prometheus_set_main(
    ngx_http_request_t *r, u_char *buf);
u_char *ngx_http_vhost_traffic_status_display_prometheus_set_server_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_display_prometheus_set_server(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_display_prometheus_set_filter_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_display_prometheus_set_filter(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_display_prometheus_set_upstream_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_display_prometheus_set_upstream(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);

#if (NGX_HTTP_CACHE)
u_char *ngx_http_vhost_traffic_status_display_prometheus_set_cache_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_display_prometheus_set_cache(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
#endif

u_char *ngx_http_vhost_traffic_status_display_prometheus_set(ngx_http_request_t *r,
    u_char *buf);


#endif /* _NGX_HTTP_VTS_DISPLAY_PROMETHEUS_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
