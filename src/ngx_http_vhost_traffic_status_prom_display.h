
#ifndef _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_
#define _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_MAIN  \
    "# HELP nginx_server_uptime nginx uptime and server info\n" \
    "# TYPE nginx_server_uptime counter\n" \
    "nginx_server_uptime{hostname=\"%V\",version=\"%s\"} %.1f\n" \
    "# HELP nginx_server_connections nginx connections\n" \
    "# TYPE nginx_server_connections gauge\n" \
    "nginx_server_connections{status=\"accepted\"} %uA\n" \
    "nginx_server_connections{status=\"active\"} %uA\n" \
    "nginx_server_connections{status=\"handled\"} %uA\n" \
    "nginx_server_connections{status=\"reading\"} %uA\n" \
    "nginx_server_connections{status=\"requests\"} %uA\n" \
    "nginx_server_connections{status=\"waiting\"} %uA\n" \
    "nginx_server_connections{status=\"writing\"} %uA\n"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_SERVER \
    "# HELP nginx_server_requests requests counter\n" \
    "# TYPE nginx_server_requests counter\n" \
    "nginx_server_requests{code=\"1xx\",host=\"%V\"} %uA\n" \
    "nginx_server_requests{code=\"2xx\",host=\"%V\"} %uA\n" \
    "nginx_server_requests{code=\"3xx\",host=\"%V\"} %uA\n" \
    "nginx_server_requests{code=\"4xx\",host=\"%V\"} %uA\n" \
    "nginx_server_requests{code=\"5xx\",host=\"%V\"} %uA\n" \
    "# HELP nginx_server_bytes request/response bytes\n" \
    "# TYPE nginx_server_bytes counter\n" \
    "nginx_server_bytes{direction=\"in\",host=\"%V\"} %uA\n" \
    "nginx_server_bytes{direction=\"out\",host=\"%V\"} %uA\n" \
    "# HELP nginx_server_request_sec average of request processing times in seconds\n" \
    "# TYPE nginx_server_request_sec gauge\n" \
    "nginx_server_request_sec{host=\"%V\"} %.3f\n"

#if (NGX_HTTP_CACHE)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_SERVER_CACHE \
    "# HELP nginx_server_cache cache hits/misses for server\n" \
    "# TYPE nginx_server_cache counter\n" \
    "nginx_server_cache{host=\"%V\",status=\"miss\"} %uA\n" \
    "nginx_server_cache{host=\"%V\",status=\"bypass\"} %uA\n" \
    "nginx_server_cache{host=\"%V\",status=\"expired\"} %uA\n" \
    "nginx_server_cache{host=\"%V\",status=\"stale\"} %uA\n" \
    "nginx_server_cache{host=\"%V\",status=\"updating\"} %uA\n" \
    "nginx_server_cache{host=\"%V\",status=\"revalidated\"} %uA\n" \
    "nginx_server_cache{host=\"%V\",status=\"hit\"} %uA\n" \
    "nginx_server_cache{host=\"%V\",status=\"scarce\"} %uA\n"

#endif

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_FILTER \
    "# HELP nginx_filter_bytes request/response bytes\n" \
    "# TYPE nginx_filter_bytes counter\n" \
    "nginx_filter_bytes{direction=\"in\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_bytes{direction=\"out\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "# HELP nginx_filter_requests requests counter\n" \
    "# TYPE nginx_filter_requests counter\n" \
    "nginx_filter_requests{code=\"1xx\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_requests{code=\"2xx\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_requests{code=\"3xx\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_requests{code=\"4xx\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_requests{code=\"5xx\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "# HELP nginx_filter_request_sec average of request processing times in seconds\n" \
    "# TYPE nginx_filter_request_sec gauge\n" \
    "nginx_filter_request_sec{filter=\"%V\",filter_name=\"%V\"} %.3f\n"

#if (NGX_HTTP_CACHE)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_FILTER_CACHE \
    "# HELP nginx_filter_cache filter cache requests\n" \
    "# TYPE nginx_filter_cache counter\n" \
    "nginx_filter_cache{status=\"miss\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"bypass\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"expired\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"stale\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"updating\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"revalidated\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"hit\",filter=\"%V\",filter_name=\"%V\"} %uA\n" \
    "nginx_filter_cache{status=\"scarce\",filter=\"%V\",filter_name=\"%V\"} %uA\n"
#endif

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_UPSTREAM \
    "# HELP nginx_upstream_bytes request/response bytes\n" \
    "# TYPE nginx_upstream_bytes counter\n" \
    "nginx_upstream_bytes{upstream=\"%V\",backend=\"%V\",direction=\"in\"} %uA\n" \
    "nginx_upstream_bytes{upstream=\"%V\",backend=\"%V\",direction=\"out\"} %uA\n" \
    "# HELP nginx_upstream_request_sec average of request processing times in seconds\n" \
    "# TYPE nginx_upstream_request_sec gauge\n" \
    "nginx_upstream_request_sec{upstream=\"%V\",backend=\"%V\"} %.3f\n" \
    "# HELP nginx_upstream_response_sec average of only upstream/backend response processing times in seconds\n" \
    "# TYPE nginx_upstream_response_sec gauge\n" \
    "nginx_upstream_response_sec{upstream=\"%V\",backend=\"%V\"} %.3f\n" \
    "# HELP nginx_upstream_requests requests counter\n" \
    "# TYPE nginx_upstream_requests counter\n" \
    "nginx_upstream_requests{upstream=\"%V\",backend=\"%V\"} %uA\n" \
    "# HELP nginx_upstream_response upstream response breakdown\n" \
    "# TYPE nginx_upstream_response counter\n" \
    "nginx_upstream_response{upstream=\"%V\",backend=\"%V\",code=\"1xx\"} %uA\n" \
    "nginx_upstream_response{upstream=\"%V\",backend=\"%V\",code=\"2xx\"} %uA\n" \
    "nginx_upstream_response{upstream=\"%V\",backend=\"%V\",code=\"3xx\"} %uA\n" \
    "nginx_upstream_response{upstream=\"%V\",backend=\"%V\",code=\"4xx\"} %uA\n" \
    "nginx_upstream_response{upstream=\"%V\",backend=\"%V\",code=\"5xx\"} %uA\n"

#if (NGX_HTTP_CACHE)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_PROM_FMT_CACHE \
    "# HELP nginx_cache_size cache zones request/response bytes\n" \
    "# TYPE nginx_cache_size gauge\n" \
    "nginx_cache_size{cache_zone=\"%V\",cache_size=\"max\"} %uA\n" \
    "nginx_cache_size{cache_zone=\"%V\",cache_size=\"used\"} %uA\n" \
    "# HELP nginx_cache_bytes cache zones request/response bytes\n" \
    "# TYPE nginx_cache_bytes counter\n" \
    "nginx_cache_bytes{cache_zone=\"%V\",direction=\"in\"} %uA\n" \
    "nginx_cache_bytes{cache_zone=\"%V\",direction=\"out\"} %uA\n" \
    "# HELP nginx_cache_requests cache hits/misses for cache zones\n" \
    "# TYPE nginx_cache_requests counter\n" \
    "nginx_cache_requests{cache_zone=\"%V\",status=\"miss\"} %uA\n" \
    "nginx_cache_requests{cache_zone=\"%V\",status=\"bypass\"} %uA\n" \
    "nginx_cache_requests{cache_zone=\"%V\",status=\"expired\"} %uA\n" \
    "nginx_cache_requests{cache_zone=\"%V\",status=\"stale\"} %uA\n" \
    "nginx_cache_requests{cache_zone=\"%V\",status=\"updating\"} %uA\n" \
    "nginx_cache_requests{cache_zone=\"%V\",status=\"revalidated\"} %uA\n" \
    "nginx_cache_requests{cache_zone=\"%V\",status=\"hit\"} %uA\n" \
    "nginx_cache_requests{cache_zone=\"%V\",status=\"scarce\"} %uA\n"

#endif

u_char *ngx_http_vhost_traffic_status_prom_display_set(ngx_http_request_t *r,
                                                  u_char *buf);
u_char *ngx_http_vhost_traffic_status_prom_display_set_server(
        ngx_http_request_t *r, u_char *buf,
        ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_prom_display_set_server_node(
        ngx_http_request_t *r,
        u_char *buf, ngx_str_t *key,
        ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_prom_display_set_filter(
        ngx_http_request_t *r, u_char *buf,
        ngx_rbtree_node_t *node);

u_char *ngx_http_vhost_traffic_status_prom_display_set_upstream_node(
        ngx_http_request_t *r, u_char *buf,
        ngx_http_upstream_server_t *us,
        ngx_str_t *upstream_name,
#if nginx_version > 1007001
        ngx_http_vhost_traffic_status_node_t *vtsn
#else
        ngx_http_vhost_traffic_status_node_t *vtsn, ngx_str_t *name
#endif
);
u_char *ngx_http_vhost_traffic_status_prom_display_set_upstream_alone(
        ngx_http_request_t *r, u_char *buf, ngx_rbtree_node_t *node, ngx_str_t *upstream_name);
u_char *ngx_http_vhost_traffic_status_prom_display_set_upstream_group(
        ngx_http_request_t *r, u_char *buf);
#if (NGX_HTTP_CACHE)
u_char *ngx_http_vhost_traffic_status_prom_display_set_cache_node(
    ngx_http_request_t *r, u_char *buf,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_prom_display_set_cache(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
#endif


u_char *ngx_http_vhost_traffic_status_prom_display_set_main(
        ngx_http_request_t *r, u_char *buf);

#endif /* _NGX_HTTP_VTS_PROM_DISPLAY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
