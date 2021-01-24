
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_DISPLAY_JSON_H_INCLUDED_
#define _NGX_HTTP_VTS_DISPLAY_JSON_H_INCLUDED_


#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S           "{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_S    "\"%V\":{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S     "\"%V\":["

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E     "]"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_E    "}"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E           "}"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT        ","

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_MAIN "\"hostName\":\"%V\","     \
    "\"moduleVersion\":\"%s\","                                                \
    "\"nginxVersion\":\"%s\","                                                 \
    "\"loadMsec\":%M,"                                                         \
    "\"nowMsec\":%M,"                                                          \
    "\"connections\":{"                                                        \
    "\"active\":%uA,"                                                          \
    "\"reading\":%uA,"                                                         \
    "\"writing\":%uA,"                                                         \
    "\"waiting\":%uA,"                                                         \
    "\"accepted\":%uA,"                                                        \
    "\"handled\":%uA,"                                                         \
    "\"requests\":%uA"                                                         \
    "},"                                                                       \
    "\"sharedZones\":{"                                                        \
    "\"name\":\"%V\","                                                         \
    "\"maxSize\":%ui,"                                                         \
    "\"usedSize\":%ui,"                                                        \
    "\"usedNode\":%ui"                                                         \
    "},"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S "\"serverZones\":{"

#if (NGX_HTTP_CACHE)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER "\"%V\":{"               \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"                                                           \
    "},"                                                                       \
    "\"requestMsecCounter\":%uA,"                                              \
    "\"requestMsec\":%M,"                                                      \
    "\"requestMsecs\":{"                                                       \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"requestBuckets\":{"                                                     \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA,"                                                          \
    "\"requestMsecCounter\":%uA"                                               \
    "}"                                                                        \
    "},"
#else
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER "\"%V\":{"               \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "},"                                                                       \
    "\"requestMsecCounter\":%uA,"                                              \
    "\"requestMsec\":%M,"                                                      \
    "\"requestMsecs\":{"                                                       \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"requestBuckets\":{"                                                     \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"requestMsecCounter\":%uA"                                               \
    "}"                                                                        \
    "},"
#endif

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER_S "\"filterZones\":{"

#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S "\"upstreamZones\":{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM "{\"server\":\"%V\","  \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA"                                                              \
    "},"                                                                       \
    "\"requestMsecCounter\":%uA,"                                              \
    "\"requestMsec\":%M,"                                                      \
    "\"requestMsecs\":{"                                                       \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"requestBuckets\":{"                                                     \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"responseMsecCounter\":%uA,"                                             \
    "\"responseMsec\":%M,"                                                     \
    "\"responseMsecs\":{"                                                      \
    "\"times\":[%s],"                                                          \
    "\"msecs\":[%s]"                                                           \
    "},"                                                                       \
    "\"responseBuckets\":{"                                                    \
    "\"msecs\":[%s],"                                                          \
    "\"counters\":[%s]"                                                        \
    "},"                                                                       \
    "\"weight\":%ui,"                                                          \
    "\"maxFails\":%ui,"                                                        \
    "\"failTimeout\":%T,"                                                      \
    "\"backup\":%s,"                                                           \
    "\"down\":%s,"                                                             \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"requestCounter\":%uA,"                                                  \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"1xx\":%uA,"                                                             \
    "\"2xx\":%uA,"                                                             \
    "\"3xx\":%uA,"                                                             \
    "\"4xx\":%uA,"                                                             \
    "\"5xx\":%uA,"                                                             \
    "\"requestMsecCounter\":%uA,"                                              \
    "\"responseMsecCounter\":%uA"                                              \
    "}"                                                                        \
    "},"

#if (NGX_HTTP_CACHE)
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE_S "\"cacheZones\":{"
#define NGX_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE "\"%V\":{"                \
    "\"maxSize\":%uA,"                                                         \
    "\"usedSize\":%uA,"                                                        \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"responses\":{"                                                          \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"                                                           \
    "},"                                                                       \
    "\"overCounts\":{"                                                         \
    "\"maxIntegerSize\":%s,"                                                   \
    "\"inBytes\":%uA,"                                                         \
    "\"outBytes\":%uA,"                                                        \
    "\"miss\":%uA,"                                                            \
    "\"bypass\":%uA,"                                                          \
    "\"expired\":%uA,"                                                         \
    "\"stale\":%uA,"                                                           \
    "\"updating\":%uA,"                                                        \
    "\"revalidated\":%uA,"                                                     \
    "\"hit\":%uA,"                                                             \
    "\"scarce\":%uA"                                                           \
    "}"                                                                        \
    "},"
#endif


u_char *ngx_http_vhost_traffic_status_display_set_main(
    ngx_http_request_t *r, u_char *buf);
u_char *ngx_http_vhost_traffic_status_display_set_server_node(
    ngx_http_request_t *r,
    u_char *buf, ngx_str_t *key,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_display_set_server(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_display_set_filter_node(
    ngx_http_request_t *r, u_char *buf,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_display_set_filter(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_display_set_upstream_node(
    ngx_http_request_t *r, u_char *buf,
    ngx_http_upstream_server_t *us,
#if nginx_version > 1007001
    ngx_http_vhost_traffic_status_node_t *vtsn
#else
    ngx_http_vhost_traffic_status_node_t *vtsn, ngx_str_t *name
#endif
    );
u_char *ngx_http_vhost_traffic_status_display_set_upstream_alone(
    ngx_http_request_t *r, u_char *buf, ngx_rbtree_node_t *node);
u_char *ngx_http_vhost_traffic_status_display_set_upstream_group(
    ngx_http_request_t *r, u_char *buf);

#if (NGX_HTTP_CACHE)
u_char *ngx_http_vhost_traffic_status_display_set_cache_node(
    ngx_http_request_t *r, u_char *buf,
    ngx_http_vhost_traffic_status_node_t *vtsn);
u_char *ngx_http_vhost_traffic_status_display_set_cache(
    ngx_http_request_t *r, u_char *buf,
    ngx_rbtree_node_t *node);
#endif

u_char *ngx_http_vhost_traffic_status_display_set(ngx_http_request_t *r,
    u_char *buf);


#endif /* _NGX_HTTP_VTS_DISPLAY_JSON_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
