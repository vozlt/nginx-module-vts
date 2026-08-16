
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NGX_HTTP_VTS_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_VTS_UPSTREAM_H_INCLUDED_


/*
 * Called once for each peer the upstream group holds, with the name of the
 * peer and the attributes the module reports for it. Returning NGX_OK asks
 * for the next peer; anything else ends the walk, and the walk returns what
 * the handler returned.
 *
 * `name` and `usn` are only good for the length of the call. Where the group
 * has a zone the name is the one held there, and the walk holds the lock of
 * the peer list around the handler, so a handler that keeps the name past its
 * own return has to take a copy of it - a re-resolve gives the peer back to
 * the slab of the upstream as soon as the lock is released.
 */
typedef ngx_int_t (*ngx_http_vhost_traffic_status_upstream_peer_pt)(
    ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf,
    ngx_str_t *name, ngx_http_upstream_server_t *usn, void *data);

ngx_int_t ngx_http_vhost_traffic_status_upstream_peers_walk(
    ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf,
    ngx_http_vhost_traffic_status_upstream_peer_pt handler, void *data);


#endif /* _NGX_HTTP_VTS_UPSTREAM_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
