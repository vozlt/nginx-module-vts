
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_upstream.h"

#if (NGX_HTTP_UPSTREAM_CHECK)
#include "ngx_http_upstream_check_module.h"
#endif


/*
 * Where the peers of an upstream group are, and what the module says about
 * each of them. Everything that reads a group - the display, the buffer it is
 * sized into, the peers a group no longer holds, and the control interface -
 * reads it through here, so that the answers cannot disagree.
 *
 * There are two sources and they are exclusive rather than one falling back to
 * the other. A group with a zone is read from its peer lists, which hold the
 * peers made at run time as well as the ones the configuration names, and the
 * backups are a list of their own hanging off peers->next. A group without a
 * zone is read from its server lines. Reading the lines of a group that has a
 * zone would answer for the placeholder a `resolve` line leaves behind, whose
 * name is never set, and miss the peer that took its place.
 *
 * Which list a peer was found in is what says whether it is a backup: a name
 * resolved at run time is not written down anywhere else.
 */

ngx_int_t
ngx_http_vhost_traffic_status_upstream_peers_walk(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *uscf,
    ngx_http_vhost_traffic_status_upstream_peer_pt handler, void *data)
{
    ngx_int_t                     rc;
    ngx_str_t                     name;
    ngx_uint_t                    i, j;
    ngx_http_upstream_server_t   *us, usn;
#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_uint_t                    backup;
    ngx_http_upstream_rr_peer_t  *peer;
    ngx_http_upstream_rr_peers_t *peers;

    if (uscf->shm_zone != NULL) {

        for (backup = 0, peers = uscf->peer.data;
             peers;
             peers = peers->next, backup = 1)
        {
            ngx_http_upstream_rr_peers_rlock(peers);

            for (peer = peers->peer; peer; peer = peer->next) {

                ngx_memzero(&usn, sizeof(ngx_http_upstream_server_t));

                usn.weight = peer->weight;
                usn.max_fails = peer->max_fails;
                usn.fail_timeout = peer->fail_timeout;
                usn.backup = backup;

#if (NGX_HTTP_UPSTREAM_CHECK)
                usn.down = ngx_http_upstream_check_peer_down(peer->check_index)
                           ? 1 : 0;
#else

                /*
                 * max_fails 0 turns the counting off, which nginx reads as
                 * never taking the peer out; without the guard the comparison
                 * holds from the first request and every such peer is called
                 * down
                 */

                usn.down = (peer->down
                            || (peer->max_fails
                                && peer->fails >= peer->max_fails));
#endif

                name = peer->name;

#if nginx_version > 1007001
                usn.name = name;
#endif

                rc = handler(r, uscf, &name, &usn, data);

                if (rc != NGX_OK) {
                    ngx_http_upstream_rr_peers_unlock(peers);
                    return rc;
                }
            }

            ngx_http_upstream_rr_peers_unlock(peers);
        }

        return NGX_OK;
    }

#endif

    us = uscf->servers->elts;

    for (i = 0; i < uscf->servers->nelts; i++) {

        /* a server gives one peer per address its name resolves to */

        for (j = 0; j < us[i].naddrs; j++) {

            usn = us[i];
            name = us[i].addrs[j].name;

#if nginx_version > 1007001
            usn.name = name;
#endif

            rc = handler(r, uscf, &name, &usn, data);

            if (rc != NGX_OK) {
                return rc;
            }
        }
    }

    return NGX_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
