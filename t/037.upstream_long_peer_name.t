# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

# The scratch buffer the upstream display builds its keys in was sized for a
# peer name no longer than an address and a port, which a unix socket path
# passes easily.
#
# It shows up twice over. Under the sanitizers the overflow itself is caught.
# On an ordinary build it is quieter and still wrong: node_generate_key()
# takes the key from the same pool with ngx_pcalloc, which zeroes a region
# overlapping the tail just written, so the name is cut short, the lookup
# misses, and the peer reads as though it had served nothing. That is what
# the requestCounter of TEST 2 and TEST 3 is for, and it fails without any
# sanitizer.
#
# The display reaches a peer by two paths and both had the fault, so both are
# here: an upstream with a zone goes through the round robin peers, one
# without goes through the servers of the group.
plan tests => repeat_each() * 16;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: an upstream over a unix socket whose path is longer than an address
--- http_config
    vhost_traffic_status_zone;

    upstream u {
        server unix:/tmp/vts-t037-a-deliberately-long-unix-domain-socket-path-for-the-upstream-key.sock;
    }

    server {
        listen unix:/tmp/vts-t037-a-deliberately-long-unix-domain-socket-path-for-the-upstream-key.sock;

        location / {
            return 200 "backend:OK";
        }
    }
--- config
    location /u {
        proxy_pass http://u;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /u',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'backend:OK',
    '"server":"unix:/tmp/vts-t037-a-deliberately-long-unix-domain-socket-path-for-the-upstream-key\.sock"'
]

=== TEST 2: the peer over the long path is counted like any other
--- http_config
    vhost_traffic_status_zone;

    upstream u {
        server unix:/tmp/vts-t037-a-deliberately-long-unix-domain-socket-path-for-the-upstream-key.sock;
    }

    server {
        listen unix:/tmp/vts-t037-a-deliberately-long-unix-domain-socket-path-for-the-upstream-key.sock;

        location / {
            return 200 "backend:OK";
        }
    }
--- config
    location /u {
        proxy_pass http://u;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /u',
    'GET /u',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'backend:OK',
    'backend:OK',
    '"upstreamZones":\{"u":\[\{"server":"unix:[^"]+","requestCounter":2'
]

=== TEST 3: the same over an upstream with a zone, which takes the other path
--- http_config
    vhost_traffic_status_zone;

    upstream u {
        zone u 1m;
        server unix:/tmp/vts-t037-a-deliberately-long-unix-domain-socket-path-for-the-upstream-key.sock;
    }

    server {
        listen unix:/tmp/vts-t037-a-deliberately-long-unix-domain-socket-path-for-the-upstream-key.sock;

        location / {
            return 200 "backend:OK";
        }
    }
--- config
    location /u {
        proxy_pass http://u;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /u',
    'GET /u',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'backend:OK',
    'backend:OK',
    '"upstreamZones":\{"u":\[\{"server":"unix:[^"]+","requestCounter":2'
]
