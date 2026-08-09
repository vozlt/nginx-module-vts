# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

# The scratch buffer the upstream display builds its keys in was sized for a
# peer name no longer than an address and a port, which a unix socket path
# passes easily. Nothing here shows on an ordinary build - the overflow lands
# in the slack of the pool block - so what these are for is the run under the
# sanitizers.
plan tests => repeat_each() * 10;
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
