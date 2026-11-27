# vi:set ft=perl ts=4 sw=4 et fdm=marker:
#
# The bytes nginx reads from and writes to each upstream server, the values
# $upstream_bytes_received and $upstream_bytes_sent log. They are counted per
# attempt, so a peer that proxy_next_upstream passed on keeps the bytes its
# attempt moved, which the client-side inBytes/outBytes of that peer cannot
# show - those describe the client request, and a passed-on attempt served
# none.

use Test::Nginx::Socket;

plan tests => repeat_each() * 30;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: the bytes of an answered attempt are counted
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1985;

        location / {
            return 200 "0123456789abcdef";
        }
    }

    upstream backend {
        server 127.0.0.1:1985;
    }
--- config
    location /up {
        proxy_pass http://backend/;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /up', 'GET /up', 'GET /status/format/json']
--- response_body_like eval
[
    qr/\A0123456789abcdef\z/,
    qr/\A0123456789abcdef\z/,

    # receivedBytes carries the response headers too, so two attempts of a
    # 16-byte body cross well over 100 bytes in; the three digits keep a
    # plain 0 or a leftover 1 from a single truncated attempt from passing
    qr/"server":"127\.0\.0\.1:1985",(?:(?!"server":).)*?"receivedBytes":[1-9]\d{2,},"sentBytes":[1-9]\d*,"weight"/s,
]

=== TEST 2: a passed-on attempt keeps the bytes it moved
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1985;

        location / {
            return 200 "ok";
        }
    }

    server {
        listen 1986;

        location / {
            return 502 "bad";
        }
    }

    upstream backend {
        server 127.0.0.1:1986 max_fails=0;
        server 127.0.0.1:1985 backup;
    }
--- config
    location /up {
        proxy_next_upstream error timeout http_502;
        proxy_pass http://backend/;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /up', 'GET /up', 'GET /status/format/json']
--- response_body_like eval
[
    qr/\Aok\z/,
    qr/\Aok\z/,
    qr/(?=.*"server":"127\.0\.0\.1:1986",(?:(?!"server":).)*?"receivedBytes":[1-9]\d*,"sentBytes":[1-9]\d*,"weight")(?=.*"server":"127\.0\.0\.1:1985",(?:(?!"server":).)*?"receivedBytes":[1-9]\d*,"sentBytes":[1-9]\d*,"weight")/s,
]

# The 502 peer has outBytes 0, since it served no client request, so only the
# peer counters can say that its attempt crossed the network at all.
#
# The patterns stop at the next "server" key, so a value is read from the
# entry of the peer it names, and end at "weight", so it is the counter
# itself and not the one of the same name in overCounts, which is 0.

=== TEST 3: a refused attempt counts no bytes on the peer it was tried on
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1985;

        location / {
            return 200 "ok";
        }
    }

    upstream backend {
        server 127.0.0.1:1981 max_fails=0;
        server 127.0.0.1:1985 backup;
    }
--- config
    location /up {
        proxy_next_upstream error timeout;
        proxy_pass http://backend/;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /up', 'GET /up', 'GET /status/format/json']
--- response_body_like eval
[
    qr/\Aok\z/,
    qr/\Aok\z/,
    qr/(?=.*"server":"127\.0\.0\.1:1981",(?:(?!"server":).)*?"receivedBytes":0,"sentBytes":0,"weight")(?=.*"server":"127\.0\.0\.1:1985",(?:(?!"server":).)*?"receivedBytes":[1-9]\d*,"sentBytes":[1-9]\d*,"weight")/s,
]

=== TEST 4: prometheus names the counters per peer and direction
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1985;

        location / {
            return 200 "0123456789abcdef";
        }
    }

    upstream backend {
        server 127.0.0.1:1985;
    }
--- config
    location /up {
        proxy_pass http://backend/;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
        access_log off;
    }
--- request eval
['GET /up', 'GET /up', 'GET /status/format/prometheus']
--- response_body_like eval
[
    qr/\A0123456789abcdef\z/,
    qr/\A0123456789abcdef\z/,
    qr/(?=.*nginx_vts_upstream_peer_bytes_total\{upstream="backend",backend="127\.0\.0\.1:1985",direction="received"\} [1-9]\d*)(?=.*nginx_vts_upstream_peer_bytes_total\{upstream="backend",backend="127\.0\.0\.1:1985",direction="sent"\} [1-9]\d*)/s,
]

=== TEST 5: a reset zeroes the counters again
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1985;

        location / {
            return 200 "0123456789abcdef";
        }
    }

    upstream backend {
        server 127.0.0.1:1985;
    }
--- config
    location /up {
        proxy_pass http://backend/;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /up',
    'GET /status/control?cmd=reset&group=upstream@group&zone=*',
    'GET /status/format/json',
]
--- response_body_like eval
[
    qr/\A0123456789abcdef\z/,
    qr/"processingCounts":[1-9]/,
    qr/"server":"127\.0\.0\.1:1985",(?:(?!"server":).)*?"receivedBytes":0,"sentBytes":0,"weight"/s,
]
