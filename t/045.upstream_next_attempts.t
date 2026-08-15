# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# shm_add_upstream() recorded u->state, the state of the last attempt, so a
# request that proxy_next_upstream passed on recorded nothing at all against
# the peer it was passed on from - the peer an operator looks for first (#388).
#
# The upstream here has a primary with nothing listening on it and a backup
# that answers, which makes the order of the attempts the same for every
# request: the primary is refused, the backup serves. max_fails=0 keeps the
# primary in play rather than having it marked down after the first failure.
#
# What each peer is expected to hold:
#
#   primary   requestCounter and 5xx, no bytes, since it served no client
#   backup    requestCounter and 2xx and the bytes, as before this change

use Test::Nginx::Socket;

plan tests => repeat_each() * 26;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: the peer that was passed on is counted at all
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1985;

        location / {
            return 200 "backup";
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
    qr/\Abackup\z/,
    qr/\Abackup\z/,
    qr/"server":"127\.0\.0\.1:1981","requestCounter":2/,
]

# The entry itself is written whether or not anything was counted, the display
# enumerating the servers of the group, so asserting that the address appears
# would pass on master as well. The counter is what says the attempt was seen.

=== TEST 2: it holds the status of its own attempt, not the client's
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1985;

        location / {
            return 200 "backup";
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
    qr/\Abackup\z/,
    qr/\Abackup\z/,
    qr/"server":"127\.0\.0\.1:1981","requestCounter":2,"inBytes":0,"outBytes":0,"responses":\{"1xx":0,"2xx":0,"3xx":0,"4xx":0,"5xx":2\}/,
]

=== TEST 3: the peer that answered is counted as it always was
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1985;

        location / {
            return 200 "backup";
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
    qr/\Abackup\z/,
    qr/\Abackup\z/,
    qr/"server":"127\.0\.0\.1:1985","requestCounter":2,"inBytes":[1-9]\d*,"outBytes":[1-9]\d*,"responses":\{"1xx":0,"2xx":2,"3xx":0,"4xx":0,"5xx":0\}/,
]

=== TEST 4: a request that needs no second attempt is unchanged
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1985;

        location / {
            return 200 "only";
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
    qr/\Aonly\z/,
    qr/\Aonly\z/,
    qr/"server":"127\.0\.0\.1:1985","requestCounter":2,"inBytes":[1-9]\d*,"outBytes":[1-9]\d*,"responses":\{"1xx":0,"2xx":2,"3xx":0,"4xx":0,"5xx":0\}/,
]

=== TEST 5: an internal redirect to another upstream keeps its peers apart
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1985;

        location / {
            return 200 "fallback";
        }
    }

    upstream first {
        server 127.0.0.1:1981;
    }

    upstream second {
        server 127.0.0.1:1985;
    }
--- config
    location /up {
        proxy_intercept_errors on;
        error_page 502 = @fb;
        proxy_pass http://first/;
    }
    location @fb {
        proxy_pass http://second;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /up', 'GET /status/format/json']
--- response_body_like eval
[
    qr/\Afallback\z/,
    qr/"second":\[\{"server":"127\.0\.0\.1:1985"[^\]]*\}\]/,
]

# r->upstream_states is request-wide. Where an internal redirect starts a
# second upstream, nginx keeps the states of the first and pushes a zeroed one
# between them, so a walk from index 0 files the peers of `first` under
# `second` - the group the current request ended up in. The assertion is that
# the array for `second` holds one entry and it is its own server.
