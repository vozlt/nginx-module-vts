# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# Every peer of an upstream group has to show up in upstreamZones, whether it
# has served a request or not. A peer that is only listed once it has traffic
# hides the backends of a freshly started or freshly resolved upstream.

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 4;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: every peer of a zone upstream is listed without traffic
--- http_config
    vhost_traffic_status_zone;

    upstream backend {
        zone backend 1m;
        server 127.0.0.1:1984;
        server 127.0.0.1:1985 down;
    }
--- config
    location /ok {
        return 200 "OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /status/format/json']
--- response_body_like eval
['OK', qr/"upstreamZones".*"127\.0\.0\.1:1984".*"127\.0\.0\.1:1985"/s]



=== TEST 2: every peer is still listed once one of them has traffic
--- http_config
    vhost_traffic_status_zone;

    upstream backend {
        zone backend 1m;
        server 127.0.0.1:1984;
        server 127.0.0.1:1985 down;
    }
--- config
    location /ok {
        return 200 "OK";
    }
    location /up {
        proxy_pass http://backend/ok;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /up', 'GET /status/format/json']
--- response_body_like eval
['OK', qr/"upstreamZones".*"127\.0\.0\.1:1984".*"127\.0\.0\.1:1985"/s]



=== TEST 3: an upstream that resolves the names at run time is displayed
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:65353 valid=1s ipv6=off;

    upstream backend {
        zone backend 1m;
        server 127.0.0.1:1984;
        server vts-test.invalid:1985 resolve;
    }
--- config
    location /ok {
        return 200 "OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /status/format/json']
--- response_body_like eval
['OK', qr/"upstreamZones".*"127\.0\.0\.1:1984"/s]
