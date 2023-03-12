# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

master_on;
plan skip_all => 'nginx_upstream_check test skipped' unless $ENV{TEST_UPSTREAM_CHECK};
plan tests => 4;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: upstream peer->down is true
--- http_config
    vhost_traffic_status_zone;
    upstream backend {
        zone backend 64k;
        server localhost:8080;
        check interval=1000 rise=1 fall=1 timeout=1000;
    }
--- config
    location /backend {
        proxy_pass http://backend;
    }
    location /status {
        check_status;
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request
GET /status
--- response_body_like eval
'"down":true'

=== TEST 2: upstream peer->down is false
--- http_config
    vhost_traffic_status_zone;
    upstream backend {
        zone backend 64k;
        server localhost:8080;
        check interval=1000 rise=1 fall=1 timeout=1000;
    }
    server {
        listen 8080;
        server_name localhost;
        location / {
            root html;
        }
    }
--- config
    location /index.html {
        proxy_pass http://backend;
    }
    location /status {
        check_status;
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request
    GET /status
--- response_body_like eval
    '"down":false'
