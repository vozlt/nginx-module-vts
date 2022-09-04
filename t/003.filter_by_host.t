# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 8;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: vhost_traffic_status_filter_by_host on
--- http_config
    vhost_traffic_status_zone;
    upstream backend {
        server 127.0.0.1;
    }
    server {
        server_name _;
        vhost_traffic_status_filter_by_host on;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /one {
        proxy_set_header Host one.example.org;
        proxy_pass http://backend;
    }
    location /two {
        proxy_set_header Host two.example.org;
        proxy_pass http://backend;
    }
--- user_files eval
[
    ['one/file.txt' => 'one.example.org:OK'],
    ['two/file.txt' => 'two.example.org:OK']
]
--- request eval
[
    'GET /one/file.txt',
    'GET /two/file.txt',
    'GET /status/control?cmd=status&group=server&zone=one.example.org',
    'GET /status/control?cmd=status&group=server&zone=two.example.org'
]
--- response_body_like eval
[
    'OK',
    'OK',
    'one.example.org',
    'two.example.org'
]



=== TEST 2: vhost_traffic_status_filter off
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter off;
    upstream backend {
        server 127.0.0.1;
    }
    server {
        server_name _;
        vhost_traffic_status_filter_by_host on;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /one {
        proxy_set_header Host one.example.org;
        proxy_pass http://backend;
    }
    location /two {
        proxy_set_header Host two.example.org;
        proxy_pass http://backend;
    }
--- user_files eval
[
    ['one/file.txt' => 'one.example.org:OK'],
    ['two/file.txt' => 'two.example.org:OK']
]
--- request eval
[
    'GET /one/file.txt',
    'GET /two/file.txt',
    'GET /status/control?cmd=status&group=server&zone=one.example.org',
    'GET /status/control?cmd=status&group=server&zone=two.example.org'
]
--- response_body_like eval
[
    'OK',
    'OK',
    '{}',
    '{}'
]
