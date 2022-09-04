# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

add_response_body_check(
    sub {
        my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;
        system("echo '$body' | python -m json.tool > /dev/null") == 0 or
        bail_out "JSON Syntax error($body)";
    }
);

plan tests => repeat_each() * blocks() * 24;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: check_json_syntax
--- http_config
    vhost_traffic_status_zone;
    proxy_cache_path /tmp/cache_one levels=1:2 keys_zone=cache_one:2m inactive=1m max_size=4m;
    proxy_cache_path /tmp/cache_two levels=1:2 keys_zone=cache_two:2m inactive=1m max_size=4m;
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
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
    }
    location /alone {
        proxy_pass http://localhost:1981;
    }
    location /cache_one {
        proxy_cache cache_one;
        proxy_cache_valid 200 10s;
        proxy_set_header Host backend;
        proxy_pass http://backend;
    }
    location /cache_two {
        proxy_cache cache_two;
        proxy_cache_valid 200 10s;
        proxy_set_header Host backend;
        proxy_pass http://backend;
    }
--- tcp_listen: 1981
--- tcp_reply eval
"HTTP/1.1 200 OK\r\n\r\n{\"upstream\@alone\":\"OK\"}"
--- user_files eval
[
    ['one/file.txt' => '{"one.example.org":"OK"}'],
    ['two/file.txt' => '{"two.example.org":"OK"}'],
    ['storage/vol0/file.txt' => '{"vol0":"OK"}'],
    ['storage/vol1/file.txt' => '{"vol1":"OK"}'],
    ['cache_one/file.txt' => '{"cache_one":"OK"}'],
    ['cache_two/file.txt' => '{"cache_two":"OK"}']
]
--- request eval
[
    'GET /status/format/json',
    'GET /one/file.txt',
    'GET /two/file.txt',
    'GET /status/format/json',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol1/file.txt',
    'GET /status/format/json',
    'GET /alone/file.txt',
    'GET /status/format/json',
    'GET /cache_one/file.txt',
    'GET /cache_two/file.txt',
    'GET /status/format/json'
]
--- response_body_like eval
[
    'nginxVersion',
    'OK',
    'OK',
    '(one|two).example.org',
    'OK',
    'OK',
    'filterZones.*(vol0|vol1)',
    'OK',
    '::nogroups',
    'OK',
    'OK',
    'cacheZone'
]
