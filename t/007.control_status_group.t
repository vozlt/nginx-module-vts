# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 4 + 2;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: /status/control?cmd=status&group=server&zone=::main
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=status&group=server&zone=::main',
]
--- response_body_like eval
[
    'OK',
    'hostName'
]



=== TEST 2: /status/control?cmd=status&group=server&zone=*
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=status&group=server&zone=*',
]
--- response_body_like eval
[
    'OK',
    '{"serverZones.*localhost'
]



=== TEST 3: /status/control?cmd=status&group=filter&zone=*
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
    }
--- user_files eval
[
    ['storage/vol0/file.txt' => 'filter:OK']
]
--- request eval
[
    'GET /storage/vol0/file.txt',
    'GET /status/control?cmd=status&group=filter&zone=*',
]
--- response_body_like eval
[
    'OK',
    '{"filterZones.*storage::'
]



=== TEST 4: /status/control?cmd=status&group=upstream@group&zone=*
--- http_config
    vhost_traffic_status_zone;
    upstream backend {
        server localhost;
    }
    server {
        server_name backend;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /backend {
        proxy_set_header Host backend;
        proxy_pass http://backend;
    }
--- user_files eval
[
    ['backend/file.txt' => 'upstream@group:OK']
]
--- request eval
[
    'GET /backend/file.txt',
    'GET /status/control?cmd=status&group=upstream@group&zone=*',
]
--- response_body_like eval
[
    'OK',
    '{"upstreamZones.*backend'
]



=== TEST 5: /status/control?cmd=status&group=upstream@alone&zone=*
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /backend {
        proxy_set_header Host backend;
        proxy_pass http://localhost:1981;
    }
--- tcp_listen: 1981
--- tcp_reply eval
"HTTP/1.1 200 OK\r\n\r\nupstream\@alone:OK"
--- request eval
[
    'GET /backend/file.txt',
    'GET /status/control?cmd=status&group=upstream@alone&zone=*',
]
--- response_body_like eval
[
    'OK',
    '{"::nogroups"'
]



=== TEST 6: /status/control?cmd=status&group=cache&zone=*
--- http_config
    vhost_traffic_status_zone;
    proxy_cache_path /tmp/cache_one levels=1:2 keys_zone=cache_one:2m inactive=1m max_size=4m;
    proxy_cache_path /tmp/cache_two levels=1:2 keys_zone=cache_two:2m inactive=1m max_size=4m;
    upstream backend {
        server localhost;
    }
    server {
        server_name backend;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /one {
        proxy_cache cache_one;
        proxy_cache_valid 200 10s;
        proxy_set_header Host backend;
        proxy_pass http://backend;
    }
    location /two {
        proxy_cache cache_two;
        proxy_cache_valid 200 10s;
        proxy_set_header Host backend;
        proxy_pass http://backend;
    }
--- user_files eval
[
    ['one/file.txt' => 'cache_one:OK'],
    ['two/file.txt' => 'cache_two:OK']
]
--- request eval
[
    'GET /one/file.txt',
    'GET /two/file.txt',
    'GET /status/control?cmd=status&group=cache&zone=*'
]
--- response_body_like eval
[
    'OK',
    'OK',
    '{"cacheZones.*cache_(one|two)'
]

=== TEST 7: /status/control?cmd=status&group=upstream%40group&zone=%2A
--- http_config
    vhost_traffic_status_zone;
    upstream backend {
        server localhost;
    }
    server {
        server_name backend;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /backend {
        proxy_set_header Host backend;
        proxy_pass http://backend;
    }
--- user_files eval
[
    ['backend/file.txt' => 'upstream@group:OK']
]
--- request eval
[
    'GET /backend/file.txt',
    'GET /status/control?cmd=status&group=upstream%40group&zone=%2A',
]
--- response_body_like eval
[
    'OK',
    '{"upstreamZones.*backend'
]

=== TEST 8: /status/control?cmd=status&group=upstream%40group&zone=%2a
--- http_config
    vhost_traffic_status_zone;
    upstream backend {
        server localhost;
    }
    server {
        server_name backend;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /backend {
        proxy_set_header Host backend;
        proxy_pass http://backend;
    }
--- user_files eval
[
    ['backend/file.txt' => 'upstream@group:OK']
]
--- request eval
[
    'GET /backend/file.txt',
    'GET /status/control?cmd=status&group=upstream%40group&zone=%2a',
]
--- response_body_like eval
[
    'OK',
    '{"upstreamZones.*backend'
]

=== TEST 9: /status/control?cmd=status&group=server&zone=%3A%3Amain
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=status&group=server&zone=%3A%3Amain',
]
--- response_body_like eval
[
    'OK',
    'hostName'
]

