# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 4 + 2;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: /status/control?cmd=delete&group=server&zone=localhost
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
    'GET /status/control?cmd=delete&group=server&zone=localhost',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 2: /status/control?cmd=delete&group=filter&zone=storage::localhost@vol0
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
    'GET /status/control?cmd=delete&group=filter&zone=storage::localhost@vol0',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 3: /status/control?cmd=delete&group=upstream@group&zone=backend@127.0.0.1:80
--- http_config
    vhost_traffic_status_zone;
    upstream backend {
        server 127.0.0.1;
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
    'GET /status/control?cmd=delete&group=upstream@group&zone=backend@127.0.0.1:80',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 4: /status/control?cmd=delete&group=upstream@alone&zone=127.0.0.1:1981
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
        proxy_pass http://127.0.0.1:1981;
    }
--- tcp_listen: 1981
--- tcp_reply eval
"HTTP/1.1 200 OK\r\n\r\nupstream\@alone:OK"
--- request eval
[
    'GET /backend/file.txt',
    'GET /status/control?cmd=delete&group=upstream@alone&zone=127.0.0.1:1981',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 5: /status/control?cmd=delete&group=cache&zone=cache_one
--- http_config
    vhost_traffic_status_zone;
    proxy_cache_path /tmp/cache_one levels=1:2 keys_zone=cache_one:2m inactive=1m max_size=4m;
    proxy_cache_path /tmp/cache_two levels=1:2 keys_zone=cache_two:2m inactive=1m max_size=4m;
    upstream backend {
        server 127.0.0.1;
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
    'GET /status/control?cmd=delete&group=cache&zone=cache_one'
]
--- response_body_like eval
[
    'OK',
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 6: delete filter zone with space
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /test_space {
        set $vol "test value";
        vhost_traffic_status_filter_by_set_key $vol storage::$server_name;
        return 200 "filter:OK";
    }
--- request eval
[
    'GET /test_space',
    'GET /status/control?cmd=delete&group=filter&zone=storage::localhost@test%20value',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 7: delete filter zone with backtick
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /test_backtick {
        set $vol "test`value";
        vhost_traffic_status_filter_by_set_key $vol storage::$server_name;
        return 200 "filter:OK";
    }
--- request eval
[
    'GET /test_backtick',
    'GET /status/control?cmd=delete&group=filter&zone=storage::localhost@test%60value',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 8: delete filter zone with pipe
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /test_pipe {
        set $vol "test|value";
        vhost_traffic_status_filter_by_set_key $vol storage::$server_name;
        return 200 "filter:OK";
    }
--- request eval
[
    'GET /test_pipe',
    'GET /status/control?cmd=delete&group=filter&zone=storage::localhost@test%7Cvalue',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 9: delete filter zone with UTF-8 Chinese
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /test_utf8 {
        set $vol "商标";
        vhost_traffic_status_filter_by_set_key $vol storage::$server_name;
        return 200 "filter:OK";
    }
--- request eval
[
    'GET /test_utf8',
    'GET /status/control?cmd=delete&group=filter&zone=storage::localhost@%E5%95%86%E6%A0%87',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 10: plus stays plus in filter zone
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /test_plus {
        set $vol "test+value";
        vhost_traffic_status_filter_by_set_key $vol storage::$server_name;
        return 200 "filter:OK";
    }
--- request eval
[
    'GET /test_plus',
    'GET /status/control?cmd=delete&group=filter&zone=storage::localhost@test+value',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 11: encoded plus decodes to literal plus in filter zone
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /test_plus_encoded {
        set $vol "test+value";
        vhost_traffic_status_filter_by_set_key $vol storage::$server_name;
        return 200 "filter:OK";
    }
--- request eval
[
    'GET /test_plus_encoded',
    'GET /status/control?cmd=delete&group=filter&zone=storage::localhost@test%2Bvalue',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]



=== TEST 12: malformed percent encoding is left untouched
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /test_malformed_percent {
        set $vol "test%2Gvalue";
        vhost_traffic_status_filter_by_set_key $vol storage::$server_name;
        return 200 "filter:OK";
    }
--- request eval
[
    'GET /test_malformed_percent',
    'GET /status/control?cmd=delete&group=filter&zone=storage::localhost@test%2Gvalue',
]
--- response_body_like eval
[
    'OK',
    '"processingCounts":[1-9]'
]
