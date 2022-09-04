# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 11 + 2;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: vhost_traffic_status_limit_traffic_by_set_key FG@group@name request:n 402
--- http_config
    vhost_traffic_status_zone;
--- config
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        set $member request;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
        vhost_traffic_status_limit_traffic_by_set_key FG@storage::$server_name@$volume $member:4 402;
    }
    error_page 402 /storage/limit/402.txt;
    location = /storage/limit/402.txt {
        internal;
    }
--- user_files eval
[
    ['storage/vol0/file.txt' => 'vol0:OK'],
    ['storage/limit/402.txt' => 'limited:OK']
]
--- request eval
[
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
]
--- error_code eval
[
    200,
    200,
    200,
    200,
    200,
    402
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK',
    'OK',
    'OK',
    'OK'
]



=== TEST 2: vhost_traffic_status_limit_traffic_by_set_key FG@group@name in:n
--- http_config
    vhost_traffic_status_zone;
--- config
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
        vhost_traffic_status_limit_traffic_by_set_key FG@storage::$server_name@$volume in:300;
    }
    error_page 503 /storage/limit/503.txt;
    location = /storage/limit/503.txt {
        internal;
    }
--- user_files eval
[
    ['storage/vol0/file.txt' => 'vol0:OK'],
    ['storage/limit/503.txt' => 'limited:OK']
]
--- request eval
[
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
]
--- error_code eval
[
    200,
    200,
    200,
    200,
    200,
    503
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK',
    'OK',
    'OK',
    'OK'
]



=== TEST 3: vhost_traffic_status_limit_traffic_by_set_key FG@group@name out:n
--- http_config
    vhost_traffic_status_zone;
--- config
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
        vhost_traffic_status_limit_traffic_by_set_key FG@storage::$server_name@$volume out:1024;
    }
    error_page 503 /storage/limit/503.txt;
    location = /storage/limit/503.txt {
        internal;
    }
--- user_files eval
[
    ['storage/vol0/file.txt' => 'vol0:OK'],
    ['storage/limit/503.txt' => 'limited:OK']
]
--- request eval
[
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
    'GET /storage/vol0/file.txt',
]
--- error_code eval
[
    200,
    200,
    200,
    200,
    200,
    503
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK',
    'OK',
    'OK',
    'OK'
]



=== TEST 4: vhost_traffic_status_limit_traffic_by_set_key UG@group@name request:n
--- http_config
    vhost_traffic_status_zone;
    upstream backend {
        server 127.0.0.1;
    }
    server {
        server_name backend;
    }
--- config
    location /backend {
        vhost_traffic_status_limit_traffic_by_set_key UG@backend@127.0.0.1:80 request:3;
        proxy_set_header Host backend;
        proxy_pass http://backend;
    }
    error_page 503 /backend/limit/503.txt;
    location = /backend/limit/503.txt {
        internal;
    }
--- user_files eval
[
    ['backend/file.txt' => 'backend:OK'],
    ['backend/limit/503.txt' => 'limited:OK']
]
--- request eval
[
    'GET /backend/file.txt',
    'GET /backend/file.txt',
    'GET /backend/file.txt',
    'GET /backend/file.txt',
    'GET /backend/file.txt',
]
--- error_code eval
[
    200,
    200,
    200,
    200,
    503,
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK',
    'OK',
    'OK',
]
