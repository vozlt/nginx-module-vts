# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 12;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: limit_check_duplicate on
--- http_config
    vhost_traffic_status_zone;
--- config
    error_page 503 /storage/limit/503.txt;
    location = /storage/limit/503.txt {
        internal;
    }
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        vhost_traffic_status_limit_check_duplicate on;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
        vhost_traffic_status_limit_traffic_by_set_key FG@storage::$server_name@$volume request:8;
        vhost_traffic_status_limit_traffic_by_set_key FG@storage::$server_name@$volume request:4;
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
    'GET /storage/vol0/file.txt'
]
--- error_code eval
[
    200,
    200,
    200,
    200,
    200,
    200
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



=== TEST 2: limit_check_duplicate off
--- http_config
    vhost_traffic_status_zone;
--- config
    error_page 503 /storage/limit/503.txt;
    location = /storage/limit/503.txt {
        internal;
    }
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        vhost_traffic_status_limit_check_duplicate off;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
        vhost_traffic_status_limit_traffic_by_set_key FG@storage::$server_name@$volume request:8;
        vhost_traffic_status_limit_traffic_by_set_key FG@storage::$server_name@$volume request:4;
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
    'GET /storage/vol0/file.txt'
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
