# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 12;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: vhost_traffic_status_limit_traffic request:n 402
--- http_config
    vhost_traffic_status_zone;
--- config
    location ~ / {
        set $member request;
        vhost_traffic_status_limit_traffic $member:4 402;
    }
    error_page 402 /storage/limit/402.txt;
    location = /storage/limit/402.txt {
        internal;
    }
--- user_files eval
[
    ['storage/limit/file.txt' => 'server:OK'],
    ['storage/limit/402.txt' => 'limited:OK']
]
--- request eval
[
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt'
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



=== TEST 2: vhost_traffic_status_limit_traffic in:n
--- http_config
    vhost_traffic_status_zone;
--- config
    location ~ / {
        vhost_traffic_status_limit_traffic in:320;
    }
    error_page 503 /storage/limit/503.txt;
    location = /storage/limit/503.txt {
        internal;
    }
--- user_files eval
[
    ['storage/limit/file.txt' => 'server:OK'],
    ['storage/limit/503.txt' => 'limited:OK']
]
--- request eval
[
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt'
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



=== TEST 3: vhost_traffic_status_limit_traffic out:n
--- http_config
    vhost_traffic_status_zone;
--- config
    location ~ / {
        vhost_traffic_status_limit_traffic out:1024;
    }
    error_page 503 /storage/limit/503.txt;
    location = /storage/limit/503.txt {
        internal;
    }
--- user_files eval
[
    ['storage/limit/file.txt' => 'server:OK'],
    ['storage/limit/503.txt' => 'limited:OK']
]
--- request eval
[
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt'
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



=== TEST 4: vhost_traffic_status_limit off
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_limit off;
--- config
    location ~ / {
        set $member request;
        vhost_traffic_status_limit_traffic $member:4;
    }
    error_page 503 /storage/limit/503.txt;
    location = /storage/limit/503.txt {
        internal;
    }
--- user_files eval
[
    ['storage/limit/file.txt' => 'server:OK'],
    ['storage/limit/503.txt' => 'limited:OK']
]
--- request eval
[
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt'
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
