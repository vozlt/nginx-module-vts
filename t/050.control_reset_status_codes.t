# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# A reset clears every status code counter of the zones it resets, the last
# listed code included.

use Test::Nginx::Socket;

repeat_each(1);
plan tests => 12;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: resetting a zone clears every code it counted
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 404;
--- config
    location /notfound { return 404 "nope"; }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /notfound',
    'GET /status/control?cmd=reset&group=server&zone=localhost',
    'GET /status',
]
--- error_code eval
[404, 200, 200]
--- response_body_like eval
[
    qr/nope/,
    qr/"processingCounts":[1-9]/,
    qr/"localhost":\{[^}]*"statusCodes":\{"other":0,"200":1,"404":0\}/,
]



=== TEST 2: resetting every zone clears every code too
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 404;
--- config
    location /notfound { return 404 "nope"; }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /notfound',
    'GET /status/control?cmd=reset&group=*',
    'GET /status',
]
--- error_code eval
[404, 200, 200]
--- response_body_like eval
[
    qr/nope/,
    qr/"processingCounts":[1-9]/,
    qr/"localhost":\{[^}]*"statusCodes":\{"other":0,"200":1,"404":0\}/,
]
