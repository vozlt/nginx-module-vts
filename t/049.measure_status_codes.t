# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# vhost_traffic_status_measure_status_codes: per-code request counters on
# every server zone, shown as "statusCodes" in JSON and as
# nginx_vts_status_code_requests_total in Prometheus. A status that is not
# measured is counted as "other". A listed code is shown even at zero; under
# "all" only the codes that occurred are.

use Test::Nginx::Socket;

repeat_each(1);
plan tests => 50;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: listed codes are counted, and the rest goes to other
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 404;
--- config
    location /ok       { return 200 "ok"; }
    location /notfound { return 404 "nope"; }
    location /broken   { return 500 "broken"; }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /ok', 'GET /notfound', 'GET /broken', 'GET /status']
--- error_code eval
[200, 200, 404, 500, 200]
--- response_body_like eval
[
    qr/\Aok\z/,
    qr/\Aok\z/,
    qr/nope/,
    qr/broken/,
    qr/"localhost":\{[^}]*"statusCodes":\{"other":1,"200":2,"404":1\}/,
]



=== TEST 2: a listed code that never occurred still reads zero
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 503;
--- config
    location /ok { return 200 "ok"; }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /status']
--- response_body_like eval
[
    qr/\Aok\z/,
    qr/"localhost":\{[^}]*"statusCodes":\{"other":0,"200":1,"503":0\}/,
]



=== TEST 3: all shows the codes that occurred, and only those
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes all;
--- config
    location /ok     { return 200 "ok"; }
    location /teapot { return 418 "teapot"; }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /teapot', 'GET /status']
--- error_code eval
[200, 418, 200]
--- response_body_like eval
[
    qr/\Aok\z/,
    qr/teapot/,
    qr/"localhost":\{[^}]*"statusCodes":\{"other":0,"200":1,"418":1\}/,
]



=== TEST 4: the sum zone adds up the codes of every zone
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 204;
    server {
        listen 1985;
        server_name other;
        location / { return 204; }
    }
--- config
    location /ok    { return 200 "ok"; }
    location /proxy { proxy_pass http://127.0.0.1:1985/; }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /proxy', 'GET /status']
--- error_code eval
[200, 204, 200]
--- response_body_like eval
[
    qr/\Aok\z/,
    qr/\A\z/,
    qr/"other":\{[^}]*"statusCodes":\{"other":0,"200":0,"204":1\}(?s:.*)"\*":\{[^}]*"statusCodes":\{"other":0,"200":1,"204":2\}/,
]



=== TEST 5: the codes in Prometheus
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 404;
--- config
    location /ok       { return 200 "ok"; }
    location /notfound { return 404 "nope"; }
    location /broken   { return 500 "broken"; }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /notfound', 'GET /broken', 'GET /status']
--- error_code eval
[200, 404, 500, 200]
--- response_body_like eval
[
    qr/\Aok\z/,
    qr/nope/,
    qr/broken/,
    qr/nginx_vts_status_code_requests_total\{host="localhost",code="other"\} 1\nnginx_vts_status_code_requests_total\{host="localhost",code="200"\} 1\nnginx_vts_status_code_requests_total\{host="localhost",code="404"\} 1\n/,
]



=== TEST 6: without the directive there are no codes
--- http_config
    vhost_traffic_status_zone;
--- config
    location /ok { return 200 "ok"; }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /status']
--- response_body_unlike eval
[
    qr/statusCodes/,
    qr/statusCodes/,
]



=== TEST 7: without the directive there are no codes in Prometheus
--- http_config
    vhost_traffic_status_zone;
--- config
    location /ok { return 200 "ok"; }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /status']
--- response_body_unlike eval
[
    qr/nginx_vts_status_code_requests_total\{/,
    qr/nginx_vts_status_code_requests_total\{/,
]



=== TEST 8: a code above 599 is refused
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 600;
--- config
--- must_die
--- error_log
invalid status_code "600"



=== TEST 9: a code below 100 is refused
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 99 200;
--- config
--- must_die
--- error_log
invalid status_code "99"



=== TEST 10: codes out of order are refused
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 404 200;
--- config
--- must_die
--- error_log
status codes must be ordered



=== TEST 11: a word that is not a code is refused
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 4xx;
--- config
--- must_die
--- error_log
invalid parameter "4xx"
