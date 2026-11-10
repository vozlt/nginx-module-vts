# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The status code counters of the sum are in the request pool, so the control
# group walk must not use them after that request.
#
# glibc unmaps the 1m pool of the first request when that request ends, and
# the short code list keeps the counters in that pool. Thus a use after free
# stops the worker on a normal build also, not only under a sanitizer.

use Test::Nginx::Socket;

our @json = (
    'GET /status/format/json',
    'GET /status/control?cmd=status&group=server&zone=*',
);
our @prometheus = (
    'GET /status/format/prometheus',
    'GET /status/control?cmd=status&group=server&zone=*',
);
our @control = (
    'GET /status/control?cmd=status&group=*&zone=*',
    'GET /status/control?cmd=status&group=server&zone=*',
);

# Only the master process writes 'exited on signal'.
master_on();
repeat_each(1);
plan tests => 3 * (@json + @prometheus + @control);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: the control group walk after a json read of the status
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 404 500;
    request_pool_size 1m;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[@main::json]
--- error_code eval
[(200) x @main::json]
--- response_body_like eval
[
    qr/"serverZones":\{"\*":\{[^}]*"statusCodes":\{"other":0,"200":0,/,
    qr/\A\{"serverZones":\{"localhost":\{[^}]*"statusCodes":\{"other":0,"200":1,/,
]
--- no_error_log
exited on signal



=== TEST 2: the control group walk after a prometheus read of the status
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 404 500;
    request_pool_size 1m;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[@main::prometheus]
--- error_code eval
[(200) x @main::prometheus]
--- response_body_like eval
[
    qr/nginx_vts_status_code_requests_total\{host="\*",code="200"\} 0\n/,
    qr/\A\{"serverZones":\{"localhost":\{[^}]*"statusCodes":\{"other":0,"200":1,/,
]
--- no_error_log
exited on signal



=== TEST 3: the control group walk after cmd=status&group=*, with no display URI
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 404 500;
    request_pool_size 1m;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[@main::control]
--- error_code eval
[(200) x @main::control]
--- response_body_like eval
[
    qr/"serverZones":\{"\*":\{[^}]*"statusCodes":\{"other":0,"200":0,/,
    qr/\A\{"serverZones":\{"localhost":\{[^}]*"statusCodes":\{"other":0,"200":1,/,
]
--- no_error_log
exited on signal
