# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# A node keeps counting by the status codes it was made with when a reload
# measures others, as it keeps the histogram buckets it was made with. The
# counters used to be indexed by the codes of the configuration in force, so
# a node made under a shorter list was counted past its end, into whatever
# the slab had put next to it - in practice the counters of another node.
#
# The blocks run in one nginx, reloaded with HUP in between, which keeps the
# zone. TEST 1 makes the nodes under one code, TEST 2 counts into one of them
# under four, TEST 3 reads them, as JSON and for Prometheus, under one other.

BEGIN {
    $ENV{TEST_NGINX_USE_HUP} = 1;
}

use Test::Nginx::Socket;

our @others = map { chr } ord('b') .. ord('h');

repeat_each(1);
plan tests => 9 + 2 * 4 + 2 * 2;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: nodes made while one code is measured
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200;
--- config
    location /k {
        vhost_traffic_status_filter_by_set_key $arg_k f::$server_name;
        if ($arg_s = 503) {
            return 503;
        }
        return 200 "ok";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[(map { "GET /k?k=$_" } 'a', @main::others), 'GET /status']
--- error_code eval
[(200) x 9]



=== TEST 2: a node counts what it does not measure as other, not past its end
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 200 404 500 503;
--- config
    location /k {
        vhost_traffic_status_filter_by_set_key $arg_k f::$server_name;
        if ($arg_s = 503) {
            return 503;
        }
        return 200 "ok";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /k?k=a&s=503', 'GET /k?k=a&s=503', 'GET /k?k=a&s=503', 'GET /status']
--- error_code eval
[503, 503, 503, 200]
--- response_body_like eval
[
    qr/503/, qr/503/, qr/503/,
    join('', '(?s)\\A',
        '(?=.*"a":\\{"requestCounter":4,[^{}]*"statusCodes":\\{"other":3,"200":1,"404":0,"500":0,"503":0\\})',
        map { qq/(?=.*"$_":\\{"requestCounter":1,[^{}]*"statusCodes":\\{"other":0,"200":1,"404":0,"500":0,"503":0\\})/ } @main::others),
]



=== TEST 3: a code no longer measured is shown as other
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_measure_status_codes 404;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /metrics {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
        access_log off;
    }
--- request eval
['GET /status', 'GET /metrics']
--- error_code eval
[200, 200]
--- response_body_like eval
[
    qr/"a":\{"requestCounter":4,[^{}]*"statusCodes":\{"other":4,"404":0\}/,
    # the server zone was made under 200, and has served 14 requests by now
    qr/(?s)\A(?!.*code="200")(?=.*host="localhost",code="other"\} 14\n)(?=.*host="localhost",code="404"\} 0\n)/,
]
