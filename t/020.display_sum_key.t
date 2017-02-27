# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 2;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: display_sum_key total
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_sum_key total;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /status/format/json',
]
--- response_body_like eval
[
    'total',
]
