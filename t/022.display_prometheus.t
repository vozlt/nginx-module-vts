# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

add_response_body_check(
    sub {
        my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;
        system("echo '$body' | promtool check metrics") == 0 or
        bail_out "prometheus Syntax error($body)";
    }
);

plan tests => repeat_each(2) * blocks() * 3;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: /status/format/prometheus
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
    }
--- request
GET /status/format/prometheus
--- response_headers_like
Content-Type: text/plain
--- response_body_like eval
[
    'nginx_vts_info',
]



=== TEST 2: /status
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
    }
--- request
GET /status
--- response_headers_like
Content-Type: text/plain
--- response_body_like eval
[
    'nginx_vts_info',
]
