# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The $vts_* variables are read straight from the node of the server zone that
# handled the request. The only test that touched them went through
# ngx_http_lua_module (t/015), so a build without lua left
# ngx_http_vhost_traffic_status_variables.c almost entirely unexecuted - and
# the variables are meant to be used from an ordinary configuration, in
# add_header, log_format or proxy_set_header, with no lua anywhere.
#
# The cache variables are not used here on purpose: they are declared inside
# #if (NGX_HTTP_CACHE), so naming one would keep this file from starting on a
# build configured with --without-http-cache.

use Test::Nginx::Socket;

plan tests => repeat_each() * 24;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: nothing to read before the zone has a node, numbers after
--- http_config
    vhost_traffic_status_zone;
--- config
    location /v {
        add_header X-Req-Counter $vts_request_counter;
        add_header X-In-Bytes $vts_in_bytes;
        add_header X-Out-Bytes $vts_out_bytes;
        add_header X-2xx $vts_2xx_counter;
        return 200 "OK";
    }
--- request eval
['GET /v', 'GET /v', 'GET /v']
--- response_body_like eval
['OK', 'OK', 'OK']
--- raw_response_headers_like eval
[
    qr/\A(?!.*X-Req-Counter)/s,
    qr/X-Req-Counter: 1\b.*X-In-Bytes: [1-9]\d*.*X-Out-Bytes: [1-9]\d*.*X-2xx: 1\b/s,
    qr/X-Req-Counter: 2\b.*X-2xx: 2\b/s,
]

=== TEST 2: the request time is the average of the queue, and has its own counter
--- http_config
    vhost_traffic_status_zone;
--- config
    location /v {
        add_header X-Req-Time $vts_request_time;
        add_header X-Req-Time-Counter $vts_request_time_counter;
        add_header X-5xx $vts_5xx_counter;
        return 200 "OK";
    }
--- request eval
['GET /v', 'GET /v']
--- response_body_like eval
['OK', 'OK']
--- raw_response_headers_like eval
[
    qr/\A(?!.*X-Req-Time)/s,
    qr/X-Req-Time: \d+\b.*X-Req-Time-Counter: \d+\b.*X-5xx: 0\b/s,
]

=== TEST 3: each server zone is read from its own node
--- http_config
    vhost_traffic_status_zone;

    server {
        listen 1984;
        server_name vts-other;

        location /v {
            add_header X-Req-Counter $vts_request_counter;
            return 200 "other";
        }
    }
--- config
    location /v {
        add_header X-Req-Counter $vts_request_counter;
        return 200 "OK";
    }
--- request eval
[
    'GET /v',
    'GET /v',
    'GET /v',
]
--- more_headers eval
[
    '',
    "Host: vts-other\n",
    "Host: vts-other\n",
]
--- response_body_like eval
['OK', 'other', 'other']
--- raw_response_headers_like eval
[
    qr/\A(?!.*X-Req-Counter)/s,
    qr/\A(?!.*X-Req-Counter)/s,
    qr/X-Req-Counter: 1\b/,
]
