# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# vhost_traffic_status_filter_max_node caps the nodes of the filter groups it
# names. The cap used to be consulted whenever any node was added, so an
# insertion it does not govern dropped a node that was inside it, with room
# left in the zone.
#
# TEST 1 adds a node of another kind: a set key with no group makes a server
# node rather than a filter one. TEST 2 adds a filter of a group the directive
# does not name. Neither may cost the capped group anything. TEST 3 is the
# insertion the cap does govern, which still has to drop the oldest.

use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks() * 8;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: a node of another kind does not drop one inside the cap
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_max_node 2 uris;
    vhost_traffic_status_filter_by_set_key $uri uris::;
    vhost_traffic_status_filter_by_set_key $request_method;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        vhost_traffic_status_bypass_stats on;
        vhost_traffic_status_bypass_limit on;
    }
    location /f {
        return 200 "ok\n";
    }
--- request eval
[
    'GET /f1',
    'GET /f2',
    'HEAD /f1',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'ok',
    'ok',
    '',
    qr/"\/f2"/,
]



=== TEST 2: nor does a filter of a group the cap does not name
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_max_node 2 uris;
    vhost_traffic_status_filter_by_set_key $uri uris::;
    vhost_traffic_status_filter_by_set_key $request_method method::;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        vhost_traffic_status_bypass_stats on;
        vhost_traffic_status_bypass_limit on;
    }
    location /f {
        return 200 "ok\n";
    }
--- request eval
[
    'GET /f1',
    'GET /f2',
    'HEAD /f1',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'ok',
    'ok',
    '',
    qr/"\/f2"/,
]



=== TEST 3: the cap still drops the oldest of the group it names
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_max_node 2 uris;
    vhost_traffic_status_filter_by_set_key $uri uris::;
    vhost_traffic_status_filter_by_set_key $request_method;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        vhost_traffic_status_bypass_stats on;
        vhost_traffic_status_bypass_limit on;
    }
    location /f {
        return 200 "ok\n";
    }
--- request eval
[
    'GET /f1',
    'GET /f2',
    'GET /f3',
    'GET /status/format/json',
]
--- response_body_unlike eval
[
    qr/never matches the body of a request/,
    qr/never matches the body of a request/,
    qr/never matches the body of a request/,
    qr/"\/f1"/,
]
