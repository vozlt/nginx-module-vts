# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# vhost_traffic_status_set_by_filter reads the tree of the shared memory, and
# now takes the mutex of the zone to do it, as every other reader does. A path
# that returned while holding it would wedge the worker, and the one no other
# test walks is a zone that has no node: the other tests all name a zone that
# is there.
#
# So ask for a peer the group never had, which finds no node, and then ask for
# something that needs the mutex again. The same worker serves both, so if the
# mutex were kept the second request would never answer. Removing the unlock
# on that path does make every request here time out.

use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks() * 6;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: a peer the group does not have leaves the zone usable
--- http_config
    vhost_traffic_status_zone;
    log_format basic 'requestCounter:$requestCounter';
    access_log logs/access.log basic;
    upstream backend {
        server 127.0.0.1:1984;
    }
--- config
    location /v {
        set $group upstream@group;
        set $zone backend@127.0.0.1:1;

        vhost_traffic_status_set_by_filter $requestCounter $group/$zone/requestCounter;

        proxy_pass http://backend/return;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        vhost_traffic_status_bypass_stats on;
    }
--- user_files eval
[
    ['return/file.txt' => '{"return":"OK"}']
]
--- request eval
[
    'GET /v/file.txt',
    'GET /v/file.txt',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'OK',
    'OK',
    qr/"hostName"/,
]
