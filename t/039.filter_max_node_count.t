# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# vhost_traffic_status_filter_max_node knows how many nodes of the groups it
# names are in the tree by walking the whole tree, on every insertion, before
# it has even compared against the cap. Keeping a count instead removes that
# walk, and these are what say the count is right.
#
# They pass on master, which counts by walking and so cannot be wrong. What
# they are for is the change that stops walking: a count that is not lowered
# when nodes are deleted leaves the cap thinking the zone is still full, and
# the eviction starts dropping what it should keep.

use Test::Nginx::Socket;

plan tests => repeat_each() * 84;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: the cap keeps the newest of the group it names
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_max_node 3 g::;
--- config
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /f?k=k1',
    'GET /f?k=k2',
    'GET /f?k=k3',
    'GET /f?k=k4',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'filter:OK',
    'filter:OK',
    'filter:OK',
    'filter:OK',
    qr/\A(?=.*"k4":\{)(?!.*"k1":\{)/s,
]

=== TEST 2: what the eviction took is given back with the rest
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_max_node 3 g::;
--- config
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /f?k=k1',
    'GET /f?k=k2',
    'GET /f?k=k3',
    'GET /f?k=k4',
    'GET /f?k=k5',
    'GET /status/control?cmd=delete&group=filter&zone=*',
    'GET /f?k=k6',
    'GET /f?k=k7',
    'GET /f?k=k8',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'filter:OK',
    'filter:OK',
    'filter:OK',
    'filter:OK',
    'filter:OK',
    qr/"processingCounts":3/,
    'filter:OK',
    'filter:OK',
    'filter:OK',
    qr/\A(?=.*"k6":\{)(?=.*"k7":\{)(?=.*"k8":\{)/s,
]

=== TEST 3: a group the cap does not name is not counted against it
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_max_node 2 g::;
--- config
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
    location /o {
        vhost_traffic_status_filter_by_set_key $arg_k other::$server_name;
        return 200 "other:OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /o?k=x1',
    'GET /o?k=x2',
    'GET /o?k=x3',
    'GET /f?k=k1',
    'GET /f?k=k2',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'other:OK',
    'other:OK',
    'other:OK',
    'filter:OK',
    'filter:OK',
    qr/\A(?=.*"x1":\{)(?=.*"x2":\{)(?=.*"x3":\{)(?=.*"k1":\{)(?=.*"k2":\{)/s,
]

=== TEST 4: a named zone an expire does not take is still counted
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_max_node 3 g::;
--- config
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /f?k=k1',
    'GET /f?k=k2',
    'GET /f?k=k3',
    "GET /status/control?cmd=delete&group=filter&zone=g::localhost\@k1&expire=1h",
    'GET /f?k=k4',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'filter:OK',
    'filter:OK',
    'filter:OK',
    qr/"processingCounts":0/,
    'filter:OK',
    qr/\A(?=.*"k4":\{)(?=.*"k3":\{)(?!.*"k1":\{)/s,
]

=== TEST 5: deleting every kind gives the cap its room back too
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_max_node 3 g::;
--- config
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /f?k=k1',
    'GET /f?k=k2',
    'GET /f?k=k3',
    'GET /status/control?cmd=delete&group=*',
    'GET /f?k=k4',
    'GET /f?k=k5',
    'GET /f?k=k6',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'filter:OK',
    'filter:OK',
    'filter:OK',
    qr/"processingReturn":true/,
    'filter:OK',
    'filter:OK',
    'filter:OK',
    qr/\A(?=.*"k4":\{)(?=.*"k5":\{)(?=.*"k6":\{)/s,
]

=== TEST 6: a named zone that is taken gives its place back
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_max_node 3 g::;
--- config
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /f?k=k1',
    'GET /f?k=k2',
    'GET /f?k=k3',
    "GET /status/control?cmd=delete&group=filter&zone=g::localhost\@k1",
    'GET /f?k=k4',
    'GET /f?k=k5',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'filter:OK',
    'filter:OK',
    'filter:OK',
    qr/"processingCounts":1/,
    'filter:OK',
    'filter:OK',
    qr/\A(?=.*"k3":\{)(?=.*"k4":\{)(?=.*"k5":\{)/s,
]
