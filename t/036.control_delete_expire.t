# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

# Two checks per request, and the blocks do not hold the same number of
# them, so the total is spelled out rather than derived from blocks().
plan tests => repeat_each() * 42;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: expire drops the node that has aged and keeps the recent one
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
    # only here to spend time between the two nodes above; it carries no
    # filter of its own
    location /slow {
        proxy_pass http://127.0.0.1:1981;
    }
--- request eval
[
    'GET /f?k=stale',
    'GET /slow',
    'GET /f?k=fresh',
    "GET /status/control?cmd=delete&group=filter&zone=*&expire=1",
    'GET /status/format/json',
]
--- tcp_listen: 1981
--- tcp_reply_delay: 2s
--- tcp_reply eval
"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nslow:OK\n"
--- response_body_like eval
[
    'filter:OK',
    'slow:OK',
    'filter:OK',
    '"processingCounts":1',
    '"fresh"'
]

=== TEST 2: the node that aged is the one that went
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
    location /slow {
        proxy_pass http://127.0.0.1:1981;
    }
--- request eval
[
    'GET /f?k=stale',
    'GET /slow',
    'GET /f?k=fresh',
    "GET /status/control?cmd=delete&group=filter&zone=*&expire=1",
    'GET /status/format/json',
]
--- tcp_listen: 1981
--- tcp_reply_delay: 2s
--- tcp_reply eval
"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nslow:OK\n"
--- response_body_unlike eval
[
    'nothing',
    'nothing',
    'nothing',
    'nothing',
    '"stale"'
]

=== TEST 3: an expire nothing has reached removes nothing
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
--- request eval
[
    'GET /f?k=one',
    'GET /f?k=two',
    "GET /status/control?cmd=delete&group=filter&zone=*&expire=3600",
    'GET /status/format/json',
]
--- response_body_like eval
[
    'filter:OK',
    'filter:OK',
    '"processingCounts":0',
    '"one"'
]

=== TEST 4: without expire the whole group still goes
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
--- request eval
[
    'GET /f?k=one',
    'GET /f?k=two',
    "GET /status/control?cmd=delete&group=filter&zone=*",
    'GET /status/format/json',
]
--- response_body_like eval
[
    'filter:OK',
    'filter:OK',
    '"processingCounts":2',
    '"usedNode":1'
]

=== TEST 5: group=* with expire keeps what has not aged
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /f {
        vhost_traffic_status_filter_by_set_key $arg_k g::$server_name;
        return 200 "filter:OK";
    }
--- request eval
[
    'GET /f?k=one',
    "GET /status/control?cmd=delete&group=*&zone=*&expire=3600",
    'GET /status/format/json',
]
--- response_body_like eval
[
    'filter:OK',
    '"processingCounts":0',
    '"one"'
]
