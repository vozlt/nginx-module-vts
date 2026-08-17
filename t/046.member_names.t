# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The names a member of a node can be asked for by. There are three
# vocabularies over one set of fields, and each of them is written out
# separately:
#
#   $vts_request_counter    the variables       (variables.c)
#   requestCounter          set_by_filter       (set.c)
#   request                 limit_traffic       (node.c, node_member)
#
# The suite reached 7 of the 18 variables, 7 of the 27 set_by_filter members
# and 3 of the 16 limit members, so most of these names could be dropped or
# misspelled without anything going red. This file names all of them that a
# build with no cache can name; the cache ones are in t/047.
#
# What each kind of assertion is worth:
#
#   variables      total. An unknown $vts_ name is a configuration error, so
#                  a dropped name stops nginx from starting and the whole
#                  file fails
#   set_by_filter  partial. An unknown member reads 0, which is also what an
#                  untouched counter reads, so only the members that can be
#                  made non-zero here are told apart from a dropped name
#   limit          partial, and for the same reason: an unknown member never
#                  reaches its limit, which is what an unused one does too
#
# set_by_filter and limit_traffic are ACCESS phase handlers, so a location
# that answers with `return` never reaches them. The locations that read a
# member serve a file instead.

use Test::Nginx::Socket;

plan tests => repeat_each() * 29;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: every variable of a build with no cache is a known name
--- http_config
    vhost_traffic_status_zone;
--- config
    location /v {
        add_header X-Request-Counter    $vts_request_counter;
        add_header X-In-Bytes           $vts_in_bytes;
        add_header X-Out-Bytes          $vts_out_bytes;
        add_header X-1xx                $vts_1xx_counter;
        add_header X-2xx                $vts_2xx_counter;
        add_header X-3xx                $vts_3xx_counter;
        add_header X-4xx                $vts_4xx_counter;
        add_header X-5xx                $vts_5xx_counter;
        add_header X-Request-Time-Ctr   $vts_request_time_counter;
        add_header X-Request-Time       $vts_request_time;
        return 200 "OK";
    }
--- request eval
['GET /v', 'GET /v']
--- response_body_like eval
['OK', 'OK']
--- raw_response_headers_like eval
[
    qr/\A(?!.*X-Request-Counter)/s,
    qr/X-Request-Counter: 1\b.*X-In-Bytes: [1-9]\d*.*X-Out-Bytes: [1-9]\d*.*X-1xx: 0\b.*X-2xx: 1\b.*X-3xx: 0\b.*X-4xx: 0\b.*X-5xx: 0\b.*X-Request-Time-Ctr: \d+\b.*X-Request-Time: \d+\b/s,
]

=== TEST 2: the set_by_filter members of a server zone
--- http_config
    vhost_traffic_status_zone;
--- config
    location /v {
        return 200 "OK";
    }

    location /three {
        return 301 "/v";
    }

    location /five {
        return 500 "no";
    }

    location /m.txt {
        vhost_traffic_status_set_by_filter $requestCounter     server/localhost/requestCounter;
        vhost_traffic_status_set_by_filter $requestMsecCounter server/localhost/requestMsecCounter;
        vhost_traffic_status_set_by_filter $requestMsec        server/localhost/requestMsec;
        vhost_traffic_status_set_by_filter $inBytes            server/localhost/inBytes;
        vhost_traffic_status_set_by_filter $outBytes           server/localhost/outBytes;
        vhost_traffic_status_set_by_filter $c1xx               server/localhost/1xx;
        vhost_traffic_status_set_by_filter $c2xx               server/localhost/2xx;
        vhost_traffic_status_set_by_filter $c3xx               server/localhost/3xx;
        vhost_traffic_status_set_by_filter $c4xx               server/localhost/4xx;
        vhost_traffic_status_set_by_filter $c5xx               server/localhost/5xx;

        add_header X-Request-Counter  $requestCounter;
        add_header X-Request-Msec-Ctr $requestMsecCounter;
        add_header X-Request-Msec     $requestMsec;
        add_header X-In-Bytes         $inBytes;
        add_header X-Out-Bytes        $outBytes;
        add_header X-1xx              $c1xx;
        add_header X-2xx              $c2xx;
        add_header X-3xx              $c3xx;
        add_header X-4xx              $c4xx;
        add_header X-5xx              $c5xx;
    }
--- user_files
>>> m.txt
read
--- request eval
['GET /v', 'GET /three', 'GET /missing', 'GET /five', 'GET /m.txt']
--- error_code eval
[200, 301, 404, 500, 200]
--- raw_response_headers_like eval
[
    qr/\A(?!.*X-Request-Counter)/s,
    qr/\A(?!.*X-Request-Counter)/s,
    qr/\A(?!.*X-Request-Counter)/s,
    qr/\A(?!.*X-Request-Counter)/s,
    qr/X-Request-Counter: [1-9]\d*.*X-Request-Msec-Ctr: \d+\b.*X-Request-Msec: \d+\b.*X-In-Bytes: [1-9]\d*.*X-Out-Bytes: [1-9]\d*.*X-1xx: 0\b.*X-2xx: [1-9]\d*.*X-3xx: [1-9]\d*.*X-4xx: [1-9]\d*.*X-5xx: [1-9]\d*/s,
]

=== TEST 3: the members an upstream peer answers for, which a server zone has no value for
--- http_config
    vhost_traffic_status_zone;

    upstream backend {
        server 127.0.0.1:1984 weight=5 max_fails=3 fail_timeout=20s;
    }

    server {
        listen 1984;
        location / {
            return 200 "up";
        }
    }
--- config
    location /p {
        proxy_pass http://backend;
    }

    location /m.txt {
        vhost_traffic_status_set_by_filter $weight      upstream@group/backend@127.0.0.1:1984/weight;
        vhost_traffic_status_set_by_filter $maxFails    upstream@group/backend@127.0.0.1:1984/maxFails;
        vhost_traffic_status_set_by_filter $failTimeout upstream@group/backend@127.0.0.1:1984/failTimeout;
        vhost_traffic_status_set_by_filter $down        upstream@group/backend@127.0.0.1:1984/down;
        vhost_traffic_status_set_by_filter $backup      upstream@group/backend@127.0.0.1:1984/backup;
        vhost_traffic_status_set_by_filter $respCtr     upstream@group/backend@127.0.0.1:1984/responseMsecCounter;
        vhost_traffic_status_set_by_filter $respMsec    upstream@group/backend@127.0.0.1:1984/responseMsec;

        add_header X-Weight       $weight;
        add_header X-Max-Fails    $maxFails;
        add_header X-Fail-Timeout $failTimeout;
        add_header X-Down         $down;
        add_header X-Backup       $backup;
        add_header X-Resp-Ctr     $respCtr;
        add_header X-Resp-Msec    $respMsec;
    }
--- user_files
>>> m.txt
read
--- request eval
['GET /p', 'GET /m.txt']
--- response_body_like eval
['up', 'read']
--- raw_response_headers_like eval
[
    qr/\A(?!.*X-Weight)/s,
    qr/X-Weight: 5\b.*X-Max-Fails: 3\b.*X-Fail-Timeout: 20\b.*X-Down: 0\b.*X-Resp-Ctr: \d+\b.*X-Resp-Msec: \d+\b/s,
]

=== TEST 4: the limit members a request of this shape can reach
--- http_config
    vhost_traffic_status_zone;
--- config
    location /r.txt {
        vhost_traffic_status_limit_traffic request:2;
    }

    location /i.txt {
        vhost_traffic_status_limit_traffic in:1;
    }

    location /o.txt {
        vhost_traffic_status_limit_traffic out:1;
    }

    location /s.txt {
        vhost_traffic_status_limit_traffic 2xx:2;
    }
--- user_files
>>> r.txt
r
>>> i.txt
i
>>> o.txt
o
>>> s.txt
s
--- request eval
['GET /r.txt', 'GET /r.txt', 'GET /r.txt', 'GET /r.txt', 'GET /i.txt', 'GET /o.txt', 'GET /s.txt']
--- error_code eval
[200, 200, 200, 503, 503, 503, 503]
