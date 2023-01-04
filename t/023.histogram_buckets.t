# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;
use Fcntl;

plan tests => repeat_each() * blocks() * 4;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: access status with vhost_traffic_status_histogram_bucket to get the request and responseBuckets after accessing upstream backend
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_histogram_buckets .1 .5 1 2;
    upstream backend {
	    server 127.0.0.1;
    }
    server {
        server_name _;
        vhost_traffic_status_filter_by_host on;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /one {
        proxy_set_header Host one.example.org;
        proxy_pass http://backend;
    }
--- user_files eval
[
    ['one/file.txt' => 'one.example.org:OK'],
]
--- request eval
[
    'GET /one/file.txt',
    'GET /status/',
]
--- response_body_like eval
[
    'OK',
    '\"requestBuckets\"\:\{\"msecs\"\:\[100,500,1000,2000\],\"counters\"\:\[1,1,1,1\].*\"responseBuckets\"\:\{\"msecs\"\:\[100,500,1000,2000\],\"counters\"\:\[1,1,1,1\]',
]
