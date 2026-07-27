# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The names of the nodes come from the request (Host header, the variables of
# vhost_traffic_status_filter_by_set_key, ...) and are not length limited, so
# the display buffer has to be sized from the keys that are actually stored.
# These tests feed oversized and hostile names and ask for every output format.
# They are most useful when nginx is built with -fsanitize=address.

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 4;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: long filter name, prometheus
--- http_config
    large_client_header_buffers 4 16k;
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
        access_log off;
    }
    location /probe {
        vhost_traffic_status_filter_by_set_key $http_user_agent ua::$server_name;
        return 200 "OK";
    }
--- more_headers eval
"User-Agent: " . ("A" x 8000)
--- request eval
['GET /probe', 'GET /status/format/prometheus']
--- response_body_like eval
['OK', 'nginx_vts_filter_bytes_total']



=== TEST 2: long filter name, json
--- http_config
    large_client_header_buffers 4 16k;
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /probe {
        vhost_traffic_status_filter_by_set_key $http_user_agent ua::$server_name;
        return 200 "OK";
    }
--- more_headers eval
"User-Agent: " . ("A" x 8000)
--- request eval
['GET /probe', 'GET /status/format/json']
--- response_body_like eval
['OK', 'filterZones']



=== TEST 3: invalid utf-8 filter name, prometheus
--- http_config
    large_client_header_buffers 4 16k;
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
        access_log off;
    }
    location /probe {
        vhost_traffic_status_filter_by_set_key $http_user_agent ua::$server_name;
        return 200 "OK";
    }
--- more_headers eval
"User-Agent: " . ("\xff" x 4000)
--- request eval
['GET /probe', 'GET /status/format/prometheus']
--- response_body_like eval
['OK', 'nginx_vts_filter_bytes_total']



=== TEST 4: control characters in filter name, json
--- http_config
    large_client_header_buffers 4 16k;
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /probe {
        vhost_traffic_status_filter_by_set_key $http_user_agent ua::$server_name;
        return 200 "OK";
    }
--- more_headers eval
"User-Agent: " . ("\x01" x 4000)
--- request eval
['GET /probe', 'GET /status/format/json']
--- response_body_like eval
['OK', 'filterZones']



=== TEST 5: several long names at once, prometheus
--- http_config
    large_client_header_buffers 4 16k;
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
        access_log off;
    }
    location /probe {
        vhost_traffic_status_filter_by_set_key $http_user_agent ua::$server_name;
        vhost_traffic_status_filter_by_set_key $http_x_test xt::$server_name;
        return 200 "OK";
    }
--- more_headers eval
"User-Agent: " . ("A" x 6000) . "\nX-Test: " . ("B" x 6000)
--- request eval
['GET /probe', 'GET /status/format/prometheus']
--- response_body_like eval
['OK', 'nginx_vts_filter_bytes_total']



=== TEST 6: long name with histogram and status codes, prometheus
--- http_config
    large_client_header_buffers 4 16k;
    vhost_traffic_status_zone;
    vhost_traffic_status_histogram_buckets 0.005 0.01 0.05 0.1 0.5 1 5 10;
    vhost_traffic_status_measure_status_codes 200 404 500;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
        access_log off;
    }
    location /probe {
        vhost_traffic_status_filter_by_set_key $http_user_agent ua::$server_name;
        return 200 "OK";
    }
--- more_headers eval
"User-Agent: " . ("A" x 8000)
--- request eval
['GET /probe', 'GET /status/format/prometheus']
--- response_body_like eval
['OK', 'nginx_vts_filter_bytes_total']



=== TEST 7: long name through the control handler
--- http_config
    large_client_header_buffers 4 16k;
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /probe {
        vhost_traffic_status_filter_by_set_key $http_user_agent ua::$server_name;
        return 200 "OK";
    }
--- more_headers eval
"User-Agent: " . ("A" x 8000)
--- request eval
['GET /probe', 'GET /status/control?cmd=status&group=filter&zone=*']
--- response_body_like eval
['OK', 'filterZones|\{\}']



=== TEST 8: long name, html
--- http_config
    large_client_header_buffers 4 16k;
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html;
        access_log off;
    }
    location /probe {
        vhost_traffic_status_filter_by_set_key $http_user_agent ua::$server_name;
        return 200 "OK";
    }
--- more_headers eval
"User-Agent: " . ("A" x 8000)
--- request eval
['GET /probe', 'GET /status/format/html']
--- response_body_like eval
['OK', 'vhost traffic status monitor']
