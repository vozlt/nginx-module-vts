# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;
use Sys::Hostname;

add_response_body_check(
    sub {
        my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;
        return unless $body =~ /^\s*\{/;
        my $name = $block->name;
        open(my $fh, '|-', 'python3 t/validate_json_schema.py')
            or bail_out "$name: failed to run validate_json_schema.py: $!";
        print $fh $body;
        close $fh;
        $? == 0 or bail_out "$name (req $req_idx): JSON schema validation failed for body: $body";
    }
);

our $hostname = lc(hostname());

plan tests => repeat_each() * 14;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: basic response schema
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /status/format/json']
--- response_body_like eval
["$::hostname"]

=== TEST 2: filterZones schema
--- http_config
    vhost_traffic_status_zone;
    upstream backend {
        server 127.0.0.1;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
    }
--- user_files eval
[['storage/vol0/file.txt' => 'filter:OK']]
--- request eval
['GET /storage/vol0/file.txt', 'GET /status/format/json']
--- response_body_like eval
['OK', 'filterZones.*vol0']

=== TEST 3: upstreamZones schema
--- http_config
    vhost_traffic_status_zone;
    upstream backend {
        server 127.0.0.1;
    }
    server {
        server_name _;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /upstream {
        proxy_pass http://backend;
    }
--- request eval
['GET /upstream', 'GET /status/format/json']
--- error_code eval
[404, 200]
--- response_body_like eval
['404', 'upstreamZones.*backend']

=== TEST 4: cacheZones schema
--- http_config
    vhost_traffic_status_zone;
    proxy_cache_path /tmp/cache_test levels=1:2 keys_zone=cache_test:2m inactive=1m max_size=4m;
    upstream backend {
        server 127.0.0.1;
    }
    server {
        server_name _;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /cached {
        proxy_cache cache_test;
        proxy_cache_valid 200 10s;
        proxy_set_header Host backend;
        proxy_pass http://backend;
    }
--- user_files eval
[['cached/file.txt' => 'cached:OK']]
--- request eval
['GET /cached/file.txt', 'GET /status/format/json']
--- error_code eval
[200, 200]
--- response_body_like eval
['cached', 'cacheZones.*cache_test']
