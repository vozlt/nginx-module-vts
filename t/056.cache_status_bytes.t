# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

add_response_body_check(
    sub {
        my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;

        return if !defined $body || $body eq 'OK';

        my $name = $block->name;

        if ($body =~ /^\s*\{/) {
            my @patterns = (
                qr/"serverZones".*"downstreamOutBytes"/s,
                qr/"filterZones".*"downstreamOutBytes"/s,
                qr/"cacheZones".*"downstreamOutBytes"/s,
                qr/"downstreamOutBytes".*"miss":[1-9][0-9]*/s,
                qr/"downstreamOutBytes".*"bypass":[1-9][0-9]*/s,
                qr/"downstreamOutBytes".*"hit":[1-9][0-9]*/s,
                qr/"upstreamInBytes".*"miss":[1-9][0-9]*/s,
                qr/"upstreamInBytes".*"bypass":[1-9][0-9]*/s,
                qr/"upstreamInBytes".*"hit":0/s,
            );

            for my $pattern (@patterns) {
                $body =~ $pattern
                    or bail_out "$name: missing expected JSON pattern $pattern";
            }
        } elsif ($body =~ /^nginx_vts_/m) {
            my @patterns = (
                qr/^nginx_vts_server_cache_bytes_total\{host="localhost",status="bypass",direction="downstream"\} [1-9][0-9]*$/m,
                qr/^nginx_vts_server_cache_bytes_total\{host="localhost",status="hit",direction="upstream"\} 0$/m,
                qr/^nginx_vts_filter_cache_bytes_total\{filter="storage::localhost",filter_name="bytes",status="miss",direction="upstream"\} [1-9][0-9]*$/m,
                qr/^nginx_vts_cache_status_bytes_total\{cache_zone="cache_status_bytes",status="hit",direction="downstream"\} [1-9][0-9]*$/m,
            );

            for my $pattern (@patterns) {
                $body =~ $pattern
                    or bail_out "$name: missing expected Prometheus pattern $pattern";
            }
        }
    }
);

plan tests => repeat_each() * blocks() * 8;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: cache status byte counters in json
--- http_config
    vhost_traffic_status_zone;
    proxy_cache_path /tmp/cache_status_bytes levels=1:2 keys_zone=cache_status_bytes:2m inactive=1m max_size=4m;
    upstream backend {
        server 127.0.0.1:1984;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /v {
        vhost_traffic_status_filter_by_set_key bytes storage::$server_name;

        proxy_cache cache_status_bytes;
        proxy_cache_valid 200 10s;
        proxy_cache_bypass $arg_bypass;
        proxy_no_cache $arg_bypass;

        proxy_pass http://backend/return;
    }
--- user_files eval
[
    ['return/file.txt' => 'cache-bytes:OK']
]
--- post_setup_server_root
system("rm -rf /tmp/cache_status_bytes");
--- request eval
[
    'GET /v/file.txt?bypass=1',
    'GET /v/file.txt',
    'GET /v/file.txt',
    'GET /status/format/json'
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK',
    'downstreamOutBytes'
]



=== TEST 2: cache status byte counters in prometheus
--- http_config
    vhost_traffic_status_zone;
    proxy_cache_path /tmp/cache_status_bytes levels=1:2 keys_zone=cache_status_bytes:2m inactive=1m max_size=4m;
    upstream backend {
        server 127.0.0.1:1984;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
        access_log off;
    }
    location /v {
        vhost_traffic_status_filter_by_set_key bytes storage::$server_name;

        proxy_cache cache_status_bytes;
        proxy_cache_valid 200 10s;
        proxy_cache_bypass $arg_bypass;
        proxy_no_cache $arg_bypass;

        proxy_pass http://backend/return;
    }
--- user_files eval
[
    ['return/file.txt' => 'cache-bytes:OK']
]
--- post_setup_server_root
system("rm -rf /tmp/cache_status_bytes");
--- request eval
[
    'GET /v/file.txt?bypass=1',
    'GET /v/file.txt',
    'GET /v/file.txt',
    'GET /status/format/prometheus'
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK',
    'nginx_vts_server_cache_bytes_total'
]
