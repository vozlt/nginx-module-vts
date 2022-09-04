# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;
use Fcntl;

add_response_body_check(
    sub {
        my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;

        my $path = 't/servroot/logs/access.log';
        my @lines = FH->getlines() if (sysopen(FH, $path, O_RDONLY));
        close(FH);
        my $ll = $lines[-1];

        ($ll =~ /(requestCounter|inBytes|outBytes|2xx):[-0-9]/) or
        bail_out "variables by set_by_filter error($ll)";

        ($req_idx > 1 && $ll !~ /(requestCounter|2xx):[1-9]/) and
        bail_out "variables by set_by_filter error($ll)";

        if ($block->name =~ /TEST 5/) {
            ($req_idx > 1 && $ll !~ /(cacheMaxSize|cacheUsedSize|cacheHit):[0-9]/) and
            bail_out "variables by set_by_filter error($ll)";
        }
    }
);

add_cleanup_handler(
    sub {
        my $CacheDir = "t/servroot/cache_*";
        system("rm -rf $CacheDir > /dev/null") == 0 or
        bail_out "Can't remove $CacheDir";
    }
);


plan tests => repeat_each() * blocks() * 6;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: access variables by vhost_traffic_status_set_by_filter $* server/*/*
--- http_config
    vhost_traffic_status_zone;
    log_format basic '[$time_local] requestCounter:$requestCounter '
                     'inBytes:$inBytes outBytes:$outBytes '
                     '2xx:$2xx';
    access_log  logs/access.log basic;
--- config
    location /v {
        set $group server;
        set $zone localhost;

        vhost_traffic_status_set_by_filter $requestCounter $group/$zone/requestCounter;
        vhost_traffic_status_set_by_filter $inBytes $group/$zone/inBytes;
        vhost_traffic_status_set_by_filter $outBytes $group/$zone/outBytes;
        vhost_traffic_status_set_by_filter $2xx $group/$zone/2xx;
    }
--- user_files eval
[
    ['v/file.txt' => '{"return":"OK"}']
]
--- request eval
[
    'GET /v/file.txt',
    'GET /v/file.txt',
    'GET /v/file.txt'
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK'
]



=== TEST 2: access variables by vhost_traffic_status_set_by_filter $* upstream@alone/*/*
--- http_config
    vhost_traffic_status_zone;
    log_format basic '[$time_local] requestCounter:$requestCounter '
                     'inBytes:$inBytes outBytes:$outBytes '
                     '2xx:$2xx';
    access_log  logs/access.log basic;
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
        set $group upstream@alone;
        set $zone 127.0.0.1:1984;

        vhost_traffic_status_set_by_filter $requestCounter $group/$zone/requestCounter;
        vhost_traffic_status_set_by_filter $inBytes $group/$zone/inBytes;
        vhost_traffic_status_set_by_filter $outBytes $group/$zone/outBytes;
        vhost_traffic_status_set_by_filter $2xx $group/$zone/2xx;

        proxy_pass http://127.0.0.1:1984/return;
    }
--- user_files eval
[
    ['return/file.txt' => '{"return":"OK"}']
]
--- request eval
[
    'GET /v/file.txt',
    'GET /v/file.txt',
    'GET /v/file.txt'
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK'
]



=== TEST 3: access variables by vhost_traffic_status_set_by_filter $* upstream@group/*/*
--- http_config
    vhost_traffic_status_zone;
    log_format basic '[$time_local] requestCounter:$requestCounter '
                     'inBytes:$inBytes outBytes:$outBytes '
                     '2xx:$2xx';
    access_log  logs/access.log basic;
    upstream backend {
        server 127.0.0.1:1984;
    }
--- config
    location /v {
        set $group upstream@group;
        set $zone backend@127.0.0.1:1984;

        vhost_traffic_status_set_by_filter $requestCounter $group/$zone/requestCounter;
        vhost_traffic_status_set_by_filter $inBytes $group/$zone/inBytes;
        vhost_traffic_status_set_by_filter $outBytes $group/$zone/outBytes;
        vhost_traffic_status_set_by_filter $2xx $group/$zone/2xx;

        proxy_pass http://backend/return;
    }
--- user_files eval
[
    ['return/file.txt' => '{"return":"OK"}']
]
--- request eval
[
    'GET /v/file.txt',
    'GET /v/file.txt',
    'GET /v/file.txt'
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK'
]



=== TEST 4: access variables by vhost_traffic_status_set_by_filter $* filter/*/*
--- http_config
    vhost_traffic_status_zone;
    log_format basic '[$time_local] requestCounter:$requestCounter '
                     'inBytes:$inBytes outBytes:$outBytes '
                     '2xx:$2xx';
    access_log  logs/access.log basic;
--- config
    location /v {
        vhost_traffic_status_filter_by_set_key v group;

        set $group filter;
        set $zone group@v;

        vhost_traffic_status_set_by_filter $requestCounter $group/$zone/requestCounter;
        vhost_traffic_status_set_by_filter $inBytes $group/$zone/inBytes;
        vhost_traffic_status_set_by_filter $outBytes $group/$zone/outBytes;
        vhost_traffic_status_set_by_filter $2xx $group/$zone/2xx;
    }
--- user_files eval
[
    ['v/file.txt' => '{"return":"OK"}']
]
--- request eval
[
    'GET /v/file.txt',
    'GET /v/file.txt',
    'GET /v/file.txt'
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK'
]



=== TEST 5: access variables by vhost_traffic_status_set_by_filter $* cache/*/*
--- http_config
    vhost_traffic_status_zone;
    proxy_cache_path cache_one levels=1:2 keys_zone=cache_one:2m inactive=1m max_size=4m;
    log_format basic '[$time_local] requestCounter:$requestCounter '
                     'inBytes:$inBytes outBytes:$outBytes '
                     '2xx:$2xx cacheMaxSize:$cacheMaxSize '
                     'cacheUsedSize:$cacheUsedSize cacheHit:$cacheHit';
    access_log  logs/access.log basic;
    upstream backend {
        server 127.0.0.1:1984;
    }
--- config
    location /v {
        proxy_cache cache_one;
        proxy_cache_valid 200 10s;

        set $group cache;
        set $zone cache_one;

        vhost_traffic_status_set_by_filter $requestCounter $group/$zone/requestCounter;
        vhost_traffic_status_set_by_filter $inBytes $group/$zone/inBytes;
        vhost_traffic_status_set_by_filter $outBytes $group/$zone/outBytes;
        vhost_traffic_status_set_by_filter $2xx $group/$zone/2xx;

        vhost_traffic_status_set_by_filter $cacheMaxSize $group/$zone/cacheMaxSize;
        vhost_traffic_status_set_by_filter $cacheUsedSize $group/$zone/cacheUsedSize;
        vhost_traffic_status_set_by_filter $cacheHit $group/$zone/cacheHit;

        proxy_pass http://backend/return;
    }
--- user_files eval
[
    ['return/file.txt' => '{"return":"OK"}']
]
--- request eval
[
    'GET /v/file.txt',
    'GET /v/file.txt',
    'GET /v/file.txt'
]
--- response_body_like eval
[
    'OK',
    'OK',
    'OK'
]
