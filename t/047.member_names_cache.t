# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The half of t/046 that a build without the cache cannot name. The cache
# members are declared inside #if (NGX_HTTP_CACHE), so naming one of them
# keeps nginx from starting on such a build - which is why they are here and
# not in t/046, and why this file steps aside when the cache is not built in.
#
# The same three vocabularies, and the same limits on what each assertion is
# worth. See the head of t/046.

use Test::Nginx::Socket;

my $nginx = $ENV{TEST_NGINX_BINARY} || 'nginx';
my $configure = `$nginx -V 2>&1` || '';

plan skip_all => "the cache is not built in: $nginx -V says --without-http-cache"
    if $configure =~ /--without-http-cache/;

plan tests => repeat_each() * 15;

add_cleanup_handler(
    sub {
        my $CacheDir = "$Test::Nginx::Util::ServRoot/cache_*";
        system("rm -rf $CacheDir > /dev/null") == 0 or
        bail_out "Can't remove $CacheDir";
    }
);

no_shuffle();
run_tests();

__DATA__

=== TEST 1: every cache variable is a known name
--- http_config
    vhost_traffic_status_zone;
--- config
    location /v {
        add_header X-Miss        $vts_cache_miss_counter;
        add_header X-Bypass      $vts_cache_bypass_counter;
        add_header X-Expired     $vts_cache_expired_counter;
        add_header X-Stale       $vts_cache_stale_counter;
        add_header X-Updating    $vts_cache_updating_counter;
        add_header X-Revalidated $vts_cache_revalidated_counter;
        add_header X-Hit         $vts_cache_hit_counter;
        add_header X-Scarce      $vts_cache_scarce_counter;
        return 200 "OK";
    }
--- request eval
['GET /v', 'GET /v']
--- response_body_like eval
['OK', 'OK']
--- raw_response_headers_like eval
[
    qr/\A(?!.*X-Miss)/s,
    qr/X-Miss: 0\b.*X-Bypass: 0\b.*X-Expired: 0\b.*X-Stale: 0\b.*X-Updating: 0\b.*X-Revalidated: 0\b.*X-Hit: 0\b.*X-Scarce: 0\b/s,
]

=== TEST 2: the set_by_filter members of a cache zone, and the cache limit members
--- http_config
    vhost_traffic_status_zone;
    proxy_cache_path cache_one levels=1:2 keys_zone=cache_one:2m inactive=1m max_size=4m;

    upstream backend {
        server 127.0.0.1:1984;
    }

    server {
        listen 1984;
        location / {
            add_header Cache-Control "max-age=10";
            return 200 "up";
        }
    }
--- config
    location /p {
        proxy_cache cache_one;
        proxy_cache_valid 200 10s;
        proxy_pass http://backend;
    }

    location /m.txt {
        vhost_traffic_status_set_by_filter $cacheMaxSize     cache/cache_one/cacheMaxSize;
        vhost_traffic_status_set_by_filter $cacheUsedSize    cache/cache_one/cacheUsedSize;
        vhost_traffic_status_set_by_filter $cacheMiss        cache/cache_one/cacheMiss;
        vhost_traffic_status_set_by_filter $cacheHit         cache/cache_one/cacheHit;
        vhost_traffic_status_set_by_filter $cacheBypass      cache/cache_one/cacheBypass;
        vhost_traffic_status_set_by_filter $cacheExpired     cache/cache_one/cacheExpired;
        vhost_traffic_status_set_by_filter $cacheStale       cache/cache_one/cacheStale;
        vhost_traffic_status_set_by_filter $cacheUpdating    cache/cache_one/cacheUpdating;
        vhost_traffic_status_set_by_filter $cacheRevalidated cache/cache_one/cacheRevalidated;
        vhost_traffic_status_set_by_filter $cacheScarce      cache/cache_one/cacheScarce;

        add_header X-Max-Size    $cacheMaxSize;
        add_header X-Used-Size   $cacheUsedSize;
        add_header X-Miss        $cacheMiss;
        add_header X-Hit         $cacheHit;
        add_header X-Bypass      $cacheBypass;
        add_header X-Expired     $cacheExpired;
        add_header X-Stale       $cacheStale;
        add_header X-Updating    $cacheUpdating;
        add_header X-Revalidated $cacheRevalidated;
        add_header X-Scarce      $cacheScarce;
    }
--- user_files
>>> m.txt
read
--- request eval
['GET /p', 'GET /p', 'GET /m.txt']
--- response_body_like eval
['up', 'up', 'read']
--- raw_response_headers_like eval
[
    qr/\A(?!.*X-Max-Size)/s,
    qr/\A(?!.*X-Max-Size)/s,
    qr/X-Max-Size: [1-9]\d*.*X-Miss: [1-9]\d*.*X-Hit: [1-9]\d*.*X-Bypass: 0\b.*X-Expired: 0\b.*X-Stale: 0\b.*X-Updating: 0\b.*X-Revalidated: 0\b.*X-Scarce: 0\b/s,
]
