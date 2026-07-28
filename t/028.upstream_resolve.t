# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The `resolve` parameter of the upstream server directive needs nginx 1.27.3
# or later, freenginx does not have it.

use Test::Nginx::Socket;

my $nginx = $ENV{TEST_NGINX_BINARY} || 'nginx';
my $version = `$nginx -v 2>&1` || '';
my $supported = 0;

if ($version =~ m{^nginx version: nginx/(\d+)\.(\d+)\.(\d+)}) {
    $supported = ($1 * 1000000 + $2 * 1000 + $3) >= 1027003;
}

plan skip_all => "upstream resolve is not supported by: $version"
    unless $supported;

plan tests => repeat_each() * blocks() * 4;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: an upstream that resolves the names at run time is displayed
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:65353 valid=1s ipv6=off;

    upstream backend {
        zone backend 1m;
        server 127.0.0.1:1984;
        server vts-test.invalid:1985 resolve;
    }
--- config
    location /ok {
        return 200 "OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /status/format/json']
--- response_body_like eval
['OK', qr/"upstreamZones".*"127\.0\.0\.1:1984"/s]
