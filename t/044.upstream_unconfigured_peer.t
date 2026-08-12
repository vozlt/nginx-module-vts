# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# An upstream group is written out of its `server` lines, so a node keyed under
# the group whose peer is not one of them is never reached. The statistics are
# in the tree and nothing prints them.
#
# Three things put a peer in that position, and they are the same case:
#
#   - a balancer_by_lua block picks an address of its own (#155)
#   - a server line is taken out of the configuration
#   - a re-resolve replaces the peers of a resolving group (#357, handled)
#
# The second one is what this file uses, because it needs neither lua nor a
# resolver: the peers are measured, the dump keeps them across a restart, and
# the configuration that comes back names only one of them.
#
# The dump is kept outside the server root, which Test::Nginx builds again for
# every block that changes the configuration.

use Test::Nginx::Socket;
use File::Spec ();

my $DumpFile = File::Spec->rel2abs('t/vts-unconfigured.dump');

$ENV{TEST_NGINX_DUMP_FILE} = $DumpFile;

unlink $DumpFile;

add_cleanup_handler(sub { unlink $DumpFile });

plan tests => repeat_each() * 14;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: both peers are measured
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;

    server {
        listen 1985;

        location / {
            return 200 "second";
        }
    }

    upstream backend {
        server 127.0.0.1:1984;
        server 127.0.0.1:1985;
    }
--- config
    location /ok {
        return 200 "OK";
    }
    location /up {
        proxy_next_upstream off;
        proxy_pass http://backend/ok;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- wait: 2
--- request eval
['GET /up', 'GET /up', 'GET /status/format/json']
--- response_body_like eval
[
    qr/\A(OK|second)/,
    qr/\A(OK|second)/,
    qr/(?=.*"server":"127\.0\.0\.1:1984")(?=.*"server":"127\.0\.0\.1:1985")/s,
]

=== TEST 2: the one taken out of the configuration is still written
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;

    server {
        listen 1985;

        location / {
            return 200 "second";
        }
    }

    upstream backend {
        server 127.0.0.1:1984;
    }
--- config
    location /ok {
        return 200 "OK";
    }
    location /up {
        proxy_pass http://backend/ok;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /status/format/json']
--- response_body_like eval
[
    qr/(?=.*"server":"127\.0\.0\.1:1984")(?=.*"server":"127\.0\.0\.1:1985")/s,
]

=== TEST 3: it keeps the counters it was measured with
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;

    server {
        listen 1985;

        location / {
            return 200 "second";
        }
    }

    upstream backend {
        server 127.0.0.1:1984;
    }
--- config
    location /ok {
        return 200 "OK";
    }
    location /up {
        proxy_pass http://backend/ok;
    }
    location /keeps {
        return 200 "keeps";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /status/format/json']
--- response_body_like eval
[
    qr/"server":"127\.0\.0\.1:1985"(?:(?!"server":).)*"requestCounter":[1-9]/s,
]

=== TEST 4: what is not known about it is not claimed
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;

    server {
        listen 1985;

        location / {
            return 200 "second";
        }
    }

    upstream backend {
        server 127.0.0.1:1984;
    }
--- config
    location /ok {
        return 200 "OK";
    }
    location /not-claimed {
        return 200 "not claimed";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /status/format/json']
--- response_body_like eval
[
    qr/"server":"127\.0\.0\.1:1985"(?:(?!"server":).)*"weight":0(?:(?!"server":).)*"down":false/s,
]

=== TEST 5: the control interface reaches it too
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;

    server {
        listen 1985;

        location / {
            return 200 "second";
        }
    }

    upstream backend {
        server 127.0.0.1:1984;
    }
--- config
    location /ok {
        return 200 "OK";
    }
    location /reaches {
        return 200 "reaches";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
["GET /status/control?cmd=status&group=upstream\@group&zone=backend\@127.0.0.1%3A1985"]
--- response_body_like eval
[
    qr/"server":"127\.0\.0\.1:1985".*"requestCounter":[1-9]/s,
]
