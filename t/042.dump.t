# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# vhost_traffic_status_dump writes the tree to a file on a timer and reads it
# back when a worker starts, so that a restart does not lose what was measured.
# Nothing in the suite configured the directive, which left every line of
# ngx_http_vhost_traffic_status_dump.c unexecuted - the write, the restore, and
# the two places recent work touched inside them: the last-seen time a restored
# node is given (#375) and the filter count a restored node is added to (#383).
#
# The file is kept outside the server root. Test::Nginx builds that directory
# again for every block that changes the configuration, and a dump written
# under it would be thrown away with it - which is exactly what the restore
# needs to survive. It is removed before the run as well: a dump left by an
# earlier one would be read into the first block, and the counters would start
# from a number this file did not put there.

use Test::Nginx::Socket;
use File::Spec ();

my $DumpFile = File::Spec->rel2abs('t/vts.dump');

$ENV{TEST_NGINX_DUMP_FILE} = $DumpFile;

unlink $DumpFile;

add_cleanup_handler(sub { unlink $DumpFile });

plan tests => repeat_each() * 12;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: what a worker measured is written to the dump file
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;
--- config
    location /ok {
        return 200 "OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- wait: 2
--- request eval
['GET /ok', 'GET /status/format/json']
--- response_body_like eval
['OK', qr/"localhost":\{"requestCounter":1/]

=== TEST 2: a worker that starts finds it and reads it back
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;
--- config
    location /ok {
        return 200 "OK";
    }
    location /restarted {
        return 200 "restarted";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /status/format/json']
--- response_body_like eval
[qr/"localhost":\{"requestCounter":[2-9]/]

=== TEST 3: the restored nodes are counted, not just written out
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;
--- config
    location /ok {
        return 200 "OK";
    }
    location /restarted-again {
        return 200 "restarted";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /status/format/json']
--- response_body_like eval
[qr/"usedNode":[1-9]/]

=== TEST 4: a restored node keeps taking traffic
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;
--- config
    location /ok {
        return 200 "OK";
    }
    location /once-more {
        return 200 "restarted";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /status/format/json']
--- response_body_like eval
['OK', qr/"localhost":\{"requestCounter":[3-9]/]
