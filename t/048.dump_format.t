# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The dump header used to carry nginx_version in its version field, which the
# restore path never read. Pre-version dumps are now rejected with a warning:
# a dump written by an older VTS build cannot be trusted to match the current
# node layout.

use Test::Nginx::Socket;
use Config;
use File::Spec ();

my $DumpFile = File::Spec->rel2abs('t/vts.dump-format');

$ENV{TEST_NGINX_DUMP_FILE} = $DumpFile;

unlink $DumpFile;

add_cleanup_handler(sub { unlink $DumpFile });

plan tests => repeat_each() * 11;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: a current dump is written
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;
--- config
    location /v {
        set $vol legacy;
        vhost_traffic_status_filter_by_set_key $vol legacy::$server_name;
        return 200 "OK";
    }
--- request
GET /v/file.txt
--- response_body_like: OK
--- wait: 2

=== TEST 2: a pre-version dump is rejected
--- post_setup_server_root
    my $dump = $ENV{TEST_NGINX_DUMP_FILE};
    open my $out, '>', $dump or die "cannot open $dump: $!";
    binmode $out;
    my $uint_fmt = $Config::Config{ptrsize} == 8 ? 'Q' : 'L!';
    print {$out} pack("a128 $uint_fmt $uint_fmt",
                      'ngx_http_vhost_traffic_status', 0, 1031004);
    print {$out} "\0" x 64;
    close $out;
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request
GET /status/format/json
--- response_body_like: "serverZones"
--- error_log
dump_restore::dump_header_read() version:1031004 failed

=== TEST 3: a dump from a newer format version is rejected
--- post_setup_server_root
    my $dump = $ENV{TEST_NGINX_DUMP_FILE};
    open my $out, '>', $dump or die "cannot open $dump: $!";
    binmode $out;
    my $uint_fmt = $Config::Config{ptrsize} == 8 ? 'Q' : 'L!';
    print {$out} pack("a128 $uint_fmt $uint_fmt $uint_fmt",
                      'ngx_http_vhost_traffic_status', 0, 2, 0);
    print {$out} "\0" x 64;
    close $out;
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request
GET /status/format/json
--- response_body_like: "serverZones"
--- error_log
dump_restore::dump_header_read() version:2 failed

=== TEST 4: a dump with the wrong node size is rejected
--- post_setup_server_root
    my $dump = $ENV{TEST_NGINX_DUMP_FILE};
    open my $out, '>', $dump or die "cannot open $dump: $!";
    binmode $out;
    my $uint_fmt = $Config::Config{ptrsize} == 8 ? 'Q' : 'L!';
    print {$out} pack("a128 $uint_fmt $uint_fmt $uint_fmt",
                      'ngx_http_vhost_traffic_status', 0, 1, 1);
    print {$out} "\0" x 64;
    close $out;
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_dump $TEST_NGINX_DUMP_FILE 1s;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request
GET /status/format/json
--- response_body_like: "serverZones"
--- error_log
dump_restore::dump_header_read() node size:1 failed
