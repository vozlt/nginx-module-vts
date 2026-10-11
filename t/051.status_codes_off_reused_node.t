# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# Without vhost_traffic_status_measure_status_codes, a node has no status code
# array, and its pointer and length must say so. The slab does not clear what
# it hands out, so a node made where a deleted node's key used to be would
# otherwise take those bytes for the array and write through them.
#
# Long filter keys fill whole pages with key bytes; deleting them gives those
# pages back; the short nodes made next are carved out of them. The lengths
# are spread so that some key lands over the pointer whatever the page size.

use Test::Nginx::Socket;

our @long = map { 'GET /k?k=' . ('A' x ($_ * 250)) } 1 .. 64;
our @short = map { "GET /k?k=s$_" } 1 .. 64;
our @requests = (@long, 'GET /status/control?cmd=delete&group=*', @short, 'GET /status');

repeat_each(1);
plan tests => 3 * @requests;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: nodes made over deleted ones do not take their bytes for an array
--- http_config
    vhost_traffic_status_zone shared:vhost_traffic_status:32m;
    large_client_header_buffers 4 32k;
--- config
    location /k {
        vhost_traffic_status_filter_by_set_key $arg_k f::$server_name;
        return 200 "ok";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[@main::requests]
--- error_code eval
[(200) x @main::requests]
--- response_body_like eval
[
    (map { qr/\Aok\z/ } @main::long),
    qr/"processingCounts":[1-9]/,
    (map { qr/\Aok\z/ } @main::short),
    qr/"f::localhost":\{"s1":/,
]
--- no_error_log
exited on signal
