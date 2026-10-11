# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# With vhost_traffic_status_measure_status_codes, a node's status code
# counters are a slab allocation of their own. A node that is deleted, or
# dropped by vhost_traffic_status_filter_max_node, has to give them back
# too; otherwise each one leaves its counters behind, and a small zone runs
# out of room for new nodes while it holds only a couple.
#
# `all` makes the counters about 4K a node, so a 256K zone has room for some
# sixty of them that nothing frees, and each block makes a few hundred.

use Test::Nginx::Socket;

our @deleted = map { ("GET /k?k=d$_", 'GET /status/control?cmd=delete&group=*') } 1 .. 150;
our @dropped = map { "GET /k?k=u$_" } 1 .. 300;

repeat_each(1);
plan tests => 3 * (@deleted + 1) + 3 * (@dropped + 1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: deleting a node frees its status code counters
--- http_config
    vhost_traffic_status_zone shared:vhost_traffic_status:256k;
    vhost_traffic_status_measure_status_codes all;
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
[@main::deleted, 'GET /k?k=last']
--- error_code eval
[(200) x (@main::deleted + 1)]
--- response_body_like eval
[(map { /delete/ ? qr/"processingCounts":[1-9]/ : qr/\Aok\z/ } @main::deleted), qr/\Aok\z/]
--- no_error_log eval
[qr/no memory|alloc_locked\(\) failed/]



=== TEST 2: dropping a node over the cap frees its status code counters
--- http_config
    vhost_traffic_status_zone shared:vhost_traffic_status:256k;
    vhost_traffic_status_measure_status_codes all;
    vhost_traffic_status_filter_max_node 1 f;
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
[@main::dropped, 'GET /status']
--- error_code eval
[(200) x (@main::dropped + 1)]
--- response_body_like eval
[(map { qr/\Aok\z/ } @main::dropped), qr/"f::localhost":\{"u300":/]
--- no_error_log eval
[qr/no memory|alloc_locked\(\) failed/]
