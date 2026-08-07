# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# find_node() kept the last node it had handed out for a type and gave it back
# whenever the hash matched, and the hash was the whole test: node->key is a
# crc32 and the key itself was never looked at. The lookup under it compares
# both, so two zones whose keys collide on crc32 shared one node and the
# traffic of one was counted against the other.
#
# The two values below collide as filter keys, "FG" 0x1f "g::" 0x1f value:
#
#     crc32("FG\x1fg::\x1fkil87gsgjv") == crc32("FG\x1fg::\x1f644iob976g")
#                                      == 0x02d2be96
#
# One request each, and the display has to hold both of them.

use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks() * 8;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: two keys that share a hash keep their own nodes
--- http_config
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_by_set_key $arg_z g::;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        vhost_traffic_status_bypass_stats on;
    }
    location /c {
        return 200 "ok\n";
    }
--- request eval
[
    'GET /c?z=kil87gsgjv',
    'GET /c?z=644iob976g',
    'GET /status/format/json',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'ok',
    'ok',
    qr/"kil87gsgjv"/,
    qr/"644iob976g"/,
]
