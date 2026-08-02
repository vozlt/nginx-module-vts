# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# usedSize is the sum of the sizes of the nodes, which is not what the zone
# has spent: the slab hands out a whole page or a whole slot for each of them.
# A zone can therefore refuse a node while usedSize still reads well below
# maxSize, and the only sign of it is a line in the error log.
#
# freeSize is what the slab itself has left, so that the display says whether
# there is room.

use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks() * 2;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: the shared zone says how much of it is left
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request
GET /status/format/json
--- response_body_like: "sharedZones":\{.*"freeSize":\d+



=== TEST 2: and says it to prometheus as well
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format prometheus;
        access_log off;
    }
--- request
GET /status/format/prometheus
--- response_body_like: nginx_vts_main_shm_usage_bytes\{shared="free_size"\} \d+
