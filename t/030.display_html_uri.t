# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The page reads its own address to build the one it fetches the JSON from,
# so that it keeps working when something in front of it serves the page
# under another path. The link in the footer is the fallback for a browser
# that runs no script, and it is the one the module fills in.
#
# One body check per block: Test::Nginx ignores response_body_unlike when
# response_body_like is in the same block.

use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks() * 2;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: the address of the JSON is taken from the browser
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html;
    }
--- request
GET /status
--- response_body_like: window\.location\.pathname



=== TEST 2: the module does not write that address into the page
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html;
    }
--- request
GET /status
--- response_body_unlike: vtsStatusURI = "



=== TEST 3: a request that ends in a slash keeps one in the link
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html;
    }
--- request
GET /status/
--- response_body_like: href="/status/format/json" id="jsonUri"



=== TEST 4: and does not double it
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html;
    }
--- request
GET /status/
--- response_body_unlike: //format/json



=== TEST 5: the link keeps the location when the format is in the address
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html;
    }
--- request
GET /status/format/html
--- response_body_like: href="/status/format/json" id="jsonUri"
