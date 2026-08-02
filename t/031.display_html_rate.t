# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The rate per second on the page is the rise of a counter between two polls.
# A counter does not only rise: vhost_traffic_status_filter_max_node drops the
# node of a filter that has not been used for a while, and the next request
# through it starts a new one from zero, which used to be shown as a negative
# rate. Two readings that carry the same time leave nothing to divide by.
#
# The script runs in the browser, so this only checks that the page carries
# the guards; what they do is covered by front/src/utils/rateTracker.test.ts,
# which holds the same rule.

use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks() * 2;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: the page does not turn a counter that fell into a rate
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html;
    }
--- request
GET /status
--- response_body_like: increase < 0



=== TEST 2: nor one that has no period to divide by
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html;
    }
--- request
GET /status
--- response_body_like: msec\.period > 0
