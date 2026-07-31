# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# A server of an upstream group resolves to one peer per address of its name.
# The control handler has to find every one of them, not only the first, which
# is what the display of the group does.
#
# The name used here is localhost, so the test needs it to resolve to both
# loopback addresses and needs the IPv6 one to be usable.

use Test::Nginx::Socket;

use IO::Socket::IP;
use Socket qw(getaddrinfo SOCK_STREAM);

my ($err, @addrs) = getaddrinfo('localhost', '', { socktype => SOCK_STREAM });

plan skip_all => 'localhost resolves to one address only'
    if $err or @addrs < 2;

plan skip_all => 'the IPv6 loopback is not usable'
    unless IO::Socket::IP->new(LocalHost => '::1', LocalPort => 0, Listen => 1);

plan tests => repeat_each() * blocks() * 8;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: the control handler finds every address of an upstream server
--- http_config
    vhost_traffic_status_zone;

    upstream backend {
        server localhost:1984;
    }
--- config
    listen [::1]:1984;

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
[
    'GET /up',
    'GET /up',
    'GET /status/control?cmd=status&group=upstream%40group&zone=backend%40127.0.0.1%3A1984',
    'GET /status/control?cmd=status&group=upstream%40group&zone=backend%40[%3A%3A1]%3A1984',
]
--- response_body_like eval
[
    'OK',
    'OK',
    qr/"server":"127\.0\.0\.1:1984"/,
    qr/"server":"\[::1\]:1984"/,
]
