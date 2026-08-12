# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The `resolve` parameter of the upstream server directive needs nginx 1.27.3
# or later, freenginx does not have it.
#
# A peer that a re-resolve takes out of its upstream group keeps its statistics
# in the tree, and the display writes them after the peers the group has now
# (#357). A group is enrolled in that only when the primary list resolves:
#
#     peers = uscf->peer.data;
#
#     if (peers->resolve == NULL) {
#         continue;
#     }
#
# nginx builds a resolve list for the backup servers too, so a group whose only
# resolving line is a backup has peers->resolve == NULL while
# peers->next->resolve is not. It is skipped, and what the replaced backup
# served is in the tree with nothing pointing at it.
#
# This file has its own resolver because the answer changes on a timer that
# starts when the resolver does: a block that has to run before the change
# cannot share one with blocks that run for an unknown length of time first.

use Test::Nginx::Socket;
use Socket;
use POSIX ();

my $nginx = $ENV{TEST_NGINX_BINARY} || 'nginx';
my $version = `$nginx -v 2>&1` || '';
my $supported = 0;

if ($version =~ m{^nginx version: nginx/(\d+)\.(\d+)\.(\d+)}) {
    $supported = ($1 * 1000000 + $2 * 1000 + $3) >= 1027003;
}

plan skip_all => "upstream resolve is not supported by: $version"
    unless $supported;

# the test resolver

my $DNSPort    = 18661;
my $FirstAddr  = '127.0.0.1';   # port 1984 of the test server answers here
my $SecondAddr = '127.0.0.2';   # and here, the peer is replaced by the name
my $SwitchIn   = 4;             # seconds until the name gets the second address

# Sends a query and tells whether the test resolver answers it.
sub dns_ready {
    my $sock;

    socket($sock, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or return 0;

    my $to = sockaddr_in($DNSPort, inet_aton('127.0.0.1'));
    my $query = pack('n n n n n n', 0x2a2a, 0x0100, 1, 0, 0, 0)
                . join('', map { chr(length $_) . $_ } qw(vts-test example))
                . "\0" . pack('n n', 1, 1);

    for (1 .. 30) {
        next unless send($sock, $query, 0, $to);

        my $rin = '';
        vec($rin, fileno($sock), 1) = 1;

        if (select($rin, undef, undef, 0.1)) {
            my $answer;
            recv($sock, $answer, 512, 0);
            close $sock;
            return 1;
        }
    }

    close $sock;

    return 0;
}

# The resolver runs as its own process: a plain fork of the test is not safe
# on every platform.
my $dns_pid = fork();

defined $dns_pid or plan skip_all => "fork() failed: $!";

if ($dns_pid == 0) {
    my $server = __FILE__;
    $server =~ s{[^/]+$}{dns_server.pl};

    exec($^X, $server, $DNSPort, $SwitchIn, $FirstAddr, $SecondAddr)
        or POSIX::_exit(1);
}

END {
    if ($dns_pid) {
        local $?;

        kill 'TERM', $dns_pid;
        waitpid($dns_pid, 0);
    }
}

plan skip_all => "the test resolver does not answer on 127.0.0.1:$DNSPort"
    unless dns_ready();

plan tests => repeat_each() * 4;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: a backup a re-resolve took out keeps its statistics
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:18661 valid=1s ipv6=off;
    resolver_timeout 2s;

    upstream backend {
        zone backend 1m;
        server 127.0.0.1:1 down;
        server vts-test.example:1984 resolve backup;
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
--- wait: 6
--- request eval
['GET /up', 'GET /status/format/json']
--- response_body_like eval
['OK', qr/(?=.*"server":"127\.0\.0\.2:1984")(?=.*\{"server":"127\.0\.0\.1:1984","requestCounter":[1-9])(?=.*"127\.0\.0\.1:1984".*?"weight":0)/s]
