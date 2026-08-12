# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The `resolve` parameter of the upstream server directive needs nginx 1.27.3
# or later, freenginx does not have it.
#
# TEST 2 answers the queries of nginx itself and gives the name a second
# address half way through the test, which is what a re-resolve does to an
# upstream group. The peers that are replaced have to keep their statistics.

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

my $DNSPort    = 18653;
my $FirstAddr  = '127.0.0.1';   # port 1984 of the test server answers here
my $SecondAddr = '127.0.0.2';
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

    # the _exit() is the path where exec() itself failed; writing it as the
    # alternative rather than the next statement is also what keeps perl from
    # warning that it is unlikely to be reached
    exec($^X, $server, $DNSPort, $SwitchIn, $FirstAddr, $SecondAddr)
        or POSIX::_exit(1);
}

END {
    if ($dns_pid) {
        # waitpid() must not carry the status of the resolver into the exit
        # status of the test
        local $?;

        kill 'TERM', $dns_pid;
        waitpid($dns_pid, 0);
    }
}

plan skip_all => "the test resolver does not answer on 127.0.0.1:$DNSPort"
    unless dns_ready();

plan tests => repeat_each() * blocks() * 4;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: an upstream that resolves the names at run time is displayed
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:65353 valid=1s ipv6=off;

    upstream backend {
        zone backend 1m;
        server 127.0.0.1:1984;
        server vts-test.invalid:1985 resolve;
    }
--- config
    location /ok {
        return 200 "OK";
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
['GET /ok', 'GET /status/format/json']
--- response_body_like eval
['OK', qr/"upstreamZones".*"127\.0\.0\.1:1984"/s]



=== TEST 2: a peer replaced by a re-resolve keeps its statistics
# The peer that is gone is the one with weight 0: nothing is known about a peer
# the group does not hold any more, and that is what the zeros say. It used to
# be marked with down, which reads as a statement about a peer that a balancer
# may in fact be using right now.
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:18653 valid=1s ipv6=off;
    resolver_timeout 2s;

    upstream backend {
        zone backend 1m;
        server vts-test.example:1984 resolve;
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
