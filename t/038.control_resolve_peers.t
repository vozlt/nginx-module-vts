# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The `resolve` parameter of the upstream server directive needs nginx 1.27.3
# or later, freenginx does not have it.
#
# #322 gave the display a path that reads the peers an upstream group made at
# run time. The control interface never got one, so it looks for the peer in
# the addrs[] of the server line, which a `resolve` line leaves empty. The
# statistics are in the tree and the display shows them; the control interface
# answers with nothing.
#
# The two blocks below reach the same lookup from its two call sites, which
# differ in whether the mutex of the zone is held: the control handler holds
# it, vhost_traffic_status_set_by_filter does not.

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

my $DNSPort    = 18654;
my $FirstAddr  = '127.0.0.1';   # port 1984 of the test server answers here
my $SecondAddr = '127.0.0.1';   # the name keeps one address for these tests
my $SwitchIn   = 3600;

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

plan tests => repeat_each() * 15;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: the control interface finds a peer the resolver made
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:18654 valid=1s ipv6=off;
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
--- request eval
[
    'GET /up',
    'GET /status/format/json',
    "GET /status/control?cmd=status&group=upstream\@group&zone=backend\@127.0.0.1%3A1984",
]
--- response_body_like eval
[
    'OK',
    qr/"upstreamZones".*"127\.0\.0\.1:1984"/s,
    qr/"server":"127\.0\.0\.1:1984".*"requestCounter":1/s,
]

=== TEST 2: set_by_filter reaches the same peer, with no mutex held
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:18654 valid=1s ipv6=off;
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
    location /peer {
        vhost_traffic_status_set_by_filter $counter upstream@group/backend@127.0.0.1:1984/requestCounter;
        add_header X-Peer-Counter $counter;
    }
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['peer/file.txt' => 'peer:OK']
]
--- request eval
[
    'GET /up',
    'GET /peer/file.txt',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'OK',
    'peer:OK',
    qr/"upstreamZones".*"127\.0\.0\.1:1984"/s,
]
--- raw_response_headers_like eval
[
    '',
    qr/X-Peer-Counter: [1-9]/,
    '',
]
