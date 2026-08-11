# vi:set ft=perl ts=4 sw=4 et fdm=marker:

# The `resolve` parameter of the upstream server directive needs nginx 1.27.3
# or later, freenginx does not have it.
#
# nginx builds a resolve list for the backup servers too, so a line reading
# `server name:port resolve backup` gets its peers at run time like any other.
# Those peers live in peers->next, and neither reader walks it: the display
# takes the primary peers from peers->peer and the backups from the server
# lines, where a resolving line leaves an address whose name was never set.
#
# The statistics are keyed on the name of the peer that served the request, so
# the node is in the tree. What comes out is an entry with an empty server name
# and no counters, and a control interface that answers with nothing.

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

my $DNSPort    = 18656;
my $WidePort   = 18658;   # a resolver whose answers carry many addresses
my $FirstAddr  = '127.0.0.1';   # port 1984 of the test server answers here
my $SecondAddr = '127.0.0.1';   # the name keeps one address for these tests
my $SwitchIn   = 3600;

# Sends a query and tells whether the test resolver answers it.
# The addresses the wide name stands for. One server line, many peers.
my @Wide = map { sprintf('127.0.%d.%d', int($_ / 250) + 1, $_ % 250 + 1) }
           0 .. 119;

sub dns_ready {
    my ($port) = @_;
    my $sock;

    socket($sock, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or return 0;

    my $to = sockaddr_in($port, inet_aton('127.0.0.1'));
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

# The resolvers run as their own processes: a plain fork of the test is not
# safe on every platform.
my @dns_pids;

for my $r ([$DNSPort, $FirstAddr, $SecondAddr], [$WidePort, $Wide[0], $Wide[0], @Wide[1 .. $#Wide]]) {
    my $pid = fork();

    defined $pid or plan skip_all => "fork() failed: $!";

    if ($pid == 0) {
        my $server = __FILE__;
        $server =~ s{[^/]+$}{dns_server.pl};

        my ($port, @addrs) = @$r;

        exec($^X, $server, $port, $SwitchIn, @addrs) or POSIX::_exit(1);
    }

    push @dns_pids, $pid;
}

END {
    local $?;

    for my $pid (@dns_pids) {
        kill 'TERM', $pid;
        waitpid($pid, 0);
    }
}

for my $port ($DNSPort, $WidePort) {
    plan skip_all => "the test resolver does not answer on 127.0.0.1:$port"
        unless dns_ready($port);
}

plan tests => repeat_each() * 28;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: a backup peer the resolver made is named in the display
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:18656 valid=1s ipv6=off;
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
--- request eval
[
    'GET /up',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'OK',
    qr/"upstreamZones".*"server":"127\.0\.0\.1:1984"(?:(?!"server":).)*"backup":true/s,
]

=== TEST 2: its statistics are counted against that name
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:18656 valid=1s ipv6=off;
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
--- request eval
[
    'GET /up',
    'GET /up',
    'GET /status/format/json',
]
--- response_body_like eval
[
    'OK',
    'OK',
    qr/"server":"127\.0\.0\.1:1984"(?:(?!"server":).)*"requestCounter":2/s,
]

=== TEST 3: the control interface finds it
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:18656 valid=1s ipv6=off;
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
--- request eval
[
    'GET /up',
    "GET /status/control?cmd=status&group=upstream\@group&zone=backend\@127.0.0.1%3A1984",
]
--- response_body_like eval
[
    'OK',
    qr/"server":"127\.0\.0\.1:1984".*"requestCounter":1.*"backup":true/s,
]

=== TEST 4: a backup that does not resolve is still named, and still backup
--- http_config
    vhost_traffic_status_zone;

    upstream backend {
        zone backend 1m;
        server 127.0.0.1:1 down;
        server 127.0.0.1:1984 backup;
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
    qr/"server":"127\.0\.0\.1:1984"(?:(?!"server":).)*"requestCounter":1(?:(?!"server":).)*"backup":true/s,
    qr/"server":"127\.0\.0\.1:1984".*"backup":true/s,
]

=== TEST 5: a primary is not called backup because a backup list exists
--- http_config
    vhost_traffic_status_zone;

    upstream backend {
        zone backend 1m;
        server 127.0.0.1:1984;
        server 127.0.0.1:1 backup;
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
    qr/"server":"127\.0\.0\.1:1984"(?:(?!"server":).)*"backup":false/s,
    qr/"server":"127\.0\.0\.1:1984".*"backup":false/s,
]

=== TEST 6: every peer a wide name stands for is written, none dropped
--- http_config
    vhost_traffic_status_zone;

    resolver 127.0.0.1:18658 valid=1s ipv6=off;
    resolver_timeout 2s;

    upstream wide {
        zone wide 1m;
        server 127.0.0.1:1984;
        server wide.example:1984 resolve backup;
    }
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request eval
[
    'GET /status/format/json',
]
--- response_body_like eval
[
    qr/"server":"127\.0\.1\.120:1984"/s,
]
