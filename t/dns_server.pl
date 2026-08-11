#!/usr/bin/env perl

# A resolver for the tests that need nginx to re-resolve an upstream server.
# It answers every A query with one address and gives the second address once
# `switch` seconds have passed, so that the peers of an upstream group get
# replaced while the test is running.
#
# Any address after the second one is added to every answer, for the tests that
# need a name to stand for more peers than the server line that holds it.
#
# usage: dns_server.pl <port> <switch> <first address> <second address> [more]

use strict;
use warnings;

use Socket;

my ($port, $switch, $first, $second, @rest) = @ARGV;

die "usage: $0 <port> <switch> <first address> <second address>\n"
    unless defined $second;

# Returns the offset just after the question section, -1 when the message does
# not hold a whole question.
sub question_end {
    my ($msg) = @_;

    my $len = length($msg);
    my $pos = 12;

    while ($pos < $len) {
        my $n = ord(substr($msg, $pos, 1));

        return -1 if $n > 63;   # a question holds no compression pointer

        $pos += $n + 1;

        if ($n == 0) {
            return $pos + 4 <= $len ? $pos + 4 : -1;
        }
    }

    return -1;
}

my $sock;

socket($sock, PF_INET, SOCK_DGRAM, getprotobyname('udp'))
    or die "socket() failed: $!\n";

setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, 1);

bind($sock, sockaddr_in($port, inet_aton('127.0.0.1')))
    or die "cannot bind 127.0.0.1:$port: $!\n";

my $started = time();

while (1) {
    my $query;
    my $from = recv($sock, $query, 512, 0);

    next unless defined $from;
    next if length($query) < 12;

    my ($id, undef, $qdcount) = unpack('n3', $query);

    next unless $qdcount == 1;

    my $end = question_end($query);

    next if $end < 0;

    my ($qtype) = unpack('n', substr($query, $end - 4, 2));
    my $question = substr($query, 12, $end - 12);

    my $answer  = '';
    my $ancount = 0;

    if ($qtype == 1) {          # A
        my $address = (time() - $started) >= $switch ? $second : $first;

        for my $a ($address, @rest) {
            # name pointer, type A, class IN, ttl, rdlength, address
            $answer .= pack('n n n N n a4', 0xc00c, 1, 1, 1, 4,
                            inet_aton($a));
            $ancount++;
        }
    }

    # id, flags (response, recursion available), section counts
    my $response = pack('n n n n n n', $id, 0x8180, 1, $ancount, 0, 0)
                   . $question . $answer;

    send($sock, $response, 0, $from);
}

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
