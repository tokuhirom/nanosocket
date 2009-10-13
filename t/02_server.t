use strict;
use warnings;
use Test::TCP;

test_tcp(
    client => sub {
        my $port = shift;
        system './t/02_server_client', $port;
    },
    server => sub {
        my $port = shift;
        exec './t/02_server_server', $port;
    },
);

