use strict;
use warnings;
use Test::TCP;

test_tcp(
    client => sub {
        my $port = shift;
        my $ret = `./t/02_server_client $port`;
        print $ret;
    },
    server => sub {
        my $port = shift;
        exec './t/02_server_server', $port;
    },
);

