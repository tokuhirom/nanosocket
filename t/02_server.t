use strict;
use warnings;
use Test::TCP;

test_tcp(
    client => sub {
        my $port = shift;
        my $ret = `./eg/client $port`;
        print $ret;
    },
    server => sub {
        my $port = shift;
        exec './eg/server', $port;
    },
);

