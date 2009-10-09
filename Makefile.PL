use inc::Module::Install;
use Module::Install::ForC;

my $e = env_for_c(CCFLAGS => '-g -Wall -Wextra');
$e->test('t/01_simple', 't/01_simple.cc');
$e->program('eg/client', 'eg/client.cc');
$e->program('eg/server', 'eg/server.cc');

tests 't/*.t t/*/*.t t/*/*/*.t';

test_requires 'Test::TCP';

WriteMakefileForC;
