use inc::Module::Install;

my $e = env_for_c(CCFLAGS => '-g -Wall -Wextra');
if ($e->have_library('ssl')) {
    $e->append(CCFLAGS => '-lssl -DHAVE_SSL', LIBS => ['ssl', 'crypto']);
    $e->test('t/03_ssl', 't/03_ssl.cc');
}
$e->test('t/01_simple', 't/01_simple.cc');
$e->program('eg/client', 'eg/client.cc');
$e->program('eg/server', 'eg/server.cc');

tests 't/*.t t/*/*.t t/*/*/*.t';

test_requires 'Test::TCP';

WriteMakefileForC;
