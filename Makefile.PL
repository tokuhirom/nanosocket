use inc::Module::Install;

my $e = env_for_c(CPPPATH => ['extlib/']);
$e->enable_warnings();
if (is_windows()) {
	$e->append(LIBS => ['ws2_32']);
}
if ($e->have_library('ssl')) {
    $e->append(CCFLAGS => '-DHAVE_SSL', LIBS => ['ssl', 'crypto']);
    $e->test('t/03_ssl', 't/03_ssl.cc');
}
$e->test('t/01_simple', 't/01_simple.cc');
$e->program('t/02_server_client', 't/02_server_client.cc');
$e->program('t/02_server_server', 't/02_server_server.cc');

tests 't/*.t t/*/*.t t/*/*/*.t';

test_requires 'Test::TCP';

WriteMakefileForC;
