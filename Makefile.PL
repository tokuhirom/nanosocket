use inc::Module::Install;
name 'Clib-nanosocket';

clib_setup;

my $e = env_for_c();
$e->enable_warnings();
if (is_win32()) {
    $e->append(LIBS => ['ws2_32']);
}
if ($e->have_library('ssl')) {
    $e->append(LIBS => ['ssl', 'crypto']);
    $e->test('t/03_ssl', 't/03_ssl.cc');
}
$e->test('t/01_simple', 't/01_simple.cc');
$e->program('t/02_server_client', 't/02_server_client.cc');
$e->program('t/02_server_server', 't/02_server_server.cc');

tests 't/*.t t/*/*.t t/*/*/*.t';

clib_header 'nanotap.h';

test_requires 'Test::TCP';
requires 'Clib::nanotap';

WriteMakefileForC;
