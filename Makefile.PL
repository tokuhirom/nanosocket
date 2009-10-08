use inc::Module::Install;
use Module::Install::ForC;

my $e = env_for_c(CCFLAGS => '-g -Wall -Wextra');
$e->program('t/01_simple', 't/01_simple.cc');

WriteMakefileForC;
