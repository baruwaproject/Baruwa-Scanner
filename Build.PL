use 5.006;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Baruwa::Scanner',
    license             => 'gpl_3',
    dist_author         => q{Andrew Colin Kissa <andrew@topdog.za.net>},
    dist_version_from   => 'lib/Baruwa/Scanner.pm',
    release_status      => 'testing',
    configure_requires => {
        'Module::Build' => 0,
    },
    build_requires => {
        'Test::More' => 0,
    },
    requires => {
        #'ABC'              => 1.6,
        #'Foo::Bar::Module' => 5.0401,
    },
    add_to_cleanup     => [ 'Baruwa-Scanner-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
