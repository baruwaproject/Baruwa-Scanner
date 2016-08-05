use v5.10;
use strict;
use warnings;
use Module::Build;
use File::Find::Rule;
# use Data::Dumper qw(Dumper);

sub find_files {
    my ($dirname) = @_;
    my (%content, @content);
    @content = File::Find::Rule->file()->in($dirname);
    @content{@content} = @content;
    return \%content;
}

my $builder = Module::Build->new(
    module_name         => 'Baruwa::Scanner',
    dist_abstract       => 'Baruwa::Scanner',
    license             => 'gpl_3',
    dist_author         => q{Andrew Colin Kissa <andrew@topdog.za.net>},
    dist_version        => '4.86.0',
    # dist_version_from   => 'lib/Baruwa/Scanner.pm',
    # release_status      => 'testing',
    etc_files           => find_files('etc'),
    sbin_files          => find_files('sbin'),
    sql_files           => find_files('sql'),
    wrapper_files       => find_files('wrapper'),
    configure_requires => {
        'File::Find::Rule' => 0,
        'Module::Build' => 0,
    },
    build_requires => {
        'Test::More' => 0,
    },
    test_requires => {
        'Devel::Cover' => 0,
        'Test::Exception' => 0,
        'File::Touch' => 0,
        'File::NCopy' => 0,
        'File::Path' => 0,
        'Test::Output' => 0,
    },
    requires => {
        'Archive::Zip' => 0,
        'Carp' => 0,
        'CDB_File' => 0,
        'Compress::Zlib' => 0,
        'Convert::BinHex' => 0,
        'Convert::TNEF' => 0,
        'Data::Dumper' => 0,
        'Date::Parse' => 0,
        'DBD::SQLite' => 0,
        'DBI' => 0,
        'Digest::MD5' => 0,
        'DirHandle' => 0,
        'Fcntl' => 0,
        'File::Basename' => 0,
        'File::Copy' => 0,
        'File::FcntlLock::XS' => 0,
        'FileHandle' => 0,
        'File::Path' => 0,
        'File::Temp' => 0,
        'Filesys::Df' => 0,
        'Getopt::Long' => 0,
        'HTML::Entities' => 0,
        'HTML::Parser' => 0,
        'HTML::TokeParser' => 0,
        'IO' => '> 1.23',
        'IO::File' => 0,
        'IO::Pipe' => 0,
        'Mail::Header' => 0,
        'Mail::SpamAssassin' => 0,
        'Mail::SPF' => '2.8.0',
        'MIME::Base64' => 0,
        'MIME::Decoder' => 0,
        'MIME::Decoder::UU' => 0,
        'MIME::Head' => 0,
        'MIME::Parser' => 0,
        'MIME::QuotedPrint' => 0,
        'MIME::Tools' => '>= 5.427, < 5.500',
        'NetAddr::IP' => '>= 4.010',
        'Net::DNS' => '>= 0.34',
        'Net::DNS::Resolver::Programmable' => 0,
        'Net::CIDR' => 0,
        'Net::LDAP' => 0,
        'OLE::Storage_Lite' => 0,
        'POSIX' => 0,
        'Socket' => 0,
        'Sys::Hostname::Long' => 0,
        'Sys::SigAction' => 0,
        'Sys::Syslog' => 0,
        'Time::HiRes' => 0,
        'Time::localtime' => 0,
    },
    add_to_cleanup     => [ 'Baruwa-Scanner-*' ],
    # create_makefile_pl => 'traditional',
);
# print Dumper $builder;
$builder->install_path(etc => '/etc');
$builder->install_path(sbin => '/usr/sbin');
$builder->install_path(sql => '/usr/share/Baruwa/sql');
$builder->install_path(wrapper => '/usr/libexec/Baruwa');
$builder->add_build_element('pl');
$builder->add_build_element('etc');
$builder->add_build_element('sql');
$builder->add_build_element('sbin');
$builder->add_build_element('wrapper');
$builder->create_build_script();
