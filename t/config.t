#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use Test::Exception;
use Test::More qw(no_plan);
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Config') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Config $Baruwa::Scanner::Config::VERSION, Perl $], $^X"
);

my $from = "$Bin/configs/template.conf";
my $conf = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $datadir = "$Bin/data";
create_config($from, $conf, $datadir);
my $conf1 = "$Bin/configs/no-db.conf";
my $conf2 = "$Bin/configs/non-exist.conf";

is(Baruwa::Scanner::Config::QuickPeek($conf1, 'mta'),
    'exim', 'QuickPeek succeeds');

is(Baruwa::Scanner::Config::QuickPeek($conf1, 'mailheader'),
    'X-BaruwaTest-BaruwaFW:', 'Percent variable replacement works');

is(Baruwa::Scanner::Config::ReadConfFile($conf1), 0, 'I can call ReadConfFile');

throws_ok {Baruwa::Scanner::Config::ReadConfFile($conf2)} qr/Could not read configuration file/, 'Throws error if configuration does not exist';

is(Baruwa::Scanner::Config::ReadData($conf1, 0), '', 'I can call ReadData');

throws_ok {Baruwa::Scanner::Config::ReadData($conf2)} qr/Could not read configuration file/, 'Throws error if configuration does not exist';

is(Baruwa::Scanner::Config::Read($conf, 0), 0, 'I can read a configuration file');

is(Baruwa::Scanner::Config::SpamLists('baruwa-dbl'), 'dbl.rbl.baruwa.net.', 'I can read RBL configs');

is(Baruwa::Scanner::Config::ScannerCmds('sophos'), '/usr/libexec/Baruwa/sophos-wrapper,/opt/sophos-av', 'I can read virus scanners');

is(Baruwa::Scanner::Config::LanguageValue(undef, 'baruwa'), 'Baruwa');

is(Baruwa::Scanner::Config::PrintFixedWidth('TEST', 6), 'TEST  ');

is(Baruwa::Scanner::Config::PrintFixedWidth('TEST', 4), 'TEST ');
