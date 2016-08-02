#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use Test::Output;
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

my $from    = "$Bin/configs/template.conf";
my $conf    = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $datadir = "$Bin/data";
create_config($from, $conf, $datadir);
my $conf1 = "$Bin/configs/no-db.conf";
my $conf2 = "$Bin/configs/non-exist.conf";

is(Baruwa::Scanner::Config::QuickPeek($conf1, 'mta'),
    'exim', 'QuickPeek succeeds');

is(Baruwa::Scanner::Config::QuickPeek($conf1, 'mailheader'),
    'X-BaruwaTest-BaruwaFW:', 'Percent variable replacement works');

is(Baruwa::Scanner::Config::ReadConfFile($conf1), 0, 'I can call ReadConfFile');

throws_ok {Baruwa::Scanner::Config::ReadConfFile($conf2)}
qr/Could not read configuration file/,
  'Throws error if configuration does not exist';

is(Baruwa::Scanner::Config::ReadData($conf1, 0), '', 'I can call ReadData');

throws_ok {Baruwa::Scanner::Config::ReadData($conf2)}
qr/Could not read configuration file/,
  'Throws error if configuration does not exist';

is(Baruwa::Scanner::Config::Read($conf, 0),
    0, 'I can read a configuration file');

is(Baruwa::Scanner::Config::SpamLists('baruwa-dbl'),
    'dbl.rbl.baruwa.net.', 'I can read RBL configs');

is( Baruwa::Scanner::Config::ScannerCmds('sophos'),
    '/usr/libexec/Baruwa/sophos-wrapper,/opt/sophos-av',
    'I can read virus scanners'
);

is(Baruwa::Scanner::Config::LanguageValue(undef, 'baruwa'), 'Baruwa');

is(Baruwa::Scanner::Config::PrintFixedWidth('TEST', 6), 'TEST  ');

is(Baruwa::Scanner::Config::PrintFixedWidth('TEST', 4), 'TEST ');

open(POSTCONFIG, '>', "$Bin/data/etc/mail/baruwa/dynamic/rules/local.scores")
  or die "failed to create local.scores file";
print POSTCONFIG
  "score           BASE_BARUWAHASHDB                       15.0\n";
close(POSTCONFIG);
$Baruwa::Scanner::ConfigSQL::ConfFile = $conf;
my @rules = Baruwa::Scanner::Config::SpamAssassinPostConfig();
is($rules[0], 'score           BASE_BARUWAHASHDB                       15.0');

my $langfile = "$Bin/data/etc/mail/baruwa/reports/en/languages.conf";
my $langs    = Baruwa::Scanner::Config::ReadOneLanguageStringsFile($langfile);
is($langs->{'theentiremessage'}, 'the entire message');

Baruwa::Scanner::Config::Default('clamdlockFile', '/tmp/clamd.lock');
is(Baruwa::Scanner::Config::Value('clamdlockFile'), '/tmp/clamd.lock');

TODO: {
    local $TODO = 'Skip tests until i figure this out';
    Baruwa::Scanner::Config::Read($conf, 1);
    output_like(sub {Baruwa::Scanner::Config::PrintNonDefaults();},
        qr/notifysenders                      yes            no/,
        qr/notifysenders                      yes            no/
    );
}

my $countryfile = "$Bin/data/etc/mail/baruwa/country.domains.conf";
Baruwa::Scanner::Config::ReadCountryDomainList($countryfile);
my %countries = %Baruwa::Scanner::Config::SecondLevelDomainExists;
is($countries{'com.ac'}, 1);

Baruwa::Scanner::Config::SetValue('clamdlockFile', '/tmp/clamd.lock');
is(Baruwa::Scanner::Config::Value('clamdlockFile'), '/tmp/clamd.lock');

Baruwa::Scanner::Config::OverrideInQueueDirs('/tmp');
my $qdirs = Baruwa::Scanner::Config::Value('inqueuedir');
is($qdirs->[0], '/tmp');

