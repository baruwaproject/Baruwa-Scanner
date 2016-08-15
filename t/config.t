#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use Test::Output;
use Test::Exception;
use Test::MockModule;
use Test::More qw(no_plan);
use File::Path qw(remove_tree);
use Baruwa::Scanner();
use Baruwa::Scanner::Mta();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::Message();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Quarantine();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    my $mock = Test::MockModule->new('Baruwa::Scanner::Config');
    $mock->mock(
        _gethostbyaddr => sub {
            print STDERR "I was called\n";
            return 'fuzzylumpkins.home.topdog-software.com';
        }
    );
    use_ok('Baruwa::Scanner::Config') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Config $Baruwa::Scanner::Config::VERSION, Perl $], $^X"
);

make_test_dirs();

my $from    = "$Bin/configs/template.conf";
my $conf    = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $datadir = "$Bin/data";
create_config($from, $conf, $datadir);
my $conf1 = "$Bin/configs/no-db.conf";
my $conf2 = "$Bin/configs/non-exist.conf";

can_ok('Baruwa::Scanner::Config', 'QuickPeek');
is(Baruwa::Scanner::Config::QuickPeek($conf1, 'mta'),
    'exim', 'QuickPeek succeeds');

is(Baruwa::Scanner::Config::QuickPeek($conf1, 'mailheader'),
    'X-BaruwaTest-BaruwaFW:', 'Percent variable replacement works');

can_ok('Baruwa::Scanner::Config', 'ReadConfFile');
is(Baruwa::Scanner::Config::ReadConfFile($conf1), 0, 'I can call ReadConfFile');

throws_ok {Baruwa::Scanner::Config::ReadConfFile($conf2)}
qr/Could not read configuration file/,
  'Throws error if configuration does not exist';

can_ok('Baruwa::Scanner::Config', 'ReadData');
is(Baruwa::Scanner::Config::ReadData($conf1, 0), '', 'I can call ReadData');

throws_ok {Baruwa::Scanner::Config::ReadData($conf2)}
qr/Could not read configuration file/,
  'Throws error if configuration does not exist';

is(Baruwa::Scanner::Config::Read($conf, 0),
    0, 'I can read a configuration file');

can_ok('Baruwa::Scanner::Config', 'SpamLists');
is(Baruwa::Scanner::Config::SpamLists('baruwa-dbl'),
    'dbl.rbl.baruwa.net.', 'I can read RBL configs');

can_ok('Baruwa::Scanner::Config', 'ScannerCmds');
is( Baruwa::Scanner::Config::ScannerCmds('sophos'),
    '/usr/libexec/Baruwa/sophos-wrapper,/opt/sophos-av',
    'I can read virus scanners'
);

can_ok('Baruwa::Scanner::Config', 'LanguageValue');
is(Baruwa::Scanner::Config::LanguageValue(undef, 'baruwa'), 'Baruwa');

can_ok('Baruwa::Scanner::Config', 'PrintFixedWidth');
is(Baruwa::Scanner::Config::PrintFixedWidth('TEST', 6), 'TEST  ');
is(Baruwa::Scanner::Config::PrintFixedWidth('TEST', 4), 'TEST ');

open(POSTCONFIG, '>', "$Bin/data/etc/mail/baruwa/dynamic/rules/local.scores")
  or die "failed to create local.scores file";
print POSTCONFIG
  "score           BASE_BARUWAHASHDB                       15.0\n";
close(POSTCONFIG);
$Baruwa::Scanner::ConfigSQL::ConfFile = $conf;
can_ok('Baruwa::Scanner::Config', 'SpamAssassinPostConfig');
my @rules = Baruwa::Scanner::Config::SpamAssassinPostConfig();
is($rules[0], 'score           BASE_BARUWAHASHDB                       15.0');

my $langfile = "$Bin/data/etc/mail/baruwa/reports/en/languages.conf";
can_ok('Baruwa::Scanner::Config', 'ReadOneLanguageStringsFile');
my $langs = Baruwa::Scanner::Config::ReadOneLanguageStringsFile($langfile);
is($langs->{'theentiremessage'}, 'the entire message');

can_ok('Baruwa::Scanner::Config', 'Default');
Baruwa::Scanner::Config::Default('clamdlockFile', '/tmp/clamd.lock');
is(Baruwa::Scanner::Config::Value('clamdlockFile'), '/tmp/clamd.lock');

can_ok('Baruwa::Scanner::Config', 'Read');

TODO: {
    local $TODO = 'Skip tests until i figure this out';
    Baruwa::Scanner::Config::Read($conf, 1);
    output_like(
        sub {Baruwa::Scanner::Config::PrintNonDefaults();},
        qr/notifysenders                      yes            no/,
        qr/notifysenders                      yes            no/
    );
}

my $countryfile = "$Bin/data/etc/mail/baruwa/country.domains.conf";
can_ok('Baruwa::Scanner::Config', 'ReadCountryDomainList');
Baruwa::Scanner::Config::ReadCountryDomainList($countryfile);
my %countries = %Baruwa::Scanner::Config::SecondLevelDomainExists;
is($countries{'com.ac'}, 1);

can_ok('Baruwa::Scanner::Config', 'SetValue');
Baruwa::Scanner::Config::SetValue('clamdlockFile', '/tmp/clamd.lock');
is(Baruwa::Scanner::Config::Value('clamdlockFile'), '/tmp/clamd.lock');

can_ok('Baruwa::Scanner::Config', 'OverrideInQueueDirs');
Baruwa::Scanner::Config::OverrideInQueueDirs('/tmp');
my $qdirs = Baruwa::Scanner::Config::Value('inqueuedir');
is($qdirs->[0], '/tmp');

Baruwa::Scanner::Config::Read($conf, 0);
my $workarea = new Baruwa::Scanner::WorkArea;
my $inqueue =
  new Baruwa::Scanner::Queue(@{Baruwa::Scanner::Config::Value('inqueuedir')});
my $mta  = new Baruwa::Scanner::Mta;
my $quar = new Baruwa::Scanner::Quarantine;
my $q    = Baruwa::Scanner::Config::Value('inqueuedir');

$global::MS = new Baruwa::Scanner(
    WorkArea   => $workarea,
    InQueue    => $inqueue,
    MTA        => $mta,
    Quarantine => $quar
);

{
    my $msgid = $Test::Baruwa::Scanner::msgs[1];
    my $m     = _parse_msg($msgid);
    can_ok('Baruwa::Scanner::Config', 'GetClientHostname');
    is(Baruwa::Scanner::Config::GetClientHostname($m, 'h'), '');
    is(Baruwa::Scanner::Config::GetClientHostname($m, 'H'), '');
    $m->{clienthostname}        = '192.168.1.1';
    $m->{clienthostnamenocheck} = '192.168.1.1';
    is(Baruwa::Scanner::Config::GetClientHostname($m, 'h'), '192.168.1.1');
    is(Baruwa::Scanner::Config::GetClientHostname($m, 'H'), '192.168.1.1');
    $m->{store}->Unlock();
}

can_ok('Baruwa::Scanner::Config', 'FirstMatchValue');
{
    my ($direction, $iporaddr, $regexp2, $value, $name, $tooverride);
    my $msgid = $Test::Baruwa::Scanner::msgs[1];
    my $m     = _parse_msg($msgid);
    $m->{allreports}{""} = "message was infected: EICAR";
    $iporaddr            = 't';
    $direction           = 'v';
    $regexp2             = qr/EICAR/;
    $value               = 'yes';

    # use Data::Dumper;
    # print STDERR "XXXXX=>".Dumper($m)."\n";
    _match_virus($direction, $iporaddr, $regexp2, $value, $name, $m,
        $tooverride);

    $direction = 'b';
    is( Baruwa::Scanner::Config::FirstMatchValue(
            $direction, $iporaddr, $regexp2, $value, $name, $m, $tooverride
        ),
        'CoNfIgFoUnDnOtHiNg'
    );
    $regexp2    = qr/andrew\@home\.topdog-software\.com/;
    $tooverride = 'andrew@home.topdog-software.com';
    is( Baruwa::Scanner::Config::FirstMatchValue(
            $direction, $iporaddr, $regexp2, $value, $name, $m, $tooverride
        ),
        $value
    );
    $direction  = 'f';
    $tooverride = undef;
    is( Baruwa::Scanner::Config::FirstMatchValue(
            $direction, $iporaddr, $regexp2, $value, $name, $m, $tooverride
        ),
        $value
    );
    $direction = 't';
    is( Baruwa::Scanner::Config::FirstMatchValue(
            $direction, $iporaddr, $regexp2, $value, $name, $m, $tooverride
        ),
        'CoNfIgFoUnDnOtHiNg'
    );
    $regexp2 = qr/angel\@home\.topdog-software\.com/;
    is( Baruwa::Scanner::Config::FirstMatchValue(
            $direction, $iporaddr, $regexp2, $value, $name, $m, $tooverride
        ),
        $value
    );
    $tooverride = 'andrew@home.topdog-software.com';
    $regexp2    = qr/andrew\@home\.topdog-software\.com/;
    is( Baruwa::Scanner::Config::FirstMatchValue(
            $direction, $iporaddr, $regexp2, $value, $name, $m, $tooverride
        ),
        $value
    );
    $m->{store}->Unlock();

    $iporaddr            = 'd';
    $direction           = 'v';
    $regexp2             = qr/EICAR/;
    $tooverride          = undef;
    $m                   = _parse_msg($msgid);
    $m->{allreports}{""} = "message was infected: EICAR";
    _match_virus($direction, $iporaddr, $regexp2, $value, $name, $m,
        $tooverride);
    $direction = 'f';
    is( Baruwa::Scanner::Config::FirstMatchValue(
            $direction, $iporaddr, $regexp2, $value, $name, $m, $tooverride
        ),
        'CoNfIgFoUnDnOtHiNg'
    );
    my @regexes = (
        '192\.168\.1\.52', '192\.168\.1\.',
        '192\.168\.1',     '192\.168\.',
        '192\.168',        '192\.',
        '192'
    );

    my $mock    = Test::MockModule->new('Baruwa::Scanner::Log');
    my $called  = 0;
    my $counter = 0;
    $mock->mock(
        WarnLog => sub {
            $called++;
        }
    );
    foreach my $rx (@regexes) {
        $regexp2 = qr/$rx/;
        is( Baruwa::Scanner::Config::FirstMatchValue(
                $direction, $iporaddr, $regexp2, $value,
                $name,      $m,        $tooverride
            ),
            $value
        );
        $direction = 't';
        is( Baruwa::Scanner::Config::FirstMatchValue(
                $direction, $iporaddr, $regexp2, $value,
                $name,      $m,        $tooverride
            ),
            'CoNfIgFoUnDnOtHiNg'
        );
        $counter++;
        is($called, $counter);
        $direction = 'f';
    }

    $direction = 'v';
    $called    = 0;
    $counter   = 0;
    foreach my $ioa (qw/h H/) {
        is( Baruwa::Scanner::Config::FirstMatchValue(
                $direction, $ioa, $regexp2, $value, $name, $m, $tooverride
            ),
            'CoNfIgFoUnDnOtHiNg'
        );
        $counter++;
        is($called, $counter);
    }
    foreach my $ioa (qw/h H/) {
        foreach my $dir_ (qw/t b/) {
            is( Baruwa::Scanner::Config::FirstMatchValue(
                    $dir_, $ioa, $regexp2, $value, $name, $m, $tooverride
                ),
                'CoNfIgFoUnDnOtHiNg'
            );
        }
    }
    $m->{store}->Unlock();

    $iporaddr            = 'c';
    $direction           = 'v';
    $m                   = _parse_msg($msgid);
    $m->{allreports}{""} = "message was infected: EICAR";
    _match_virus($direction, $iporaddr, $regexp2, 'CoNfIgFoUnDnOtHiNg', $name,
        $m, $tooverride);
    $regexp2 = qr/EICAR/;
    _match_virus($direction, $iporaddr, $regexp2, $value, $name, $m,
        $tooverride);

    $direction = 'f';
    my @addrs = (
        '192.0.0.0/8',    '192.168.0.0/16',
        '192.168.1.0/25', '192.168.1.0/24',
        '192.168.1.52/32'
    );
    foreach my $rx (@addrs) {
        is( Baruwa::Scanner::Config::FirstMatchValue(
                $direction, $iporaddr, $rx, $value, $name, $m, $tooverride
            ),
            $value
        );
    }
    is( Baruwa::Scanner::Config::FirstMatchValue(
            $direction, $iporaddr, '192.168.1.0/52', $value,
            $name,      $m,        $tooverride
        ),
        'CoNfIgFoUnDnOtHiNg'
    );
    foreach my $dir_ (qw/t b/) {
        is( Baruwa::Scanner::Config::FirstMatchValue(
                $dir_, $iporaddr, $regexp2, $value, $name, $m, $tooverride
            ),
            'CoNfIgFoUnDnOtHiNg'
        );
    }
    $m->{store}->Unlock();
}

can_ok('Baruwa::Scanner::Config', 'initialise');

can_ok('Baruwa::Scanner::Config', 'SetPercent');

can_ok('Baruwa::Scanner::Config', 'EndCustomFunctions');

can_ok('Baruwa::Scanner::Config', 'NFilenameRulesValue');

can_ok('Baruwa::Scanner::Config', 'AFilenameRulesValue');

can_ok('Baruwa::Scanner::Config', 'FilenameRulesValue');

can_ok('Baruwa::Scanner::Config', 'NFiletypeRulesValue');

can_ok('Baruwa::Scanner::Config', 'AFiletypeRulesValue');

can_ok('Baruwa::Scanner::Config', 'FiletypeRulesValue');

can_ok('Baruwa::Scanner::Config', 'ReadConfBasicLDAP');

can_ok('Baruwa::Scanner::Config', 'DisconnectLDAP');

can_ok('Baruwa::Scanner::Config', 'LDAPUpdated');

can_ok('Baruwa::Scanner::Config', 'LDAPFetchSerial');

can_ok('Baruwa::Scanner::Config', 'CallCustomAction');

sub _parse_msg {
    my ($msgid) = @_;
    my $m = new Baruwa::Scanner::Message($msgid, $q->[0], 0);
    my $dir = "$workarea->{dir}/$msgid";
    remove_tree($dir, {keep_root => 0});
    mkdir "$dir", 0777 or die "could not create work dir";
    my $parser = MIME::Parser->new;
    my $filer  = Baruwa::Scanner::FileInto->new($dir);
    MIME::WordDecoder->default->handler(
        '*' => \&Baruwa::Scanner::Message::WordDecoderKeep7Bit);
    $parser->filer($filer);
    $parser->extract_uuencode(1);
    $parser->output_to_core(0);
    my $handle = IO::File->new_tmpfile;
    binmode($handle);
    is($m->{store}->Lock(), 1);
    $m->WriteHeaderFile();
    $m->{store}->ReadMessageHandle($m, $handle);
    $parser->max_parts(200 * 3);
    my $entity = eval {$parser->parse($handle)};
    close($handle);
    $m->{entity} = $entity;
    return $m;
}

sub _match_virus {
    my ($direction, $iporaddr, $regexp2, $value, $name, $m, $tooverride) = @_;
    is( Baruwa::Scanner::Config::FirstMatchValue(
            $direction, $iporaddr, $regexp2, $value, $name, $m, $tooverride
        ),
        $value
    );
}
