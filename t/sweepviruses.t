#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use Test::MockModule;
use Test::More qw(no_plan);
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::SweepViruses') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::SweepViruses $Baruwa::Scanner::SweepViruses::VERSION, Perl $], $^X"
);

make_test_dirs();

my $from           = "$Bin/configs/template.conf";
my $conf           = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $conf_antivirus = "$Bin/data/etc/mail/baruwa/baruwa-antivirus.conf";
my $datadir        = "$Bin/data";
create_config($from, $conf, $datadir);
my @antivirus_matches = ('Virus Scanners = auto');
my @antivirus_repls   = (
    "Virus Scanners = css bitdefender f-prot-6 avastd panda drweb sophos f-secure clamd avast nod32 mcafee6 symscanengine command kaspersky kavdaemonclient f-protd-6 esets trend"
);
update_config($conf, $conf_antivirus, \@antivirus_matches, \@antivirus_repls);
Baruwa::Scanner::Config::Read($conf, 0);

can_ok('Baruwa::Scanner::SweepViruses', 'InitGenericParser');

is(Baruwa::Scanner::SweepViruses::InitGenericParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitSophosParser');

is(Baruwa::Scanner::SweepViruses::InitSophosParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitMcAfee6Parser');

is(Baruwa::Scanner::SweepViruses::InitMcAfee6Parser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitCommandParser');

is(Baruwa::Scanner::SweepViruses::InitCommandParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitKasperskyParser');

is(Baruwa::Scanner::SweepViruses::InitKasperskyParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitKavDaemonClientParser');

is(Baruwa::Scanner::SweepViruses::InitKavDaemonClientParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitFSecureParser');

is(Baruwa::Scanner::SweepViruses::InitFSecureParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitFProt6Parser');

is(Baruwa::Scanner::SweepViruses::InitFProt6Parser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitFProtd6Parser');

is(Baruwa::Scanner::SweepViruses::InitFProtd6Parser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitNOD32Parser');

is(Baruwa::Scanner::SweepViruses::InitNOD32Parser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitPandaParser');

is(Baruwa::Scanner::SweepViruses::InitPandaParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitClamAVModParser');

is(Baruwa::Scanner::SweepViruses::InitClamAVModParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitTrendParser');

is(Baruwa::Scanner::SweepViruses::InitTrendParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitBitdefenderParser');

is(Baruwa::Scanner::SweepViruses::InitBitdefenderParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitDrwebParser');

is(Baruwa::Scanner::SweepViruses::InitDrwebParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitCSSParser');

is(Baruwa::Scanner::SweepViruses::InitCSSParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitSymScanEngineParser');

is(Baruwa::Scanner::SweepViruses::InitSymScanEngineParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitAvastParser');

is(Baruwa::Scanner::SweepViruses::InitAvastParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitAvastdParser');

is(Baruwa::Scanner::SweepViruses::InitAvastdParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'InitesetsParser');

is(Baruwa::Scanner::SweepViruses::InitesetsParser(), 1);

can_ok('Baruwa::Scanner::SweepViruses', 'initialise');

{
    my $InstalledScanners_called = 0;
    my $mod = Test::MockModule->new('Baruwa::Scanner::SweepViruses');
    $mod->mock(
        InstalledScanners => sub {
            $InstalledScanners_called++;
            return qw/f-prot-6 sophos f-secure clamd f-protd-6 esets/;
        }
    );
    Baruwa::Scanner::SweepViruses::initialise();
    is($InstalledScanners_called, 1);

    Baruwa::Scanner::Config::Read($conf_antivirus, 0);
    $InstalledScanners_called = 0;
    Baruwa::Scanner::SweepViruses::initialise();
    is($InstalledScanners_called, 0);
}

can_ok('Baruwa::Scanner::SweepViruses', 'InstalledScanners');

my @installed_scanners = ();
my @returned_scanners  = Baruwa::Scanner::SweepViruses::InstalledScanners();

is(@returned_scanners, @installed_scanners);

{
    my $system_called = 0;
    my $mod = Test::MockModule->new('Baruwa::Scanner::SweepViruses');
    $mod->mock(
        call_system => sub {
            $system_called++;
            return 0;
        }
    );

    my @returned_scanners = Baruwa::Scanner::SweepViruses::InstalledScanners();
    # print STDERR "@returned_scanners\n";
    is($system_called,        6);
    is($returned_scanners[0], 'f-prot-6');
    is($returned_scanners[5], 'esets');
}

# can_ok('Baruwa::Scanner::SweepViruses', 'ScanBatch');
# can_ok('Baruwa::Scanner::SweepViruses', 'MergeReports');
# can_ok('Baruwa::Scanner::SweepViruses', 'TryCommercial');
# can_ok('Baruwa::Scanner::SweepViruses', 'TryOneCommercial');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessClamAVModOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessGenericOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessSophosOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessMcAfee6Output');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessCommandOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessKasperskyOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessKavDaemonClientOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessFSecureOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessFProt6Output');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessNOD32Output');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessPandaOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessDrwebOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessTrendOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessBitdefenderOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessCSSOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessSymScanEngineOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessAvastOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessAvastdOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessesetsOutput');
# can_ok('Baruwa::Scanner::SweepViruses', 'CheckCodeStatus');
# can_ok('Baruwa::Scanner::SweepViruses', 'ClamdScan');
# can_ok('Baruwa::Scanner::SweepViruses', 'ConnectToClamd');
# can_ok('Baruwa::Scanner::SweepViruses', 'ConnectToFpscand');
# can_ok('Baruwa::Scanner::SweepViruses', 'Fprotd6Scan');
# can_ok('Baruwa::Scanner::SweepViruses', 'Fpscand');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessFProtd6Output');
