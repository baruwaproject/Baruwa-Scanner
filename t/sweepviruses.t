#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use File::Touch;
use FindBin '$Bin';
use Test::Exception;
use Test::MockModule;
use Test::MockObject;
use File::Path qw(make_path);
use Test::More qw(no_plan);
use Baruwa::Scanner();
use Baruwa::Scanner::Mta();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Quarantine();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    my ($tcp_socket) = Test::MockObject->new;
    $tcp_socket->fake_module('IO::Socket::INET');
    $tcp_socket->fake_new('IO::Socket::INET');
    $tcp_socket->set_false('connected');
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
my @antivirus_repls =
  ("Virus Scanners = f-prot-6 sophos f-secure clamd f-protd-6 esets");
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

can_ok('Baruwa::Scanner::SweepViruses', 'CheckCodeStatus');

foreach (qw/0 1 2 3/) {
    throws_ok {Baruwa::Scanner::SweepViruses::CheckCodeStatus($_)}
    qr/Baruwa is unable to start at/,
      'Throws error if incorrect code support configured';
}

is(Baruwa::Scanner::SweepViruses::CheckCodeStatus(4), 1);

# mocks
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

my @installed_scanners = ('f-protd-6');
my @returned_scanners  = Baruwa::Scanner::SweepViruses::InstalledScanners();

is(@returned_scanners, @installed_scanners);

{
    my $system_called = 0;
    my $mod           = Test::MockModule->new('Baruwa::Scanner::SweepViruses');
    $mod->mock(
        call_system => sub {
            $system_called++;
            return 0;
        }
    );

    my @returned_scanners = Baruwa::Scanner::SweepViruses::InstalledScanners();
    is($system_called,        6);
    is($returned_scanners[0], 'f-protd-6');
    is($returned_scanners[5], 'esets');
}

can_ok('Baruwa::Scanner::SweepViruses', 'ConnectToClamd');

{
    my $sock =
      Baruwa::Scanner::SweepViruses::ConnectToClamd(1, '127.0.0.1', 3310, 10);
    isnt($sock, undef);
}

can_ok('Baruwa::Scanner::SweepViruses', 'ConnectToFpscand');

{
    my $sock =
      Baruwa::Scanner::SweepViruses::ConnectToFpscand(1, '127.0.0.1', 10200,
        10);
    isnt($sock, undef);
}

can_ok('Baruwa::Scanner::SweepViruses', 'ScanBatch');

{
    my $workarea = new Baruwa::Scanner::WorkArea;
    my $inqueue =
      new Baruwa::Scanner::Queue(
        @{Baruwa::Scanner::Config::Value('inqueuedir')});
    my $mta  = new Baruwa::Scanner::Mta;
    my $quar = new Baruwa::Scanner::Quarantine;
    my $q    = Baruwa::Scanner::Config::Value('inqueuedir');
    $global::MS = new Baruwa::Scanner(
        WorkArea   => $workarea,
        InQueue    => $inqueue,
        MTA        => $mta,
        Quarantine => $quar
    );

    Baruwa::Scanner::SweepViruses::initialise();
    is(Baruwa::Scanner::SweepViruses::ScanBatch(), 0);
    my $mod = Test::MockModule->new('Baruwa::Scanner::SweepViruses');
    $mod->mock(
        TryCommercial => sub {
            return 'ScAnNeRfAiLeD';
        }
    );
    my $batch = Test::MockObject->new;
    $batch->fake_new('Baruwa::Scanner::MessageBatch');
    $batch->set_true('DropBatch');
    is(Baruwa::Scanner::SweepViruses::ScanBatch($batch), 1);
    is($batch->called('DropBatch'),                      1);
    my ($reportref, $typeref);
    $mod->mock(
        TryCommercial => sub {
            return '';
        },
        MergeReports => sub {
            ($reportref, $typeref) = @_;
        }
    );
    my $called = 0;
    my $log    = Test::MockModule->new('Baruwa::Scanner::Log');
    $log->mock(
        WarnLog => sub {
            $called++;
        }
    );
    my $msgid = $Test::Baruwa::Scanner::msgs[1];
    make_path("$workarea->{dir}/$msgid", {mode => 0700});
    is(Baruwa::Scanner::SweepViruses::ScanBatch($batch), 0);
    is($batch->called('DropBatch'),                      1);
    is($called,                                          3);
    is(exists $reportref->{$msgid},                      1);

    # can_ok('Baruwa::Scanner::SweepViruses', 'Fpscand');

    # my @files = (
    #     "$workarea->{dir}/$msgid/message.txt",
    #     "$workarea->{dir}/$msgid/attach.doc"
    # );
    # touch(@files);
    # my $scanned = 0;
    # my $sock = Test::MockObject->new;
    # $sock->fake_module('FileHandle');
    # $sock->fake_new('FileHandle');
    # $sock->set_true(->mock(print => sub {
    #     $scanned++;
    # });
    # Baruwa::Scanner::SweepViruses::Fpscand("$workarea->{dir}/$msgid", $sock);
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
# can_ok('Baruwa::Scanner::SweepViruses', 'ClamdScan');
# can_ok('Baruwa::Scanner::SweepViruses', 'ConnectToFpscand');
# can_ok('Baruwa::Scanner::SweepViruses', 'Fprotd6Scan');
# can_ok('Baruwa::Scanner::SweepViruses', 'Fpscand');
# can_ok('Baruwa::Scanner::SweepViruses', 'ProcessFProtd6Output');
