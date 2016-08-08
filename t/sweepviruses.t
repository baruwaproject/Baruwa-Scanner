#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::SweepViruses') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::SweepViruses $Baruwa::Scanner::SweepViruses::VERSION, Perl $], $^X");

can_ok('Baruwa::Scanner::SweepViruses', 'initialise');
can_ok('Baruwa::Scanner::SweepViruses', 'ScanBatch');
can_ok('Baruwa::Scanner::SweepViruses', 'MergeReports');
can_ok('Baruwa::Scanner::SweepViruses', 'TryCommercial');
can_ok('Baruwa::Scanner::SweepViruses', 'TryOneCommercial');
can_ok('Baruwa::Scanner::SweepViruses', 'InitGenericParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitSophosParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitMcAfee6Parser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitCommandParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitKasperskyParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitKavDaemonClientParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitFSecureParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitFProt6Parser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitFProtd6Parser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitNOD32Parser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitPandaParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitClamAVModParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitTrendParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitBitdefenderParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitDrwebParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitCSSParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitSymScanEngineParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitAvastParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitAvastdParser');
can_ok('Baruwa::Scanner::SweepViruses', 'InitesetsParser');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessClamAVModOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessGenericOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessSophosOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessMcAfee6Output');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessCommandOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessKasperskyOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessKavDaemonClientOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessFSecureOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessFProt6Output');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessNOD32Output');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessPandaOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessDrwebOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessTrendOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessBitdefenderOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessCSSOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessSymScanEngineOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessAvastOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessAvastdOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessesetsOutput');
can_ok('Baruwa::Scanner::SweepViruses', 'InstalledScanners');
can_ok('Baruwa::Scanner::SweepViruses', 'CheckCodeStatus');
can_ok('Baruwa::Scanner::SweepViruses', 'ClamdScan');
can_ok('Baruwa::Scanner::SweepViruses', 'ConnectToClamd');
can_ok('Baruwa::Scanner::SweepViruses', 'ConnectToFpscand');
can_ok('Baruwa::Scanner::SweepViruses', 'Fprotd6Scan');
can_ok('Baruwa::Scanner::SweepViruses', 'Fpscand');
can_ok('Baruwa::Scanner::SweepViruses', 'ProcessFProtd6Output');
