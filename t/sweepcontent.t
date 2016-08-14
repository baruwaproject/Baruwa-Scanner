#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::SweepContent') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::SweepContent $Baruwa::Scanner::SweepContent::VERSION, Perl $], $^X");

can_ok('Baruwa::Scanner::SweepContent', 'ScanBatch');

can_ok('Baruwa::Scanner::SweepContent', 'FixMaliciousSubjects');

can_ok('Baruwa::Scanner::SweepContent', 'CheckAttachmentSizes');

can_ok('Baruwa::Scanner::SweepContent', 'FindPartialMessage');

can_ok('Baruwa::Scanner::SweepContent', 'LastEntity');

can_ok('Baruwa::Scanner::SweepContent', 'FindHTMLExploits');

can_ok('Baruwa::Scanner::SweepContent', 'SearchHTMLBody');

can_ok('Baruwa::Scanner::SweepContent', 'FindExternalBody');

can_ok('Baruwa::Scanner::SweepContent', 'EncryptionStatus');

can_ok('Baruwa::Scanner::SweepContent', 'ExtractPublicKeys');

can_ok('Baruwa::Scanner::SweepContent', 'SavePublicKey');

can_ok('Baruwa::Scanner::SweepContent', 'FixSubstringBoundaries');
