#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::SweepOther') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::SweepOther $Baruwa::Scanner::SweepOther::VERSION, Perl $], $^X");

can_ok('Baruwa::Scanner::SweepOther', 'ScanBatch');

can_ok('Baruwa::Scanner::SweepOther', 'CheckFileContentTypes');

can_ok('Baruwa::Scanner::SweepOther', 'CheckFileTypesRules');
