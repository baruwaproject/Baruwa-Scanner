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