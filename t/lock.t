#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Lock') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::Lock $Baruwa::Scanner::Lock::VERSION, Perl $], $^X");
