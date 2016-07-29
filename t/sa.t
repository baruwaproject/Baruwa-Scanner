#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::SA') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::SA $Baruwa::Scanner::SA::VERSION, Perl $], $^X");
