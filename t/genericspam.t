#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::GenericSpam') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::GenericSpam $Baruwa::Scanner::GenericSpam::VERSION, Perl $], $^X");

can_ok('Baruwa::Scanner::GenericSpam', 'Checks');

can_ok('Baruwa::Scanner::GenericSpam', 'GSForkAndTest');
