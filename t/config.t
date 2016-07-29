#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Config') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::Config $Baruwa::Scanner::Config::VERSION, Perl $], $^X");

# is(Baruwa::Scanner::Config::Value('runasuser'), 'exim', 'The default runasuser is exim');
