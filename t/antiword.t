#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

BEGIN {
    use_ok('Baruwa::Scanner::Antiword') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::Antiword $Baruwa::Scanner::Antiword::VERSION, Perl $], $^X");

can_ok('Baruwa::Scanner::Antiword', 'new');

my $a = new Baruwa::Scanner::Antiword();

isa_ok($a, 'Baruwa::Scanner::Antiword', '$a');
