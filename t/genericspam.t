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

my $g = new Baruwa::Scanner::GenericSpam();

isa_ok($g, 'Baruwa::Scanner::GenericSpam', '$g');
