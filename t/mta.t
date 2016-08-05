#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);
# use FindBin '$Bin';
# use lib "$Bin/lib";
# use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Mta') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::Mta $Baruwa::Scanner::Mta::VERSION, Perl $], $^X");

can_ok('Baruwa::Scanner::Mta', 'new');

my $e = new Baruwa::Scanner::Mta();

isa_ok($e, 'Baruwa::Scanner::Mta', '$e');

can_ok($e, 'initialise');

# is($Baruwa::Scanner::UnsortedBatchesLeft, undef);

$e->initialise();

# is($Baruwa::Scanner::UnsortedBatchesLeft, 0);
