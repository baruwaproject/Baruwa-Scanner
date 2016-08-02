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
    require_ok('Baruwa/Scanner/Exim.pm') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::Sendmail $Baruwa::Scanner::Sendmail::VERSION, Perl $], $^X");

can_ok('Baruwa::Scanner::Sendmail', 'new');

my $e = new Baruwa::Scanner::Sendmail();

isa_ok($e, 'Baruwa::Scanner::Sendmail', '$e');

can_ok($e, 'initialise');

# is($Baruwa::Scanner::UnsortedBatchesLeft, undef);

$e->initialise();

# is($Baruwa::Scanner::UnsortedBatchesLeft, 0);
