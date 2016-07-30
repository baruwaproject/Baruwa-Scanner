#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Quarantine') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Quarantine $Baruwa::Scanner::Quarantine::VERSION, Perl $], $^X"
);

can_ok('Baruwa::Scanner::Quarantine', 'new');

my $qdir = new Baruwa::Scanner::Quarantine;

isa_ok($qdir, 'Baruwa::Scanner::Quarantine');

my ($day, $month, $year) = (localtime)[3, 4, 5];
$month++;
$year += 1900;

is(Baruwa::Scanner::Quarantine::TodayDir(), sprintf("%04d%02d%02d", $year, $month, $day));
