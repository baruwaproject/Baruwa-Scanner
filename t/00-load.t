#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);
use FindBin '$Bin';
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner $Baruwa::Scanner::VERSION, Perl $], $^X");
diag("Greating Test directory structures");
make_test_dirs();

my $scanner = new Baruwa::Scanner(
    InQueue    => 'inqueue',
    WorkArea   => 'workarea',
    MTA        => 'exim',
    Quarantine => 'quarantine',
);

isa_ok($scanner, 'Baruwa::Scanner', '$scanner');
is($scanner->{inq}, 'inqueue', 'InQueue is correct');
is($scanner->{work}, 'workarea', 'WorkArea is correct');
is($scanner->{mta}, 'exim', 'MTA is correct');
is($scanner->{quar}, 'quarantine', 'Quarantine is correct');
