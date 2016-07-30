#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use lib "$Bin/lib";
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Queue') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Queue $Baruwa::Scanner::Queue::VERSION, Perl $], $^X"
);

can_ok('Baruwa::Scanner::Queue', 'new');

my $dir   = "$Bin/data/var/spool/exim.in/input";
my $queue = new Baruwa::Scanner::Queue($dir);

isa_ok($queue, 'Baruwa::Scanner::Queue');

is($queue->{dir}[0], $dir);
