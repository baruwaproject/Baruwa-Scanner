#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    require_ok('Baruwa/Scanner/EximDiskStore.pm') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::SMDiskStore $Baruwa::Scanner::SMDiskStore::VERSION, Perl $], $^X");

can_ok('Baruwa::Scanner::SMDiskStore', 'new');
