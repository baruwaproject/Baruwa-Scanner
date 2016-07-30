#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::MessageBatch') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::MessageBatch $Baruwa::Scanner::MessageBatch::VERSION, Perl $], $^X");

can_ok('Baruwa::Scanner::MessageBatch', 'new');
