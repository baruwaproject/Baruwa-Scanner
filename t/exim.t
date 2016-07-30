#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    require_ok('Baruwa/Scanner/Exim.pm') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::Sendmail $Baruwa::Scanner::Sendmail::VERSION, Perl $], $^X");

can_ok('Baruwa::Scanner::Sendmail', 'new');
