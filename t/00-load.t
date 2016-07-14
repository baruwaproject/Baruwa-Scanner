#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Baruwa::Scanner' ) || print "Bail out!\n";
}

diag( "Testing Baruwa::Scanner $Baruwa::Scanner::VERSION, Perl $], $^X" );
