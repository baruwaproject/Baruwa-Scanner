#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FileHandle;
use FindBin qw/$Bin/;
use lib "$Bin/lib";
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Lock') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Lock $Baruwa::Scanner::Lock::VERSION, Perl $], $^X"
);

SKIP: {
    skip('Only run tests on Linux', 4) unless($^O eq 'linux');
    my $lockhandle = new FileHandle;
    my $filename   = "$Bin/data/var/lock/Baruwa/test-lock";
    is(Baruwa::Scanner::Lock::openlock($lockhandle, '+<' . $filename, 'w', 0), 1);
    # is(Baruwa::Scanner::Lock::openlock($lockhandle, '+<' . $filename, 'w', 0), 0);
    is(Baruwa::Scanner::Lock::unlockclose($lockhandle), 1);
    is(Baruwa::Scanner::Lock::openlock($lockhandle, '+<' . $filename, 'r', 0), 1);
    # is(Baruwa::Scanner::Lock::openlock($lockhandle, '+<' . $filename, 'r', 0), 1);
    is(Baruwa::Scanner::Lock::unlockclose($lockhandle), 1);
}
