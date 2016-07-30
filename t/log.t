#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Log') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::Log $Baruwa::Scanner::Log::VERSION, Perl $], $^X");

Baruwa::Scanner::Log::Configure('TestBanner', 'file');

is($Baruwa::Scanner::Log::Banner, 'TestBanner');
is($Baruwa::Scanner::Log::LogType, 'file');

Baruwa::Scanner::Log::Configure('TestBanner');

is($Baruwa::Scanner::Log::LogType, 'syslog');

is($Baruwa::Scanner::Log::WarningsOnly, 0);

Baruwa::Scanner::Log::WarningsOnly();

is($Baruwa::Scanner::Log::WarningsOnly, 1);

Baruwa::Scanner::Log::Start('Andrew', 'info');

is($Baruwa::Scanner::Log::name, 'Andrew');
is($Baruwa::Scanner::Log::facility, 'info');
is($Baruwa::Scanner::Log::logsock, 'unix');

Baruwa::Scanner::Log::Start('Andrew', 'info', 'tcp');
is($Baruwa::Scanner::Log::logsock, 'tcp');
