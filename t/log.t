#!/usr/bin/env perl -T
use v5.10;
use strict;
use warnings;
use Test::Output;
use Test::MockModule;
use Test::More qw(no_plan);

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Log') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::Log $Baruwa::Scanner::Log::VERSION, Perl $], $^X"
);

can_ok('Baruwa::Scanner::Log', 'Configure');

Baruwa::Scanner::Log::Configure('TestBanner', 'file');

is($Baruwa::Scanner::Log::Banner,  'TestBanner');
is($Baruwa::Scanner::Log::LogType, 'file');

Baruwa::Scanner::Log::Configure('TestBanner');

is($Baruwa::Scanner::Log::LogType, 'syslog');

is($Baruwa::Scanner::Log::WarningsOnly, 0);

can_ok('Baruwa::Scanner::Log', 'WarningsOnly');

Baruwa::Scanner::Log::WarningsOnly();

is($Baruwa::Scanner::Log::WarningsOnly, 1);

can_ok('Baruwa::Scanner::Log', 'Start');

Baruwa::Scanner::Log::Start('Andrew', 'info');

is($Baruwa::Scanner::Log::name,     'Andrew');
is($Baruwa::Scanner::Log::facility, 'info');
is($Baruwa::Scanner::Log::logsock,  'unix');

Baruwa::Scanner::Log::Start('Andrew', 'info', 'tcp');
is($Baruwa::Scanner::Log::logsock, 'tcp');

{
    can_ok('Baruwa::Scanner::Log', 'Reset');
    my $mod        = Test::MockModule->new('Sys::Syslog');
    my $setlogsock = 0;
    my $openlog    = 0;
    my $closelog   = 0;
    my $syslog     = 0;
    $mod->mock(
        setlogsock => sub {
            $setlogsock++;
        },
        openlog => sub {
            $openlog++;
        },
        closelog => sub {
            $closelog++;
        },
        syslog => sub {
            $syslog++;
        }
    );
    Baruwa::Scanner::Log::Reset();
    is($openlog,    1);
    is($setlogsock, 1);

    can_ok('Baruwa::Scanner::Log', 'Stop');
    Baruwa::Scanner::Log::Stop();
    is($closelog, 1);

    Baruwa::Scanner::Log::LogText('test');
    is($syslog, 1);
    Baruwa::Scanner::Log::Configure('TestBanner', 'file');
    Baruwa::Scanner::Log::LogText('test');
    is($syslog, 1);

    my $config = Test::MockModule->new('Baruwa::Scanner::Config');
    $config->mock(
        Value => sub {
            return 1;
        }
    );
    Baruwa::Scanner::Log::Configure('TestBanner', 'stderr');
    can_ok('Baruwa::Scanner::Log', 'DebugLog');
    stderr_like(
        sub {Baruwa::Scanner::Log::DebugLog('Test log message');},
        qr/Test log message/,
        qr/Test log message/
    );
}

