#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use Test::More qw(no_plan);
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::ConfigSQL') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::ConfigSQL $Baruwa::Scanner::ConfigSQL::VERSION, Perl $], $^X"
);

make_test_dirs();

my $from    = "$Bin/configs/template.conf";
my $conf    = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $datadir = "$Bin/data";
create_config($from, $conf, $datadir);

can_ok('Baruwa::Scanner::ConfigSQL', 'db_connect');
{
    Baruwa::Scanner::Config::Read($conf, 0);
    is(Baruwa::Scanner::ConfigSQL::db_connect(), undef);
    is(Baruwa::Scanner::ConfigSQL::db_connect($conf), undef);
    # Baruwa::Scanner::Config::SetValue('SQLDebug', 'yes');
    # is(Baruwa::Scanner::ConfigSQL::db_connect($conf), undef);
}

can_ok('Baruwa::Scanner::ConfigSQL', 'QuickPeek');
{
    Baruwa::Scanner::Config::Read($conf, 0);
    is(Baruwa::Scanner::ConfigSQL::QuickPeek(), undef);
    is(Baruwa::Scanner::ConfigSQL::QuickPeek(undef, 'sql'), undef);
    is(Baruwa::Scanner::ConfigSQL::QuickPeek($conf, 'sql'), undef);
}

can_ok('Baruwa::Scanner::ConfigSQL', 'ReadConfBasic');
{
    Baruwa::Scanner::Config::Read($conf, 0);
    is(Baruwa::Scanner::ConfigSQL::ReadConfBasic(), undef);
    is(Baruwa::Scanner::ConfigSQL::ReadConfBasic(undef, 'sql'), undef);
    is(Baruwa::Scanner::ConfigSQL::ReadConfBasic($conf, 'sql'), undef);
}

can_ok('Baruwa::Scanner::ConfigSQL', 'ReadRuleset');
{
    Baruwa::Scanner::Config::Read($conf, 0);
    is(Baruwa::Scanner::ConfigSQL::ReadRuleset(), undef);
}

can_ok('Baruwa::Scanner::ConfigSQL', 'ReturnSpamAssassinConfig');
{
    Baruwa::Scanner::Config::Read($conf, 0);
    is(Baruwa::Scanner::ConfigSQL::ReturnSpamAssassinConfig(), undef);
}

can_ok('Baruwa::Scanner::ConfigSQL', 'CheckForUpdate');
{
    Baruwa::Scanner::Config::Read($conf, 0);
    is(Baruwa::Scanner::ConfigSQL::CheckForUpdate(), undef);
}
