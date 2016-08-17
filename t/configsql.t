#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use Test::Exception;
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

my $from             = "$Bin/configs/template.conf";
my $conf             = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $conf_sql         = "$Bin/data/etc/mail/baruwa/baruwa-sql.conf";
my $conf_sql_fail    = "$Bin/data/etc/mail/baruwa/baruwa-sql-fail.conf";
my $conf_sql_fail_qp = "$Bin/data/etc/mail/baruwa/baruwa-sql-fail-qp.conf";
my $datadir          = "$Bin/data";
create_config($from, $conf, $datadir);
my @configsql_matches = (
    '^Local DB DSN =$',
    '^SQL Serial Number =$',
    '^SQL Quick Peek =$',
    '^SQL Config =$',
    '^SQL Ruleset =$',

    # '^SQL Debug = no$',
);
my @configsql_reps = (
    "Local DB DSN = DBI:SQLite:dbname=$Bin/data/var/lib/baruwa/data/db/baruwa2.db",
    "SQL Serial Number = SELECT MAX(value) AS confserialnumber FROM quickpeek WHERE internal='confserialnumber'",
    "SQL Quick Peek = SELECT value FROM quickpeek WHERE LOWER(external) = ? AND (hostname = ? OR hostname='default') LIMIT 1",
    "SQL Config = SELECT internal, value, hostname FROM quickpeek WHERE hostname=? OR hostname='default'",
    "SQL Ruleset = SELECT row_number, ruleset AS rule FROM msrulesets WHERE name=?",

    # "SQL Debug = yes",
);
my @configsql_fail_matches = (
    "Local DB DSN = DBI:SQLite:dbname=$Bin/data/var/lib/baruwa/data/db/baruwa2.db"
);
my @configsql_fail_reps = (
    "Local DB DSN = DBI:SQLite:dbname=$Bin/data/var/lib/baruwa/datax/db/baruwa2.db"
);
my @configsql_fail_qp_matches = ("SELECT value FROM quickpeek WHERE LOWER");
my @configsql_fail_qp_reps    = ("SELECT value FROM quickpeekz WHERE LOWER");
update_config($conf, $conf_sql, \@configsql_matches, \@configsql_reps);
update_config($conf_sql, $conf_sql_fail, \@configsql_fail_matches,
    \@configsql_fail_reps);
update_config($conf_sql, $conf_sql_fail_qp, \@configsql_fail_qp_matches,
    \@configsql_fail_qp_reps);

can_ok('Baruwa::Scanner::ConfigSQL', 'db_connect');
{
    is(Baruwa::Scanner::ConfigSQL::db_connect(),      undef);
    is(Baruwa::Scanner::ConfigSQL::db_connect($conf), undef);
    throws_ok {Baruwa::Scanner::ConfigSQL::db_connect($conf_sql_fail)}
    qr/Database connection error/,
      'Throws error if db connection fails';
    isnt(Baruwa::Scanner::ConfigSQL::db_connect($conf_sql), undef);
}

can_ok('Baruwa::Scanner::ConfigSQL', 'QuickPeek');
{
    is(Baruwa::Scanner::ConfigSQL::QuickPeek(), undef);
    is(Baruwa::Scanner::ConfigSQL::QuickPeek(undef, 'sql'), undef);
    is(Baruwa::Scanner::ConfigSQL::QuickPeek($conf, 'sql'), undef);
    is( Baruwa::Scanner::ConfigSQL::QuickPeek(
            $conf_sql, 'logpermittedfiletypes'
        ),
        'yes'
    );
    is(Baruwa::Scanner::ConfigSQL::QuickPeek($conf_sql, 'mailheader'), undef);

    # Baruwa::Scanner::ConfigSQL::QuickPeek($conf_sql_fail_qp, 'mailheader');
}

can_ok('Baruwa::Scanner::ConfigSQL', 'ReadConfBasic');
{
    is(Baruwa::Scanner::ConfigSQL::ReadConfBasic(), undef);
    is(Baruwa::Scanner::ConfigSQL::ReadConfBasic(undef, 'sql'), undef);
    is(Baruwa::Scanner::ConfigSQL::ReadConfBasic($conf, 'sql'), undef);
    my (%File, %BaruwaCustomVars);
    isnt(exists $File{'logpermittedfiletypes'}, 1);
    is(Baruwa::Scanner::ConfigSQL::ReadConfBasic($conf_sql, \%File, \%BaruwaCustomVars), undef);
    is(exists $File{'logpermittedfiletypes'}, 1);
    is($File{'logpermittedfiletypes'}, 'yes');
}

can_ok('Baruwa::Scanner::ConfigSQL', 'ReadRuleset');
{
    is(Baruwa::Scanner::ConfigSQL::ReadRuleset(), undef);
}

can_ok('Baruwa::Scanner::ConfigSQL', 'ReturnSpamAssassinConfig');
{
    is(Baruwa::Scanner::ConfigSQL::ReturnSpamAssassinConfig(), undef);
}

can_ok('Baruwa::Scanner::ConfigSQL', 'CheckForUpdate');
{
    is(Baruwa::Scanner::ConfigSQL::CheckForUpdate(), 0);
}
