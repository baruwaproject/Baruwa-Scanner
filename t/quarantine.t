#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use File::Path qw(remove_tree);
use Test::More qw(no_plan);
use Baruwa::Scanner();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::WorkArea();
require "Baruwa/Scanner/Exim.pm";
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Quarantine') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Quarantine $Baruwa::Scanner::Quarantine::VERSION, Perl $], $^X"
);

make_test_dirs();
my $from    = "$Bin/configs/template.conf";
my $conf    = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $datadir = "$Bin/data";
create_config($from, $conf, $datadir);
Baruwa::Scanner::Config::Read($conf, 0);

can_ok('Baruwa::Scanner::Quarantine', 'new');

my $qdir = new Baruwa::Scanner::Quarantine;

isa_ok($qdir, 'Baruwa::Scanner::Quarantine');

my ($day, $month, $year) = (localtime)[3, 4, 5];
$month++;
$year += 1900;

my $today = sprintf("%04d%02d%02d", $year, $month, $day);

is(Baruwa::Scanner::Quarantine::TodayDir(), $today);

my $workarea = new Baruwa::Scanner::WorkArea;
my $inqueue =
  new Baruwa::Scanner::Queue(@{Baruwa::Scanner::Config::Value('inqueuedir')});
my $mta = new Baruwa::Scanner::Sendmail;
my $q   = Baruwa::Scanner::Config::Value('inqueuedir');

$global::MS = new Baruwa::Scanner(
    WorkArea   => $workarea,
    InQueue    => $inqueue,
    MTA        => $mta,
    Quarantine => $qdir
);
my $msgid = $Test::Baruwa::Scanner::msgs[1];
my $m     = new Baruwa::Scanner::Message($msgid, $q->[0], 0);
my $qbase = Baruwa::Scanner::Config::Value('quarantinedir', $m);
my $dir   = "$workarea->{dir}/$msgid";
mkdir "$dir", 0777 or die "could not create work dir";
$m->WriteHeaderFile();
$m->Explode();

can_ok($qdir, 'StoreInfections');

remove_tree("$qbase/$today", {keep_root => 0});

isnt(-d "$qbase/$today", 1);

$qdir->StoreInfections($m);

is(-d "$qbase/$today", 1);

is(-f "$qbase/$today/$msgid/message", 1);

is($m->{quarantineplaces}[0], "$qbase/$today/$msgid");

remove_tree("$qbase", {keep_root => 0});

isnt(-d "$qbase/$today", 1);

$qdir->StoreInfections($m);

is(-d "$qbase/$today", 1);

is($m->{quarantineplaces}[0], "$qbase/$today/$msgid");
