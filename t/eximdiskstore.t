#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use Test::More qw(no_plan);
use Baruwa::Scanner();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::Quarantine();
require "Baruwa/Scanner/Exim.pm";
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    require_ok('Baruwa/Scanner/EximDiskStore.pm') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::SMDiskStore $Baruwa::Scanner::SMDiskStore::VERSION, Perl $], $^X"
);

can_ok('Baruwa::Scanner::SMDiskStore', 'new');

my $from    = "$Bin/configs/template.conf";
my $conf    = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $datadir = "$Bin/data";
create_config($from, $conf, $datadir);
Baruwa::Scanner::Config::Read($conf, 0);
my $workarea = new Baruwa::Scanner::WorkArea;
my $inqueue =
  new Baruwa::Scanner::Queue(@{Baruwa::Scanner::Config::Value('inqueuedir')});
my $mta  = new Baruwa::Scanner::Sendmail;
my $quar = new Baruwa::Scanner::Quarantine;

$global::MS = new Baruwa::Scanner(
    WorkArea   => $workarea,
    InQueue    => $inqueue,
    MTA        => $mta,
    Quarantine => $quar
);

my $s = new Baruwa::Scanner::SMDiskStore();
#
isa_ok($s, 'Baruwa::Scanner::SMDiskStore', '$s');
