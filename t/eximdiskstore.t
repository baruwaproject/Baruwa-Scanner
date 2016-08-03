#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use Test::Output;
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

make_test_dirs();

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
my $q    = Baruwa::Scanner::Config::Value('inqueuedir');
my $oq   = Baruwa::Scanner::Config::Value('outqueuedir');

$global::MS = new Baruwa::Scanner(
    WorkArea   => $workarea,
    InQueue    => $inqueue,
    MTA        => $mta,
    Quarantine => $quar
);

my $s =
  new Baruwa::Scanner::SMDiskStore($Test::Baruwa::Scanner::msgs[0], $q->[0]);
#
isa_ok($s, 'Baruwa::Scanner::SMDiskStore', '$s');

can_ok($s, 'print');

stderr_like(sub {$s->print();}, qr/1bUUOQ-0000g4-C7-D/, qr/1bUUOQ-0000g4-C7-D/);

can_ok($s, 'Lock');

is($s->Lock(), 1);

can_ok($s, 'Unlock');

is($s->Unlock(), 1);

can_ok($s, 'Delete');

is(-f $s->{'hpath'}, 1);
is(-f $s->{'dpath'}, 1);

$s->Delete();

isnt(-f $s->{'hpath'}, 1);
isnt(-f $s->{'dpath'}, 1);

make_test_dirs();

my $msgid = $Test::Baruwa::Scanner::msgs[0];

$s = new Baruwa::Scanner::SMDiskStore($msgid, $q->[0]);

can_ok($s, 'OutQDir');

is($s->OutQDir(), '/');

can_ok($s, 'OutQName');

is(Baruwa::Scanner::SMDiskStore::OutQName($oq, $s->{hname}),
    $oq . '/' . $s->{'hname'});

can_ok($s, 'LinkData');

isnt(-e "$Bin/data/var/spool/exim/input/$msgid-D", 1);

$s->LinkData($oq);

is(-e "$Bin/data/var/spool/exim/input/$msgid-D", 1);

can_ok($s, 'WriteHeader');

# isnt(-e "$Bin/data/var/spool/exim/input/$msgid-H", 1);

# $s->WriteHeader()

is(-f $s->{'hpath'}, 1);
is(-f $s->{'dpath'}, 1);

$s->DeleteUnlock();

isnt(-f $s->{'hpath'}, 1);
isnt(-f $s->{'dpath'}, 1);
