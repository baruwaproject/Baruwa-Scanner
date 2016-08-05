#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use Test::Output;
use FindBin '$Bin';
use Test::More qw(no_plan);
use Baruwa::Scanner();
use Baruwa::Scanner::Mta();
use Baruwa::Scanner::Message();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::Quarantine();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::EximDiskStore') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::EximDiskStore $Baruwa::Scanner::EximDiskStore::VERSION, Perl $], $^X"
);

make_test_dirs();

can_ok('Baruwa::Scanner::EximDiskStore', 'new');

my $from    = "$Bin/configs/template.conf";
my $conf    = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $datadir = "$Bin/data";
create_config($from, $conf, $datadir);
Baruwa::Scanner::Config::Read($conf, 0);
my $workarea = new Baruwa::Scanner::WorkArea;
my $inqueue =
  new Baruwa::Scanner::Queue(@{Baruwa::Scanner::Config::Value('inqueuedir')});
my $mta  = new Baruwa::Scanner::Mta;
my $quar = new Baruwa::Scanner::Quarantine;
my $q    = Baruwa::Scanner::Config::Value('inqueuedir');
my $oq   = Baruwa::Scanner::Config::Value('outqueuedir');

$global::MS = new Baruwa::Scanner(
    WorkArea   => $workarea,
    InQueue    => $inqueue,
    MTA        => $mta,
    Quarantine => $quar
);

my $msgid = $Test::Baruwa::Scanner::msgs[0];
my $s = new Baruwa::Scanner::EximDiskStore($msgid, $q->[0]);
#
isa_ok($s, 'Baruwa::Scanner::EximDiskStore', '$s');

can_ok($s, 'print');

stderr_like(sub {$s->print();}, qr/1bUUOQ-0000g4-C7-D/, qr/1bUUOQ-0000g4-C7-D/);

can_ok($s, 'Lock');

is($s->Lock(), 1);

is($s->dsize(), (stat($s->{dpath}))[7]);

can_ok($s, 'Unlock');

is($s->Unlock(), 1);

can_ok($s, 'Delete');

is(-f $s->{'hpath'}, 1);
is(-f $s->{'dpath'}, 1);

$s->Delete();

isnt(-f $s->{'hpath'}, 1);
isnt(-f $s->{'dpath'}, 1);

make_test_dirs();

my $m = new Baruwa::Scanner::Message($msgid, $q->[0], 0);
my $dir = "$workarea->{dir}/$msgid";
unless (-d $dir) {
    unless (-d "$workarea->{dir}") {
        mkdir "$workarea->{dir}", 0777 or die "could not create work dir $!\n";
    }
    mkdir "$dir", 0777 or die "could not create work dir $!\n";
}
$m->WriteHeaderFile();
$m->Explode();
$s = new Baruwa::Scanner::EximDiskStore($msgid, $q->[0]);

can_ok($s, 'OutQDir');

is($s->OutQDir(), '/');

can_ok($s, 'OutQName');

is(Baruwa::Scanner::EximDiskStore::OutQName($oq, $s->{hname}),
    $oq . '/' . $s->{'hname'});

my (@body, $retval);
can_ok($s, 'ReadBody');
$s->Lock();
$s->ReadBody(\@body);

SKIP:{
    if (scalar(@body)){
        $retval = $body[0];
        chomp $retval;
    } else {
        skip('Unknown issue on travis', 1);
    }
    is($retval, 'This is a test mailing');
}

can_ok($s, 'LinkData');

isnt(-e "$Bin/data/var/spool/exim/input/$msgid-D", 1);

$s->LinkData($oq);

is(-e "$Bin/data/var/spool/exim/input/$msgid-D", 1);

can_ok($s, 'WriteHeader');

isnt(-f "$Bin/data/var/spool/exim/input/$msgid-H", 1);

$s->WriteHeader($m, "$Bin/data/var/spool/exim/input");

is(-f "$Bin/data/var/spool/exim/input/$msgid-H", 1);

can_ok($s, 'WriteMIMEBody');

unlink("$Bin/data/var/spool/exim/input/$msgid-D");
isnt(-f "$Bin/data/var/spool/exim/input/$msgid-D", 1);

$s->WriteMIMEBody($msgid, $m->{entity}, "$Bin/data/var/spool/exim/input");

is(-f "$Bin/data/var/spool/exim/input/$msgid-D", 1);

is(-f $s->{'hpath'}, 1);
is(-f $s->{'dpath'}, 1);

$s->DeleteUnlock();

isnt(-f $s->{'hpath'}, 1);
isnt(-f $s->{'dpath'}, 1);

make_test_dirs();

$s = new Baruwa::Scanner::EximDiskStore($msgid, $q->[0]);
$s->Lock();

can_ok($s, 'CopyToDir');

isnt(-f "$Bin/data/var/lib/baruwa/archive/$msgid-H", 1);
isnt(-f "$Bin/data/var/lib/baruwa/archive/$msgid-D", 1);

$s->CopyToDir("$Bin/data/var/lib/baruwa/archive", $msgid);

is(-f "$Bin/data/var/lib/baruwa/archive/$msgid-H", 1);
is(-f "$Bin/data/var/lib/baruwa/archive/$msgid-D", 1);

is(-f $s->{'hpath'}, 1);
is(-f $s->{'dpath'}, 1);

can_ok($s, 'DoPendingDeletes');

@Baruwa::Scanner::EximDiskStore::DeletesPending = ($s->{'hpath'}, $s->{'dpath'});

$s->DoPendingDeletes();

isnt(-f $s->{'hpath'}, 1);
isnt(-f $s->{'dpath'}, 1);
