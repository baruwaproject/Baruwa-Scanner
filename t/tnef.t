#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use File::Which;
use File::Path qw(remove_tree);
use FindBin '$Bin';
use MIME::Parser;
use Test::More qw(no_plan);
use Baruwa::Scanner();
use Baruwa::Scanner::Mta();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::Message();
use Baruwa::Scanner::FileInto();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Quarantine();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::TNEF') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::TNEF $Baruwa::Scanner::TNEF::VERSION, Perl $], $^X"
);

make_test_dirs();
my $from          = "$Bin/configs/template.conf";
my $conf          = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $conf_internal = "$Bin/data/etc/mail/baruwa/baruwa-tnef-internal.conf";
my $conf_external = "$Bin/data/etc/mail/baruwa/baruwa-tnef-external.conf";
my $datadir       = "$Bin/data";
my $tnef_path     = which('tnef');
$tnef_path = '/usr/bin/tnef' unless ($tnef_path);
my @internal_matches = ('^TNEF Expander = /usr/bin/tnef --maxsize=100000000$');
my @internal_repls   = ('TNEF Expander = internal');
my @external_matches = ('^TNEF Expander = /usr/bin/tnef --maxsize=100000000$');
my @external_repls   = ("TNEF Expander = $tnef_path --maxsize=100000000");
create_config($from, $conf, $datadir);
update_config($conf, $conf_internal, \@internal_matches, \@internal_repls);
update_config(
    $conf, $conf_external,
    \@external_matches,
    \@external_repls
);
Baruwa::Scanner::Config::Read($conf_external, 0);

is($Baruwa::Scanner::TNEF::UseTNEFModule, 0);

my $workarea = new Baruwa::Scanner::WorkArea;
my $inqueue =
  new Baruwa::Scanner::Queue(@{Baruwa::Scanner::Config::Value('inqueuedir')});
my $mta  = new Baruwa::Scanner::Mta;
my $quar = new Baruwa::Scanner::Quarantine;
my $q    = Baruwa::Scanner::Config::Value('inqueuedir');

$global::MS = new Baruwa::Scanner(
    WorkArea   => $workarea,
    InQueue    => $inqueue,
    MTA        => $mta,
    Quarantine => $quar
);
my $msgid = $Test::Baruwa::Scanner::msgs[1];

can_ok('Baruwa::Scanner::TNEF', 'FindTNEFFile');

my ($tnefentity, $tnefname, $msg, $entity);
($msg, $entity) = _parse_msg($msgid);

($tnefentity, $tnefname) = Baruwa::Scanner::TNEF::FindTNEFFile($entity);

is($tnefentity, undef);
is($tnefname,   undef);
$msg->{store}->Unlock();

$msgid = $Test::Baruwa::Scanner::msgs[4];
($msg,        $entity)   = _parse_msg($msgid);
($tnefentity, $tnefname) = Baruwa::Scanner::TNEF::FindTNEFFile($entity);

isa_ok($tnefentity, 'MIME::Entity');
is($tnefname, 'nwinmail.dat');

isnt($msg->{bodymodified}, 1);
is( Baruwa::Scanner::TNEF::Decoder(
        "$workarea->{dir}/$msgid", 'nwinmail.dat', $msg
    ),
    1
);
is($msg->{bodymodified}, 1);
$msg->{store}->Unlock();

my $perms  = $global::MS->{work}->{fileumask} ^ 0777;
my $owner  = $global::MS->{work}->{uid};
my $group  = $global::MS->{work}->{gid};
my $change = $global::MS->{work}->{changeowner};

($msg, $entity) = _parse_msg($msgid);
isnt($msg->{bodymodified}, 1);
is( Baruwa::Scanner::TNEF::ExternalDecoder(
        "$workarea->{dir}/$msgid", 'nwinmail.dat', $msg, $perms, $owner,
        $group, $change
    ),
    1
);
is($msg->{bodymodified}, 1);
$msg->{store}->Unlock();

Baruwa::Scanner::Config::Read($conf_internal, 0);

Baruwa::Scanner::TNEF::initialise();

is($Baruwa::Scanner::TNEF::UseTNEFModule, 1);

($msg, $entity) = _parse_msg($msgid);
isnt($msg->{bodymodified}, 1);
is( Baruwa::Scanner::TNEF::InternalDecoder(
        "$workarea->{dir}/$msgid", 'nwinmail.dat', $msg, $perms, $owner,
        $group, $change
    ),
    1
);
is($msg->{bodymodified}, 1);
$msg->{store}->Unlock();

sub _parse_msg {
    my ($msgid) = @_;
    my $m = new Baruwa::Scanner::Message($msgid, $q->[0], 0);
    my $dir = "$workarea->{dir}/$msgid";
    remove_tree($dir, {keep_root => 0});
    mkdir "$dir", 0777 or die "could not create work dir";
    my $parser = MIME::Parser->new;
    my $filer  = Baruwa::Scanner::FileInto->new($dir);
    MIME::WordDecoder->default->handler(
        '*' => \&Baruwa::Scanner::Message::WordDecoderKeep7Bit);
    $parser->filer($filer);
    $parser->extract_uuencode(1);
    $parser->output_to_core(0);
    my $handle = IO::File->new_tmpfile;
    binmode($handle);
    is($m->{store}->Lock(), 1);
    $m->WriteHeaderFile();
    $m->{store}->ReadMessageHandle($m, $handle);
    $parser->max_parts(200 * 3);
    my $entity = eval {$parser->parse($handle)};
    close($handle);
    $m->{entity} = $entity;
    return ($m, $entity);
}
