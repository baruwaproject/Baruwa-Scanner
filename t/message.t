#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use Digest::MD5;
use Test::Output;
use FindBin '$Bin';
use Test::MockModule;
use Test::More qw(no_plan);
use File::Path qw(remove_tree);
use Baruwa::Scanner();
use Baruwa::Scanner::SA();
use Baruwa::Scanner::Mta();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Quarantine();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Message') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Message $Baruwa::Scanner::Message::VERSION, Perl $], $^X"
);

make_test_dirs();

can_ok('Baruwa::Scanner::Message', 'new');

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

$global::MS = new Baruwa::Scanner(
    WorkArea   => $workarea,
    InQueue    => $inqueue,
    MTA        => $mta,
    Quarantine => $quar
);

my @msgs = @Test::Baruwa::Scanner::msgs;

my $msgid1 = $msgs[0];
my $msgid2 = $msgs[4];
my $msgid3 = $msgs[5];
my $msgid4 = $msgs[3];
my $msgid5 = $msgs[2];
my $msgid6 = $msgs[1];

foreach (@msgs) {
    my $lmsgid = $_;
    my $m = new Baruwa::Scanner::Message($_, $q->[0], 0);
    isa_ok($m, 'Baruwa::Scanner::Message', '$m');
    my $f = new Baruwa::Scanner::Message($_, $q->[0], 0);
    is($f, undef, 'Test locking of a message');

    can_ok('Baruwa::Scanner::Message', 'PrintInfections');
    stderr_like(
        sub {Baruwa::Scanner::Message::PrintInfections($m);},
        qr/All reports for/,
        qr/All reports for/
    );

    my $mshmackey = Baruwa::Scanner::Config::Value('mshmac',      $m);
    my $mshamcexp = Baruwa::Scanner::Config::Value('mshmacvalid', $m);
    my $date      = time();
    my $expiry    = time() + $mshamcexp;
    can_ok('Baruwa::Scanner::Message', 'createHMAC');
    my $hash =
      Baruwa::Scanner::Message::createHMAC($expiry,
        $m->{fromuser} . "\@" . $m->{fromdomain},
        $date, $mshmackey, $lmsgid);
    is( Digest::MD5::md5_base64(
            join("\$\%", $expiry, $date, $mshmackey, $lmsgid)
          ) eq $hash,
        1
    );
    my $check = "$expiry\@$hash";
    $date = time();
    can_ok('Baruwa::Scanner::Message', 'checkHMAC');
    is( Baruwa::Scanner::Message::checkHMAC(
            $check, $m->{fromuser} . "\@" . $m->{fromdomain},
            $date, $mshmackey, $lmsgid
        ),
        1
    );

    # print STDERR "STRUP=> $m->{needsstripping}\n";
    can_ok('Baruwa::Scanner::Message', 'DropFromBatch');
    isnt(exists $m->{deleted},      1);
    isnt(exists $m->{gonefromdisk}, 1);
    isnt(exists $m->{abandoned},    1);
    Baruwa::Scanner::Message::DropFromBatch($m);
    is($m->{deleted},      1);
    is($m->{gonefromdisk}, 1);
    is($m->{abandoned},    1);
}

can_ok('Baruwa::Scanner::Message', 'CountParts');

my ($msg, $entity);

_count_parts($msgid1, 0);
_count_parts($msgid2, 2);

can_ok('Baruwa::Scanner::Message', 'DeliverModifiedBody');

isnt(-f "$Bin/data/var/spool/exim/input/$msgid1-D", 1);
isnt(-f "$Bin/data/var/spool/exim/input/$msgid1-D", 1);

($msg, $entity) = _parse_msg($msgid1);

$msg->DeliverModifiedBody('cleanheader');

is(-f "$Bin/data/var/spool/exim/input/$msgid1-D", 1);
is(-f "$Bin/data/var/spool/exim/input/$msgid1-H", 1);

can_ok('Baruwa::Scanner::Message', 'DeliverUnmodifiedBody');
isnt(-f "$Bin/data/var/spool/exim/input/$msgid2-D", 1);
isnt(-f "$Bin/data/var/spool/exim/input/$msgid2-H", 1);
($msg, $entity) = _parse_msg($msgid2);
$msg->DeliverUnmodifiedBody('cleanheader');
is(-f "$Bin/data/var/spool/exim/input/$msgid2-D", 1);
is(-f "$Bin/data/var/spool/exim/input/$msgid2-H", 1);

($msg, $entity) = _parse_msg($msgid3);

can_ok('Baruwa::Scanner::Message', 'ArchiveToFilesystem');
my $todaydir = $msg->{datenumber};
isnt(-f "$Bin/data/var/lib/baruwa/archive/$todaydir/$msgid3-D", 1);
isnt(-f "$Bin/data/var/lib/baruwa/archive/$todaydir/$msgid3-H", 1);
is($msg->ArchiveToFilesystem(),                               1);
is(-f "$Bin/data/var/lib/baruwa/archive/$todaydir/$msgid3-D", 1);
is(-f "$Bin/data/var/lib/baruwa/archive/$todaydir/$msgid3-H", 1);

can_ok('Baruwa::Scanner::Message', 'AppendToMbox');
isnt(-f "$Bin/data/var/lib/baruwa/archive/mboxes/mbox", 1);
isnt(-f "$Bin/data/var/lib/baruwa/archive/mboxes/mbox", 1);
$msg->AppendToMbox("$Bin/data/var/lib/baruwa/archive/mboxes/mbox");
is(-f "$Bin/data/var/lib/baruwa/archive/mboxes/mbox", 1);
is(-f "$Bin/data/var/lib/baruwa/archive/mboxes/mbox", 1);

can_ok('Baruwa::Scanner::Message', 'DeleteMessage');
isnt($msg->{deleted},   1);
isnt($msg->{abandoned}, 0);
$msg->DeleteMessage();
is($msg->{deleted},   1);
is($msg->{abandoned}, 0);

can_ok('Baruwa::Scanner::Message', 'DeleteAllRecipients');
($msg, $entity) = _parse_msg($msgid4);
isnt(scalar @{$msg->{to}},       0);
isnt(scalar @{$msg->{touser}},   0);
isnt(scalar @{$msg->{todomain}}, 0);
Baruwa::Scanner::Message::DeleteAllRecipients($msg);
is(scalar @{$msg->{to}},       0);
is(scalar @{$msg->{touser}},   0);
is(scalar @{$msg->{todomain}}, 0);

can_ok('Baruwa::Scanner::Message', 'QuarantineDOS');
($msg, $entity) = _parse_msg($msgid5);
isnt(exists $msg->{quarantinedinfections}, 1);
isnt(
    -f "$Bin/data/var/spool/baruwa/quarantine/$msg->{datenumber}/$msgid5/message",
    1
);
Baruwa::Scanner::Message::QuarantineDOS($msg);
is(exists $msg->{quarantinedinfections}, 1);
is($msg->{quarantinedinfections},        1);
is( -f "$Bin/data/var/spool/baruwa/quarantine/$msg->{datenumber}/$msgid5/message",
    1
);

{
    can_ok('Baruwa::Scanner::Message', 'DeliverUninfected');
    my $mod                 = Test::MockModule->new('Baruwa::Scanner::Message');
    my $DeliverModifiedBody = 0;
    my $DeliverUnmodifiedBody = 0;
    $mod->mock(
        DeliverModifiedBody => sub {
            $DeliverModifiedBody++;
        },
        DeliverUnmodifiedBody => sub {
            $DeliverUnmodifiedBody++;
        }
    );
    ($msg, $entity) = _parse_msg($msgid6);
    $msg->DeliverUninfected();
    is($DeliverUnmodifiedBody, 1);
    $msg->{store}->Unlock();
    ($msg, $entity) = _parse_msg($msgid6);
    $msg->{bodymodified} = 1;
    $msg->DeliverUninfected();
    is($DeliverModifiedBody, 1);
    $msg->{store}->Unlock();
    can_ok('Baruwa::Scanner::Message', 'DeliverCleaned');
    ($msg, $entity) = _parse_msg($msgid6);
    $msg->DeliverCleaned();
    is($DeliverModifiedBody, 2);
    $msg->{store}->Unlock();
}

can_ok('Baruwa::Scanner::Message', 'DeleteFile');
$workarea->ClearAll();
my $m = new Baruwa::Scanner::Message($msgid6, $q->[0], 0);
my $dir = "$workarea->{dir}/$msgid6";
unless (-e "$dir") {
    mkdir "$dir", 0777 or die "could not create work dir: $dir => $!";
}
$m->WriteHeaderFile();
$m->Explode();
is(-f "$workarea->{dir}/1bUvRz-0001Mr-4W/nkudzu.doc", 1);
$msg->DeleteFile('nkudzu.doc');
isnt(-f "$workarea->{dir}/1bUvRz-0001Mr-4W/nkudzu.doc", 1);

$workarea->ClearAll();
remove_tree("$Bin/data/var/spool/baruwa/quarantine", {keep_root => 1});

can_ok('Baruwa::Scanner::Message', 'CleanLinkURL');
my ($linkurl, $alarm);

($linkurl, $alarm) = Baruwa::Scanner::Message::CleanLinkURL('');
is($linkurl, '');
is($alarm,   0);

foreach (
    qw/andrew@baruwa.com mailto:andrew@baruwa.com file:\/\/\/home\/andrew\/testfile/
  ) {
    ($linkurl, $alarm) = Baruwa::Scanner::Message::CleanLinkURL($_);
    is($linkurl, '');
    is($alarm,   0);
}

($linkurl, $alarm) = Baruwa::Scanner::Message::CleanLinkURL('#baruwa-settings');
is($linkurl, '');
is($alarm,   0);

($linkurl, $alarm) = Baruwa::Scanner::Message::CleanLinkURL('baruwa.com.');
is($linkurl, 'baruwa.com');
is($alarm,   0);

foreach (
    qw/http:\/\/www.baruwa.com http:\/\/www.baruwa.com:80 https:\/\/www.baruwa.com ftp:\/\/www.baruwa.com webcal:\/\/www.baruwa.com/
  ) {
    ($linkurl, $alarm) = Baruwa::Scanner::Message::CleanLinkURL($_);
    is($linkurl, 'www.baruwa.com');
    is($alarm,   0);
}

($linkurl, $alarm) =
  Baruwa::Scanner::Message::CleanLinkURL('javascript:window.show();');
is($linkurl, 'JavaScript');
is($alarm,   0);

use Data::Dumper;
can_ok('Baruwa::Scanner::Message', 'IsSpam');
{
    my $log             = Test::MockModule->new('Baruwa::Scanner::Log');
    my $config          = Test::MockModule->new('Baruwa::Scanner::Config');
    my $ret             = 0;
    my $mshmacskipvalid = 0;
    my $mshmacnull_none = 0;
    my $whitelisted     = 0;
    my $manyrecips      = 0;
    my $skippedastoobig = 0;

    # Baruwa::Scanner::Config::SetValue('usespamassassin', 0);
    $log->mock(
        InfoLog => sub {
            my ($log_msg) = @_;

            # print STDERR "XXXX:$log_msg\n";
            $ret++
              if ($log_msg eq
                "Valid RET hash found in Message %s, skipping Spam Checks");
            $mshmacskipvalid++
              if ($log_msg eq
                "Valid Watermark HASH found in Message %s Header, skipping Spam Checks"
              );
            $mshmacnull_none++
              if ($log_msg eq
                "Message %s from %s has no (or invalid) watermark or sender address"
              );
            $whitelisted++
              if ($log_msg eq "Message %s from %s (%s) is whitelisted");
            $manyrecips++
              if ($log_msg eq
                "Message %s from %s (%s) ignored whitelist, had %d recipients (>%d)"
              );
            $skippedastoobig++
              if ($log_msg eq
                "Message %s from %s (%s) to %s is too big for spam checks (%d > %d bytes)"
              );
        }
    );

    # $config->mock(
    #     Value => sub {
    #         my ($opt, $lmsg) = @_;
    #         print STDERR "Got option: $opt\n";
    #         return 0 if ($opt eq 'usespamassassin');
    #     }
    # );
    ($msg, $entity) = _parse_msg($msgid5);
    $msg->{ret} = 1;
    isnt(exists $msg->{isspam}, 1);
    is($msg->IsSpam(),        0);
    is($ret,                  1);
    is(exists $msg->{isspam}, 1);
    $msg->{ret}             = 0;
    $msg->{mshmacskipvalid} = 1;
    is($msg->IsSpam(),   0);
    is($mshmacskipvalid, 1);
    $msg->{mshmacskipvalid}   = 0;
    $msg->{mshmacnullpresent} = 1;
    $msg->{mshmacnullvalid}   = 0;
    Baruwa::Scanner::SA::initialise(0);
    Baruwa::Scanner::Config::SetValue('mshmacnull', 'delete');
    isnt($msg->{deleted},     1);
    isnt($msg->{dontdeliver}, 1);
    is($msg->IsSpam(),      0);
    is($msg->{deleted},     1);
    is($msg->{dontdeliver}, 1);
    $msg->{deleted}     = 0;
    $msg->{dontdeliver} = 0;
    $msg->{ishigh}      = 0;
    my $highscore =
      Baruwa::Scanner::Config::Value('highspamassassinscore', $msg);
    Baruwa::Scanner::Config::SetValue('mshmacnull', 'high');
    isnt($msg->{spamreport}, "spam(no watermark or sender address)");
    isnt($msg->{sascore},    $highscore);
    is($msg->IsSpam(),     1);
    is($msg->{ishigh},     1);
    is($msg->{spamreport}, "spam(no watermark or sender address)");
    is($msg->{sascore},    $highscore);
    my $reqscore = Baruwa::Scanner::Config::Value('reqspamassassinscore', $msg);
    _reset_msg(\$msg);
    Baruwa::Scanner::Config::SetValue('mshmacnull', 'spam');
    is($msg->IsSpam(),     1);
    is($msg->{isspam},     1);
    is($msg->{sascore},    $reqscore);
    is($msg->{spamreport}, "spam(no watermark or sender address)");
    _reset_msg(\$msg);
    Baruwa::Scanner::Config::SetValue('mshmacnull', '5.0');
    is($msg->IsSpam(), 1);
    is($msg->{isspam}, 1);
    like($msg->{spamreport}, qr/no watermark or sender address/);
    _reset_msg(\$msg);
    Baruwa::Scanner::Config::SetValue('mshmacnull', 'nothing');
    is($msg->IsSpam(),   0);
    is($mshmacnull_none, 1);
    _reset_msg(\$msg);
    $msg->{mshmacnullpresent} = 0;
    $config->mock(
        Value => sub {
            my ($opt, $lmsg) = @_;

            # print STDERR "Got option: $opt\n";
            return 1 if ($opt eq 'spamwhitelist');
            return 1 if ($opt eq 'lognonspam');
        }
    );
    Baruwa::Scanner::Config::SetValue('includespamheader', 0);
    isnt($msg->{spamwhitelisted}, 1);
    is($msg->IsSpam(),          0);
    is($whitelisted,            1);
    is($msg->{spamwhitelisted}, 1);
    _reset_msg(\$msg);
    $msg->{spamwhitelisted} = 0;
    $config->mock(
        Value => sub {
            my ($opt, $lmsg) = @_;

            # print STDERR "Got option: $opt\n";
            return 1  if ($opt eq 'lognonspam');
            return -1 if ($opt eq 'whitelistmaxrecips');
        }
    );
    is($msg->IsSpam(), 0);
    is($manyrecips,    1);
    _reset_msg(\$msg);
    $msg->{spamwhitelisted} = 0;
    $config->mock(
        Value => sub {
            my ($opt, $lmsg) = @_;

            # print STDERR "Got option: $opt\n";
            return 1    if ($opt eq 'lognonspam');
            return 1    if ($opt eq 'spamblacklist');
            return 4000 if ($opt eq 'maxspamchecksize');
        }
    );
    isnt($msg->{spamblacklisted}, 1);
    isnt($msg->{isspam},          1);
    is($msg->IsSpam(),          1);
    is($msg->{spamblacklisted}, 1);
    is($msg->{isspam},          1);
    _reset_msg(\$msg);
    $msg->{spamblacklisted} = 0;
    $config->mock(
        Value => sub {
            my ($opt, $lmsg) = @_;

            # print STDERR "Got option: $opt\n";
            return 1 if ($opt eq 'lognonspam');
            return 5 if ($opt eq 'maxspamchecksize');
        }
    );
    is($msg->IsSpam(),     0);
    is($msg->{spamreport}, 'skippedastoobig');
    is($skippedastoobig,   2);
    _reset_msg(\$msg);
    $msg->{store}->Unlock();
}

{
    my $sa  = Test::MockModule->new('Baruwa::Scanner::SA');
    my $rbl = Test::MockModule->new('Baruwa::Scanner::RBLs');
    $rbl->mock(
        Checks => sub {
            return (1, 'spamhaus-XBL');
        }
    );
    ($msg, $entity) = _parse_msg($msgid5);
    foreach my $usesa (qw/0 1/) {
        Baruwa::Scanner::Config::SetValue('usespamassassin', $usesa);
        isnt($msg->{isrblspam}, 1);
        is($msg->IsSpam(),    1);
        is($msg->{isrblspam}, 1);
        _reset_msg(\$msg);
        $msg->{isrblspam} = 0;
    }
    Baruwa::Scanner::Config::SetValue('usespamassassin',     1);
    Baruwa::Scanner::Config::SetValue('checksaifonspamlist', 0);
    is($msg->IsSpam(),    1);
    is($msg->{isrblspam}, 1);
    _reset_msg(\$msg);
    $msg->{isrblspam} = 0;
    Baruwa::Scanner::Config::SetValue('checksaifonspamlist', 1);
    Baruwa::Scanner::Config::SetValue('usespamassassin',     0);
    $rbl->mock(
        Checks => sub {
            return (0, '');
        }
    );
    is($msg->IsSpam(),    0);
    is($msg->{isrblspam}, 0);
    $sa->mock(Checks => sub {
        return ();
    });
    # print STDERR "Msgid->$msg->{id}\n";
    # print STDERR "MSG=>" . Dumper($msg);
    $msg->{store}->Unlock();
}

sub _reset_msg {
    my ($msg) = @_;
    $$msg->{ishigh}     = 0;
    $$msg->{isspam}     = 0;
    $$msg->{sascore}    = 0;
    $$msg->{spamreport} = "";
}

sub _count_parts {
    my ($msgid, $num) = @_;
    ($msg, $entity) = _parse_msg($msgid);
    is(Baruwa::Scanner::Message::CountParts($entity), $num);
    Baruwa::Scanner::Message::DropFromBatch($msg);
}

sub _parse_msg {
    my ($msgid) = @_;
    my $m = new Baruwa::Scanner::Message($msgid, $q->[0], 0);
    my $dir = "$workarea->{dir}/$msgid";
    remove_tree($dir, {keep_root => 0});
    mkdir "$dir", 0777 or die "could not create work dir: $dir $!";
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
