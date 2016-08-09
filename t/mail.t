#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use Test::MockModule;
use FindBin '$Bin';
use Test::More qw(no_plan);
use Baruwa::Scanner();
use Baruwa::Scanner::Mta();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::Message();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Quarantine();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Mail') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Mail $Baruwa::Scanner::Mail::VERSION, Perl $], $^X"
);

make_test_dirs();

{
    can_ok('Baruwa::Scanner::Mail', 'TellAbout');
    my $conf = "$Bin/data/etc/mail/baruwa/baruwa.conf";
    Baruwa::Scanner::Config::Read($conf, 0);
    my $workarea = new Baruwa::Scanner::WorkArea;
    my $inqueue =
      new Baruwa::Scanner::Queue(
        @{Baruwa::Scanner::Config::Value('inqueuedir')});
    my $mta  = new Baruwa::Scanner::Mta;
    my $quar = new Baruwa::Scanner::Quarantine;
    my $q    = Baruwa::Scanner::Config::Value('inqueuedir');
    $global::MS = new Baruwa::Scanner(
        WorkArea   => $workarea,
        InQueue    => $inqueue,
        MTA        => $mta,
        Quarantine => $quar
    );

    my ($queueref, $sendmailref);
    my $mod    = Test::MockModule->new('Baruwa::Scanner::Mta');
    my $kicked = 0;
    $mod->mock(
        KickMessage => sub {
            $kicked++;
            ($queueref, $sendmailref) = @_;
        }
    );

    my $msgid;
    my $ids = "";
    my @msgs = ();
    my $queuename = Baruwa::Scanner::Config::Value('outqueuedir');
    foreach $msgid (@Test::Baruwa::Scanner::msgs) {
        my $m = new Baruwa::Scanner::Message($msgid, $q->[0], 0);
        isa_ok($m, 'Baruwa::Scanner::Message', '$m');
        $ids .= " " . $msgid;
        push @msgs, $m;
    }
    Baruwa::Scanner::Mail::TellAbout(@msgs);
    is($kicked, 1);
    is(exists $queueref->{"$queuename"}, 1);
    is($queueref->{"$queuename"}, $ids);
    is(exists $sendmailref->{"$queuename"}, 1);
    is($sendmailref->{"$queuename"}, Baruwa::Scanner::Config::Value('sendmail2'));
}

