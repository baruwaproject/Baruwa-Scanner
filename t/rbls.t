#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use Socket qw(inet_aton);
use Test::More qw(no_plan);
use Test::MockModule;
use Baruwa::Scanner();
use Baruwa::Scanner::Mta();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Quarantine();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::RBLs') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::RBLs $Baruwa::Scanner::RBLs::VERSION, Perl $], $^X"
);

make_test_dirs();

can_ok('Baruwa::Scanner::RBLs', 'Checks');

my $from     = "$Bin/configs/template.conf";
my $conf     = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $conf_rbl = "$Bin/data/etc/mail/baruwa/baruwa-rbl.conf";
my $datadir  = "$Bin/data";
create_config($from, $conf, $datadir);
my @rbl_matches =
  ('^Spam List =$', '^Spam Domain List =$', '^Spam List Timeout = 10$');
my @rbl_repls = (
    "Spam List = spamhaus-XBL spamhaus-ZEN spamcop.net HOSTKARMA-RBL",
    "Spam Domain List = BARUWA-DBL HOSTKARMA-DBL SEM",
    "Spam List Timeout = 5"
);
update_config($conf, $conf_rbl, \@rbl_matches, \@rbl_repls);
Baruwa::Scanner::Config::Read($conf, 0);
my $workarea = new Baruwa::Scanner::WorkArea;
my $q        = Baruwa::Scanner::Config::Value('inqueuedir');

{
    my $inqueue =
      new Baruwa::Scanner::Queue(
        @{Baruwa::Scanner::Config::Value('inqueuedir')});
    my $mta  = new Baruwa::Scanner::Mta;
    my $quar = new Baruwa::Scanner::Quarantine;

    $global::MS = new Baruwa::Scanner(
        WorkArea   => $workarea,
        InQueue    => $inqueue,
        MTA        => $mta,
        Quarantine => $quar
    );
    my $m = _parse_msg($Test::Baruwa::Scanner::msgs[1]);
    my ($num, $hits, $queries);
    ($num, $hits) = Baruwa::Scanner::RBLs::Checks($m);
    is($num,  0);
    is($hits, '');
    Baruwa::Scanner::Config::Read($conf_rbl, 0);
    my $rbl = Test::MockModule->new('Baruwa::Scanner::RBLs');
    $rbl->mock(
        resolve_name => sub {
            my ($hostname) = @_;
            return '' if ($hostname =~ /itsekiri\.rbl\.baruwa\.net\./);
            return inet_aton('127.0.0.2');
        }
    );
    ($num, $hits) = Baruwa::Scanner::RBLs::Checks($m);
    is($num,  3);
    is($hits, 'BARUWA-DBL, HOSTKARMA-DBL, SEM');
    $m->{store}->Unlock();
    $m = _parse_msg($Test::Baruwa::Scanner::msgs[5]);
    ($num, $hits) = Baruwa::Scanner::RBLs::Checks($m);
    is($num, 6);
    is($hits,
        'spamhaus-XBL, spamcop.net, HOSTKARMA-RBL, BARUWA-DBL, HOSTKARMA-DBL, SEM'
    );
    $rbl->mock(
        resolve_name => sub {
            my ($hostname) = @_;
            if ($hostname =~ /\.baruwa\.net\./) {
                while (1) {
                    ;
                }
            }
            return inet_aton('127.0.0.2');
        }
    );
    ($num, $hits) = Baruwa::Scanner::RBLs::Checks($m);
    is($num,  1);
    is($hits, 'spamhaus-XBL');
    $m->{store}->Unlock();
}

sub _parse_msg {
    my ($msgid) = @_;
    my $m = new Baruwa::Scanner::Message($msgid, $q->[0], 0);
    my $dir = "$workarea->{dir}/$msgid";
    mkdir "$dir", 0777 or die "could not create work dir";
    $m->WriteHeaderFile();
    $m->Explode();
    return $m;
}
