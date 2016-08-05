#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use FindBin '$Bin';
use Test::More qw(no_plan);
use File::Path qw(remove_tree);
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
    use_ok('Baruwa::Scanner::Message') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Message $Baruwa::Scanner::Message::VERSION, Perl $], $^X"
);

make_test_dirs();

can_ok('Baruwa::Scanner::Message', 'new');

my $conf = "$Bin/data/etc/mail/baruwa/baruwa.conf";
Baruwa::Scanner::Config::Read($conf, 0);
my $workarea = new Baruwa::Scanner::WorkArea;
my $inqueue =
  new Baruwa::Scanner::Queue(@{Baruwa::Scanner::Config::Value('inqueuedir')});
my $mta  = new Baruwa::Scanner::Mta;
my $quar = new Baruwa::Scanner::Quarantine;
my $q   = Baruwa::Scanner::Config::Value('inqueuedir');

$global::MS = new Baruwa::Scanner(
    WorkArea   => $workarea,
    InQueue    => $inqueue,
    MTA        => $mta,
    Quarantine => $quar
);

foreach (@Test::Baruwa::Scanner::msgs) {
    my $m = new Baruwa::Scanner::Message($_, $q->[0], 0);
    isa_ok($m, 'Baruwa::Scanner::Message', '$m');
    my $f = new Baruwa::Scanner::Message($_, $q->[0], 0);
    is($f, undef, 'Test locking of a message');
}

remove_tree("$Bin/data/var/spool/baruwa/incoming", {keep_root => 1});
