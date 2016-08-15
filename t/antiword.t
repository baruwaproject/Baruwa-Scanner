#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use File::Which;
use FindBin '$Bin';
use Test::More qw(no_plan);
use Baruwa::Scanner();
use Baruwa::Scanner::Mta();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Quarantine();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

BEGIN {
    use_ok('Baruwa::Scanner::Antiword') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Antiword $Baruwa::Scanner::Antiword::VERSION, Perl $], $^X"
);

make_test_dirs();

my $from          = "$Bin/configs/template.conf";
my $conf          = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $conf_antiword = "$Bin/data/etc/mail/baruwa/baruwa-antiword.conf";
my $datadir       = "$Bin/data";
create_config($from, $conf, $datadir);

my $antiword_path = which('antiword');
if ($antiword_path) {
    my @antiword_matches = ('Antiword = /usr/bin/antiword');
    my @antiword_repls   = ("Antiword = $antiword_path");
    update_config($conf, $conf_antiword, \@antiword_matches, \@antiword_repls);
    Baruwa::Scanner::Config::Read($conf_antiword, 0);
} else {
    Baruwa::Scanner::Config::Read($conf, 0);
}

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

can_ok('Baruwa::Scanner::Antiword', 'FindDocFiles');
my %nullhash = ();
my $msgid    = $Test::Baruwa::Scanner::msgs[1];
my $m        = new Baruwa::Scanner::Message($msgid, $q->[0], 0);
my $dir      = "$workarea->{dir}/$msgid";
mkdir "$dir", 0777 or die "could not create work dir";
$m->WriteHeaderFile();
$m->Explode();
my $docfiles =
  Baruwa::Scanner::Antiword::FindDocFiles($m->{entity}, $m->{entity},
    \%nullhash);
is(exists $docfiles->{'nkudzu.doc'}, 1);

SKIP: {
    my ($docfile, $parent, $antiword, $len, @anti);
    $len      = keys %$docfiles;
    @anti     = split(/\s+/, Baruwa::Scanner::Config::Value('antiword'));
    $antiword = $anti[0];
    skip('Antiword is required to run this test', $len) unless (-f $antiword);
    can_ok('Baruwa::Scanner::Antiword', 'RunAntiword');
    while (($docfile, $parent) = each %$docfiles) {
        is(Baruwa::Scanner::Antiword::RunAntiword($dir, $docfile, $parent, $m),
            1);
    }
}
