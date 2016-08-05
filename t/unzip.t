#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use MIME::Parser;
use FindBin '$Bin';
use File::Map qw(map_file);
use Test::More qw(no_plan);
use Baruwa::Scanner::Config();
use Baruwa::Scanner::FileInto();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Unzip') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::Unzip $Baruwa::Scanner::Unzip::VERSION, Perl $], $^X"
);

make_test_dirs();
my $from       = "$Bin/configs/template.conf";
my $conf       = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $conf_unzip = "$Bin/data/etc/mail/baruwa/baruwa_unzip.conf";
my $datadir    = "$Bin/data";
create_config($from, $conf, $datadir);
map_file my $conf_data, $conf;
$conf_data =~
  s/Unzip Maximum Files Per Archive = 0/Unzip Maximum Files Per Archive = 1/;
create_file($conf_unzip, $conf_data);
Baruwa::Scanner::Config::Read($conf_unzip, 0);
my $workarea = new Baruwa::Scanner::WorkArea;
my $inqueue =
  new Baruwa::Scanner::Queue(@{Baruwa::Scanner::Config::Value('inqueuedir')});
my $mta  = new Baruwa::Scanner::Sendmail;
my $quar = new Baruwa::Scanner::Quarantine;
my $q    = Baruwa::Scanner::Config::Value('inqueuedir');

$global::MS = new Baruwa::Scanner(
    WorkArea   => $workarea,
    InQueue    => $inqueue,
    MTA        => $mta,
    Quarantine => $quar
);

my $msgid = $Test::Baruwa::Scanner::msgs[1];
my $m     = new Baruwa::Scanner::Message($msgid, $q->[0], 0);
my $dir   = "$workarea->{dir}/$msgid";
mkdir "$dir", 0777 or die "could not create work dir";
$m->WriteHeaderFile();

# $m->Explode();
$m->{file2parent}{""} = "";
my $parser = MIME::Parser->new;
my $filer  = Baruwa::Scanner::FileInto->new($dir);

can_ok('Baruwa::Scanner::Unzip', 'new');

my $u = new Baruwa::Scanner::Unzip();

isa_ok($u, 'Baruwa::Scanner::Unzip', '$u');
