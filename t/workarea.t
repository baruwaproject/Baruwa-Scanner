#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use File::Touch;
use FindBin '$Bin';
use Test::Exception;
use File::Path qw(make_path);
use Test::More qw(no_plan);
use Baruwa::Scanner::Config();
use Baruwa::Scanner::WorkArea();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::WorkArea') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::WorkArea $Baruwa::Scanner::WorkArea::VERSION, Perl $], $^X"
);

make_test_dirs();

can_ok('Baruwa::Scanner::WorkArea', 'new');

my $from    = "$Bin/configs/template.conf";
my $conf    = "$Bin/data/etc/mail/baruwa/baruwa.conf";
my $datadir = "$Bin/data";
create_config($from, $conf, $datadir);
Baruwa::Scanner::Config::Read($conf, 0);

my $workarea = new Baruwa::Scanner::WorkArea;

isa_ok($workarea, 'Baruwa::Scanner::WorkArea', "$workarea");

is(-d $workarea->{dir}, 1);

can_ok($workarea, 'Clear');

my @files = (
    "$workarea->{dir}/1bUUOQ-0000g4-C7.header",
    "$workarea->{dir}/1bUvRz-0001Mr-4W.header"
);

my @dirs =
  ("$workarea->{dir}/1bUUOQ-0000g4-C7", "$workarea->{dir}/1bUvRz-0001Mr-4W");

create_working_dirs();

check_existance();

$workarea->Clear();

check_non_existance();

can_ok($workarea, 'ClearAll');

create_working_dirs();

check_existance();

$workarea->ClearAll();

check_non_existance();

can_ok($workarea, 'ClearIds');

create_working_dirs();

check_existance();

my @ids = ($files[0], $dirs[1]);
$workarea->ClearIds(\@ids);

check_partial();

$workarea->ClearAll();

create_working_dirs();
check_existance();
$workarea->Clear(\@ids);

check_partial();

$workarea->ClearAll();

can_ok($workarea, 'DeleteFile');
can_ok($workarea, 'FileExists');
can_ok($workarea, 'ChangeToMessage');

my %msg = (id => '1bUUOQ-0000g4-C7');

isnt($workarea->ChangeToMessage(\%msg), 1);

make_path("$workarea->{dir}/1bUUOQ-0000g4-C7", {mode => 0700});
my @d = ("$workarea->{dir}/1bUUOQ-0000g4-C7/docu.doc");
touch(@d);

is($workarea->ChangeToMessage(\%msg), 1);

is(-f $d[0], 1);
is($workarea->FileExists(\%msg, 'docu.doc'), 1);

$workarea->DeleteFile(\%msg, 'docu.doc');

isnt(-f $d[0], 1);
isnt($workarea->FileExists(\%msg, 'docu.doc'), 1);

can_ok($workarea, 'Destroy');

$workarea->Destroy();

isnt(-d $workarea->{dir}, 1);

throws_ok {$workarea->ClearIds(\@ids)}
qr/Cannot chdir to/,
  'Throws error if msg work directory does not exist';

sub create_working_dirs {
    touch(@files);
    foreach (@dirs) {
        make_path($_, {mode => 0700}) unless (-d $_);
        is(-d $_, 1);
    }
}

sub check_existance {
    foreach (@dirs) {
        is(-d $_, 1);
    }

    foreach (@files) {
        is(-f $_, 1);
    }
}

sub check_non_existance {
    foreach (@dirs) {
        isnt(-d $_, 1);
    }

    foreach (@files) {
        isnt(-f $_, 1);
    }
}

sub check_partial {
    isnt(-f $files[0], 1);
    is(-f $files[1], 1);
    isnt(-d $dirs[1], 1);
    is(-d $dirs[0], 1);
}
