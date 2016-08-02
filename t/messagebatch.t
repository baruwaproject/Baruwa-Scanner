#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use Test::Output;
use FindBin '$Bin';
use Test::Exception;
use Test::More qw(no_plan);
use Baruwa::Scanner();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Quarantine();
require "Baruwa/Scanner/Exim.pm";
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::MessageBatch') || print "Bail out!\n";
}

diag(
    "Testing Baruwa::Scanner::MessageBatch $Baruwa::Scanner::MessageBatch::VERSION, Perl $], $^X"
);

can_ok('Baruwa::Scanner::MessageBatch', 'new');

throws_ok {my $batch = new Baruwa::Scanner::MessageBatch('normal', undef)}
qr/Tried to create a MessageBatch without calling initglobals/,
  'Throws error if Baruwa::Scanner::MessageBatch::initialize not called';

my $conf = "$Bin/data/etc/mail/baruwa/baruwa.conf";
Baruwa::Scanner::Config::Read($conf, 0);
my $workarea = new Baruwa::Scanner::WorkArea;
my $inqueue =
  new Baruwa::Scanner::Queue(@{Baruwa::Scanner::Config::Value('inqueuedir')});
my $mta  = new Baruwa::Scanner::Sendmail;
my $quar = new Baruwa::Scanner::Quarantine;

$global::MS = new Baruwa::Scanner(
    WorkArea   => $workarea,
    InQueue    => $inqueue,
    MTA        => $mta,
    Quarantine => $quar
);
Baruwa::Scanner::MessageBatch::initialise();
my $batch = new Baruwa::Scanner::MessageBatch('normal', undef);
isa_ok($batch, 'Baruwa::Scanner::MessageBatch', '$batch');

stderr_like(
    sub {$batch->print();},
    qr/Message 1bUUOQ-0000g4-C7/,
    qr/Message 1bUUOQ-0000g4-C7/
);

can_ok($batch, 'StartTiming');
can_ok($batch, 'StartTiming');

foreach (qw/virus virus_processing spam disinfection/) {
    isnt(exists $batch->{$_ . '_starttime'}, 1);
    isnt(exists $batch->{$_ . '_endtime'},   1);
}

foreach (qw/virus virus_processing spam disinfection/) {
    $batch->StartTiming($_, $_ . " checks");
    $batch->StopTiming($_, $_ . " checks");
}

foreach (qw/virus virus_processing spam disinfection/) {
    is(exists $batch->{$_ . '_starttime'}, 1);
    is(exists $batch->{$_ . '_endtime'},   1);
}

foreach (@Test::Baruwa::Scanner::msgs) {
    isnt(-d "$Bin/data/var/spool/baruwa/incoming/$$/$_", 1);
}

$global::MS->{work}->BuildInDirs($batch);

can_ok($batch, 'Empty');

is($batch->Empty(), 0);

can_ok($batch, 'Explode');

for my $i (0 .. $#Test::Baruwa::Scanner::msgs) {
    is( -d "$Bin/data/var/spool/baruwa/incoming/$$/$Test::Baruwa::Scanner::msgs[$i]",
        1
    );
}

$batch->Explode();

for my $i (0 .. $#Test::Baruwa::Scanner::msgs) {
    my $num = $i + 1;
    is( -f "$Bin/data/var/spool/baruwa/incoming/$$/$Test::Baruwa::Scanner::msgs[$i]/nmsg-$$-$num.txt",
        1
    );
}

isnt(exists $batch->{'endtime'}, 1);

can_ok($batch, 'EndBatch');

$batch->EndBatch();

is(exists $batch->{'endtime'}, 1);

