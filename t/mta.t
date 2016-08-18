#!/usr/bin/env perl
use v5.10;
use strict;
use warnings;
use Test::Output;
use Test::More qw(no_plan);
use FindBin '$Bin';
use Baruwa::Scanner();
use Baruwa::Scanner::Mta();
use Baruwa::Scanner::Queue();
use Baruwa::Scanner::Config();
use Baruwa::Scanner::WorkArea();
use Baruwa::Scanner::Quarantine();
use Baruwa::Scanner::MessageBatch();
use lib "$Bin/lib";
use Test::Baruwa::Scanner;

# plan tests => 1;

BEGIN {
    use_ok('Baruwa::Scanner::Mta') || print "Bail out!\n";
}

diag("Testing Baruwa::Scanner::Mta $Baruwa::Scanner::Mta::VERSION, Perl $], $^X"
);

make_test_dirs();

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

can_ok('Baruwa::Scanner::Mta', 'new');

my $e = new Baruwa::Scanner::Mta();

isa_ok($e, 'Baruwa::Scanner::Mta', '$e');

can_ok($e, 'initialise');

$e->initialise();

can_ok($e, 'DFileName');
is($e->DFileName('1bWglk-0003N7-5T'), '1bWglk-0003N7-5T-D');

can_ok($e, 'HFileName');
is($e->HFileName('1bWglk-0003N7-5T'), '1bWglk-0003N7-5T-H');

can_ok($e, 'TFileName');
is($e->TFileName('1bWglk-0003N7-5T'), '1bWglk-0003N7-5T-T');

can_ok($e, 'LFileName');
is($e->LFileName('1bWglk-0003N7-5T'), '../msglog/1bWglk-0003N7-5T');

can_ok($e, 'ReadQf');
{
    my $msgid = $Test::Baruwa::Scanner::msgs[1];
    my $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    is($m->{from},     'andrew@home.topdog-software.com');
    is($m->{clientip}, '192.168.1.52');
}

can_ok($e, 'AddHeadersToQf');
{
    my $msgid = $Test::Baruwa::Scanner::msgs[1];
    my $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    my $header1 = $m->{metadata}{headers}[0]{name};
    is($m->{metadata}{headers}[0]{name}, $header1);
    $e->AddHeadersToQf($m);
    is($m->{metadata}{headers}[0]{name}, $header1);
    isnt($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Test:');
    $e->AddHeadersToQf($m, 'X-Baruwa-Test: 1');
    is($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Test:');
}

can_ok($e, 'RealAddHeadersToQf');
{
    my $msgid = $Test::Baruwa::Scanner::msgs[1];
    my $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    my $header1 = $m->{metadata}{headers}[0]{name};
    my @headers = @{$m->{headers}};
    is($m->{metadata}{headers}[0]{name}, $header1);
    is($e->RealAddHeadersToQf($m, \@headers), 1);
    is($m->{metadata}{headers}[0]{name}, $header1);
    isnt($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Test:');
    @headers = ('X-Baruwa-Test: 1');
    is($e->RealAddHeadersToQf($m, \@headers), 1);
    is($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Test:');
}

can_ok($e, 'AddHeader');
{
    my ($msgid, $m, $last);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    isnt($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Test:');
    $e->AddHeader($m, 'X-Baruwa-Test:', '1');
    is($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Test:');
    $last = $#{$m->{metadata}{headers}};
    isnt($m->{metadata}{headers}[$last]{name}, 'X-Baruwa-Last:');
    $m->{newheadersattop} = 0;
    $e->AddHeader($m, 'X-Baruwa-Last:', '1');
    $last = $#{$m->{metadata}{headers}};
    is($m->{metadata}{headers}[$last]{name}, 'X-Baruwa-Last:');
}

can_ok($e, 'DeleteHeader');
{
    my ($msgid, $m);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    isnt($m->{metadata}{headers}[0]{flag}, '*');
    $e->DeleteHeader($m, 'Received:');
    is($m->{metadata}{headers}[0]{flag}, '*');
}

can_ok($e, 'UniqHeader');
{
    my ($msgid, $m, $last);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    $m->{newheadersattop} = 0;
    $e->AddHeader($m, 'X-Baruwa-Virus-Checks:', ' bypassed smtp time checks');
    $last = $#{$m->{metadata}{headers}};
    isnt($m->{metadata}{headers}[$last]{flag}, '*');
    $e->UniqHeader($m, 'X-Baruwa-Virus-Checks:');
    is($m->{metadata}{headers}[$last]{flag}, '*');
}

can_ok($e, 'ReplaceHeader');
{
    my ($msgid, $m, $last);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    isnt($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Virus-Checks:');
    $e->ReplaceHeader($m, 'X-Baruwa-Virus-Checks:', ' notnice');
    $last = $#{$m->{metadata}{headers}};
    is($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Virus-Checks:');
    isnt($m->{metadata}{headers}[$last]{flag}, '*');
}

can_ok($e, 'ReplaceHeader');
{
    # dkimfriendly off
    my ($msgid, $m, $last);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    isnt($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Virus-Checks:');
    $m->{dkimfriendly} = 0;
    $e->ReplaceHeader($m, 'X-Baruwa-Virus-Checks:', ' notnice');
    is($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Virus-Checks:');
    $last = $#{$m->{metadata}{headers}};
    is($m->{metadata}{headers}[$last]{flag}, '*');
}

can_ok($e, 'FindHeader');
{
    my ($msgid, $m);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    is($e->FindHeader($m, 'X-Baruwa-Last:'), undef);
    is($e->FindHeader($m, 'X-Baruwa-Virus-Checks:')->{name},
        'X-Baruwa-Virus-Checks:');
}

can_ok($e, 'AppendHeader');
{
    my ($msgid, $m, $last, $body);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    isnt($m->{metadata}{headers}[0]{name}, 'X-Baruwa-First:');
    is($e->AppendHeader($m, 'X-Baruwa-First:', 'notnice', ';'), 1);
    is($m->{metadata}{headers}[0]{name}, 'X-Baruwa-First:');
    $last = $#{$m->{metadata}{headers}};
    $body = $m->{metadata}{headers}[$last]{body};
    chomp($body);
    unlike($m->{metadata}{headers}[$last]{body}, qr/notnice/);
    is($e->AppendHeader($m, 'X-Baruwa-Virus-Checks:', 'notnice', ';'), 1);
    like($m->{metadata}{headers}[$last]{body}, qr/notnice/);
    is($m->{metadata}{headers}[$last]{body}, $body . ';' . 'notnice' . "\n");
}

can_ok($e, 'PrependHeader');
{
    my ($msgid, $m, $last, $body);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    isnt($m->{metadata}{headers}[0]{name}, 'X-Baruwa-First:');
    is($e->PrependHeader($m, 'X-Baruwa-First:', 'notnice', ';'), 1);
    is($m->{metadata}{headers}[0]{name}, 'X-Baruwa-First:');
    $last = $#{$m->{metadata}{headers}};
    $body = $m->{metadata}{headers}[$last]{body};
    chomp($body);
    unlike($m->{metadata}{headers}[$last]{body}, qr/notnice/);
    is($e->PrependHeader($m, 'X-Baruwa-Virus-Checks:', 'notnice', ';'), 1);
    like($m->{metadata}{headers}[$last]{body}, qr/notnice/);
    $body =~ s/^(;|\s)*//;
    is($m->{metadata}{headers}[$last]{body}, ' notnice' . ';' . $body . "\n");
}

can_ok($e, 'TextStartsHeader');
{
    my ($msgid, $m);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    is($e->TextStartsHeader($m, 'X-Baruwa-First:',        'blahbla'),  0);
    is($e->TextStartsHeader($m, 'X-Baruwa-Virus-Checks:', 'bypassed'), 1);
}

can_ok($e, 'TextEndsHeader');
{
    my ($msgid, $m);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    is($e->TextEndsHeader($m, 'X-Baruwa-First:',        'blahbla'), 0);
    is($e->TextEndsHeader($m, 'X-Baruwa-Virus-Checks:', 'checks'),  1);
}

can_ok($e, 'AddRecipients');
{
    my ($msgid, $m, @to);
    @to    = ('tony@home.topdog-software.com', 'fsb@home.topdog-software.com');
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m     = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    is($m->{metadata}{numrcpts}, 1);
    $e->AddRecipients($m, @to);
    is($m->{metadata}{numrcpts}, 3);
    is($m->{metadata}{rcpts}[1], $to[0]);
    is($m->{metadata}{rcpts}[2], $to[1]);
}

can_ok($e, 'DeleteRecipients');
{
    my ($msgid, $m);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    is($m->{metadata}{numrcpts},        1);
    is(scalar @{$m->{metadata}{rcpts}}, 1);
    is($e->DeleteRecipients($m),        1);
    is(scalar @{$m->{metadata}{rcpts}}, 0);
    is(scalar @{$m->{metadata}{rcpts}}, 0);
}

can_ok($e, 'KickMessage');

can_ok('Baruwa::Scanner::Mta', 'CreateQf');
{
    my ($msgid, $m);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    like(Baruwa::Scanner::Mta::CreateQf($m), qr/352P Received:/);
}

can_ok('Baruwa::Scanner::Mta', 'FindAndFlag');
{
    my @headers = (
        {name => 'BCC:',        flag => ' '},
        {name => 'CC:',         flag => ' '},
        {name => 'From:',       flag => ' '},
        {name => 'Message-ID:', flag => ' '},
        {name => 'Reply-To:',   flag => ' '},
        {name => 'Sender:',     flag => ' '},
        {name => 'To:',         flag => ' '},
        {name => 'Received:',   flag => ' '},
        {name => 'Received:',   flag => ' '},
    );
    is(Baruwa::Scanner::Mta::FindAndFlag(\@headers, 'X'), 0);
    foreach my $flag (qw/B C F I R S T P/) {
        is(Baruwa::Scanner::Mta::FindAndFlag(\@headers, $flag), 1);
    }
}

can_ok('Baruwa::Scanner::Mta', 'BTreeString');
{
    my ($msgid, $m);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    is(Baruwa::Scanner::Mta::BTreeString($m->{metadata}->{nonrcpts}),
        'XX' . "\n");
}

can_ok('Baruwa::Scanner::Mta', 'BTreeHash');
{
    my ($msgid, $m);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    is(%{Baruwa::Scanner::Mta::BTreeHash($m->{metadata}->{nonrcpts})}, 0);
}

can_ok('Baruwa::Scanner::Mta', 'BTreeDescend');
{
    is(Baruwa::Scanner::Mta::BTreeDescend({}), '');
}

can_ok($e, 'AddMultipleHeaderName');
{
    my ($msgid, $m, $body, $last);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    isnt($m->{metadata}{headers}[0]{name}, 'X-Baruwa-First:');
    $e->AddMultipleHeaderName($m, 'X-Baruwa-First:', 'notnice', ';');
    is($m->{metadata}{headers}[0]{name}, 'X-Baruwa-First:');

    # append
    Baruwa::Scanner::Config::SetValue('multipleheaders', 'append');
    $last = $#{$m->{metadata}{headers}};
    $body = $m->{metadata}{headers}[$last]{body};
    chomp($body);
    unlike($m->{metadata}{headers}[$last]{body}, qr/notnice/);
    $e->AddMultipleHeaderName($m, 'X-Baruwa-Virus-Checks:', 'notnice', ';');
    like($m->{metadata}{headers}[$last]{body}, qr/notnice/);
    is($m->{metadata}{headers}[$last]{body}, $body . ';' . 'notnice' . "\n");

    # replace
    Baruwa::Scanner::Config::SetValue('multipleheaders', 'replace');
    isnt($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Virus-Checks:');
    $e->AddMultipleHeaderName($m, 'X-Baruwa-Virus-Checks:', ' notnice', ';');
    $last = $#{$m->{metadata}{headers}};
    is($m->{metadata}{headers}[0]{name}, 'X-Baruwa-Virus-Checks:');
    isnt($m->{metadata}{headers}[$last]{flag}, '*');
}

can_ok($e, 'AddMultipleHeader');
{
    my ($msgid, $m, $body, $last, $header);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    $header = Baruwa::Scanner::Config::Value('mailheader', $m);
    isnt($m->{metadata}{headers}[0]{name}, $header);
    $e->AddMultipleHeader($m, 'mailheader', 'notnice', ';');
    is($m->{metadata}{headers}[0]{name}, $header);

    # append
    Baruwa::Scanner::Config::SetValue('multipleheaders', 'append');
    $last = $#{$m->{metadata}{headers}};
    $body = $m->{metadata}{headers}[$last]{body};
    chomp($body);
    unlike($m->{metadata}{headers}[$last]{body}, qr/notnice/);
    $header = Baruwa::Scanner::Config::Value('mailheader', $m);
    $e->AddMultipleHeader($m, 'mailheader', 'notnice', ';');
    $last = $#{$m->{metadata}{headers}};
    like($m->{metadata}{headers}[0]{body}, qr/notnice/);

    # is($m->{metadata}{headers}[0]{body}, $body . ';' . 'notnice' . "\n");
    # replace
    Baruwa::Scanner::Config::SetValue('multipleheaders', 'replace');
    $header = Baruwa::Scanner::Config::Value('spamheader', $m);
    isnt($m->{metadata}{headers}[0]{name}, $header);
    $e->AddMultipleHeader($m, 'spamheader', ' notnice', ';');
    $last = $#{$m->{metadata}{headers}};
    is($m->{metadata}{headers}[0]{name}, $header);
    isnt($m->{metadata}{headers}[$last]{flag}, '*');
}

can_ok('Baruwa::Scanner::Mta', 'SendMessageString');
can_ok('Baruwa::Scanner::Mta', 'SendMessageEntity');

can_ok($e, 'CreateBatch');
{
    Baruwa::Scanner::MessageBatch::initialise();
    my $batch = new Baruwa::Scanner::MessageBatch('normal', undef);
    $e->CreateBatch($batch);
    stderr_like(
        sub {$batch->print();},
        qr/Message 1bUUOQ-0000g4-C7/,
        qr/Message 1bUUOQ-0000g4-C7/
    );
    $batch->EndBatch();
}

can_ok($e, 'OriginalMsgHeaders');
{
    my ($msgid, $m, @headers, @result);
    $msgid = $Test::Baruwa::Scanner::msgs[1];
    $m = new Baruwa::Scanner::Message($msgid, $q->[0], 1);
    is($global::MS->{mta}->ReadQf($m, 0), 1);
    @headers = @{$m->{headers}};
    @result  = $e->OriginalMsgHeaders($m);
    is($result[0], $headers[0]);
    @result = $e->OriginalMsgHeaders($m, ';');
    is($result[0], $headers[0] . ';');
}
