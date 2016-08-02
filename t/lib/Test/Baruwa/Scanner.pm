package

  # hide from PAUSE
  Test::Baruwa::Scanner;

use strict;
use warnings;
use File::Touch;
use File::NCopy;
use FindBin '$Bin';
use File::Path qw(make_path);
use Exporter qw/import/;

our @EXPORT = qw/create_config make_test_dirs/;

my @paths = (
    "$Bin/data/var/run/baruwa/scanner",
    "$Bin/data/var/spool/baruwa/incoming",
    "$Bin/data/var/spool/baruwa/quarantine",
    "$Bin/data/var/spool/exim/input",
    "$Bin/data/var/spool/exim.in/input",
    "$Bin/data/var/lock/Baruwa",
    "$Bin/data/etc/mail/baruwa/dynamic/rules",
    "$Bin/data/etc/mail/baruwa/dynamic/signatures",
);
my @files = ("$Bin/data/var/lock/Baruwa/test-lock");

sub create_config {
    my ($from, $to, $path) = @_;
    open(FROM, '<', $from) or die "Could not open $from\n";
    open(TO,   '>', $to)   or die "Could not open $to\n";
    while (<FROM>) {
        unless (/PATH/) {
            print TO;
            next;
        }
        s/PATH/$path/;
        print TO;
    }
    close(FROM);
    close(TO);
}

sub make_test_dirs {
    foreach (@paths) {
        make_path($_, {mode => 0700}) unless (-d $_);
    }
    touch(@files) unless -f $files[0];
    unless (-f "$Bin/data/etc/mail/baruwa/virus.scanners.conf") {
        my $cp = File::NCopy->new(recursive => 1);
        $cp->copy("$Bin/../etc/mail/baruwa/*", "$Bin/data/etc/mail/baruwa/");
    }
}
