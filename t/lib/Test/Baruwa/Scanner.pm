package

  # hide from PAUSE
  Test::Baruwa::Scanner;

use strict;
use warnings;
use File::Copy;
use File::Touch;
use FindBin '$Bin';
use File::Copy::Recursive qw(dircopy);
use File::Path qw(make_path remove_tree);
use Exporter qw/import/;

our @EXPORT = qw/create_config make_test_dirs create_file update_config/;

my @paths = (
    "$Bin/data/var/lib/baruwa/archive",
    "$Bin/data/var/run/baruwa/scanner",
    "$Bin/data/var/spool/baruwa/incoming",
    "$Bin/data/var/spool/baruwa/quarantine",
    "$Bin/data/var/spool/exim/input",
    "$Bin/data/var/spool/exim.in/input",
    "$Bin/data/var/lock/Baruwa",
    "$Bin/data/etc/mail/baruwa/dynamic/rules",
    "$Bin/data/etc/mail/baruwa/dynamic/signatures",
);
my @clean_paths = (
    "$Bin/data/var/spool/exim/input",
    "$Bin/data/var/lib/baruwa/archive",
    "$Bin/data/var/spool/exim.in/input",
    "$Bin/data/var/spool/baruwa/incoming",
);
my @files = ("$Bin/data/var/lock/Baruwa/test-lock");
our @msgs = (
    '1bUUOQ-0000g4-C7', '1bUvRz-0001Mr-4W',
    '1bVCqk-0001rd-7G', '1bWglk-0003N7-5T',
    '1bWiNO-0000Yw-Pc'
);

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

sub update_config {
    my ($from, $to, $patterns, $replacement) = @_;
    die "Pattern is required"     unless ($patterns);
    die "Replacement is required" unless ($replacement);
    open(FROM, '<', $from) or die "Could not open $from\n";
    open(TO,   '>', $to)   or die "Could not open $to\n";

    # my $pattern;
  OUTER: while (<FROM>) {
        for my $i (0 .. $#{$patterns}) {
            if (m|$patterns->[$i]|) {
                s|$patterns->[$i]|$replacement->[$i]|;
                print TO;
                next OUTER;
            }
        }
        print TO;
    }
    close(FROM);
    close(TO);
}

sub make_test_dirs {
    my ($from, $to);
    foreach (@clean_paths) {
        next unless (chdir $_ . "/..");
        remove_tree($_, {keep_root => 1});
    }
    foreach (@paths) {
        make_path($_, {mode => 0700}) unless (-d $_);
    }
    touch(@files) unless -f $files[0];
    unless (-f "$Bin/data/etc/mail/baruwa/virus.scanners.conf") {
        dircopy("$Bin/../etc/mail/baruwa/*", "$Bin/data/etc/mail/baruwa/")
          or die $!;
    }
    foreach (@msgs) {
        foreach my $suffix (qw/H D/) {
            $from = "$Bin/static/spool/$_-$suffix";
            $to   = "$Bin/data/var/spool/exim.in/input/$_-$suffix";
            copy($from, $to) or die "Failed to copy $from => $to: $!";
        }
    }
}

sub create_file {
    my ($filename, $data, $overwrite) = @_;
    unless (-f "$filename" and !$overwrite) {
        open(FILE, '>', $filename) or die "Could not create file: $filename";
        print FILE $data;
        close(FILE);
    }
}
