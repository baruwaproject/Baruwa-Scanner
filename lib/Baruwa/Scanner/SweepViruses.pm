# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# This file was forked from MailScanner in July 2016.
# Original author, and relevant copyright and licensing information is below:
# :author: Julian Field
# :copyright: Copyright (C) 2002  Julian Field
#

package Baruwa::Scanner::SweepViruses;

use strict 'vars';
use strict 'refs';
no strict 'subs';    # Allow bare words for parameter %'s

use POSIX qw(:signal_h setsid);    # For Solaris 9 SIG bug workaround
use DirHandle;
use IO::Socket::INET;
use IO::Socket::UNIX;
use Baruwa::Scanner::Config();

our ($ScannerPID);

our $VERSION = '4.086000';

# Locking definitions for flock() which is used to lock the Lock file
my ($LOCK_SH) = 1;
my ($LOCK_EX) = 2;
my ($LOCK_NB) = 4;
my ($LOCK_UN) = 8;

# ClamAV Module object and library directory modification time
my ($Clam, $Claminuse, %Clamwatchfiles, %ClamAVAlreadyLogged);
$Claminuse      = 0;
%Clamwatchfiles = ();

# So we can kill virus scanners when we are HUPped
$ScannerPID = 0;
my $scannerlist = "";

#
# Virus scanner definitions table
#
my ($S_NONE,           # Not present
    $S_UNSUPPORTED,    # Present but you're on your own
    $S_ALPHA,          # Present but not tested -- we hope it works!
    $S_BETA,           # Present and tested to some degree -- we think it works!
    $S_SUPPORTED,      # People use this; it'd better work!
) = (0, 1, 2, 3, 4);

my %Scanners = (
    generic => {
        Name             => 'Generic',
        Lock             => 'genericBusy.lock',
        CommonOptions    => '',
        DisinfectOptions => '-disinfect',
        ScanOptions      => '',
        InitParser       => \&InitGenericParser,
        ProcessOutput    => \&ProcessGenericOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_NONE,
    },
    sophos => {
        Name => 'Sophos',
        Lock => 'sophosBusy.lock',

        # In next line, '-ss' makes it work nice and quietly
        CommonOptions => '-sc -f -all -rec -ss -archive -cab -loopback '
          . '--no-follow-symlinks --no-reset-atime -TNEF',
        DisinfectOptions => '-di',
        ScanOptions      => '',
        InitParser       => \&InitSophosParser,
        ProcessOutput    => \&ProcessSophosOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    mcafee6 => {
        Name          => 'McAfee6',
        Lock          => 'mcafee6Busy.lock',
        CommonOptions => '--recursive --ignore-links --analyze --mime '
          . '--secure --noboot',
        DisinfectOptions => '--clean',
        ScanOptions      => '',
        InitParser       => \&InitMcAfee6Parser,
        ProcessOutput    => \&ProcessMcAfee6Output,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    command => {
        Name             => 'Command',
        Lock             => 'commandBusy.lock',
        CommonOptions    => '-packed -archive',
        DisinfectOptions => '-disinf',
        ScanOptions      => '',
        InitParser       => \&InitCommandParser,
        ProcessOutput    => \&ProcessCommandOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    kaspersky => {
        Name             => 'Kaspersky',
        Lock             => 'kasperskyBusy.lock',
        CommonOptions    => '',
        DisinfectOptions => '-- -I2',
        ScanOptions      => '-I0',
        InitParser       => \&InitKasperskyParser,
        ProcessOutput    => \&ProcessKasperskyOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    kavdaemonclient => {
        Name             => 'KavDaemon',
        Lock             => 'kasperskyBusy.lock',
        CommonOptions    => '',
        DisinfectOptions => '-- -I2',
        ScanOptions      => '',
        InitParser       => \&InitKavDaemonClientParser,
        ProcessOutput    => \&ProcessKavDaemonClientOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_NONE,
    },
    "f-secure" => {
        Name             => 'F-Secure',
        Lock             => 'f-secureBusy.lock',
        CommonOptions    => '--dumb --archive',
        DisinfectOptions => '--auto --disinf',
        ScanOptions      => '',
        InitParser       => \&InitFSecureParser,
        ProcessOutput    => \&ProcessFSecureOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "f-prot-6" => {
        Name             => 'F-Prot6',
        Lock             => 'f-prot-6Busy.lock',
        CommonOptions    => '-s 4 --adware',
        DisinfectOptions => '--disinfect --macros_safe',
        ScanOptions      => '--report',
        InitParser       => \&InitFProt6Parser,
        ProcessOutput    => \&ProcessFProt6Output,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "f-protd-6" => {
        Name             => 'F-Protd6',
        Lock             => 'f-prot-6Busy.lock',
        CommonOptions    => '',
        DisinfectOptions => '',
        ScanOptions      => '',
        InitParser       => \&InitFProtd6Parser,
        ProcessOutput    => \&ProcessFProtd6Output,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_NONE,
    },
    nod32 => {
        Name             => 'Nod32',
        Lock             => 'nod32Busy.lock',
        CommonOptions    => '-log- -all',
        DisinfectOptions => '-clean -delete',
        ScanOptions      => '',
        InitParser       => \&InitNOD32Parser,
        ProcessOutput    => \&ProcessNOD32Output,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "panda" => {
        Name             => 'Panda',
        Lock             => 'pandaBusy.lock',
        CommonOptions    => '-nor -nos -nob -heu -eng -aex -auto -cmp',
        DisinfectOptions => '-clv',
        ScanOptions      => '-nor',
        InitParser       => \&InitPandaParser,
        ProcessOutput    => \&ProcessPandaOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "clamd" => {
        Name             => 'Clamd',
        Lock             => 'clamdBusy.lock',
        CommonOptions    => '',
        DisinfectOptions => '',
        ScanOptions      => '',
        InitParser       => \&InitClamAVModParser,
        ProcessOutput    => \&ProcessClamAVModOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_NONE,
    },
    "trend" => {
        Name             => 'Trend',
        Lock             => 'trendBusy.lock',
        CommonOptions    => '-a -za -r',
        DisinfectOptions => '-c',
        ScanOptions      => '',
        InitParser       => \&InitTrendParser,
        ProcessOutput    => \&ProcessTrendOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "bitdefender" => {
        Name             => 'Bitdefender',
        Lock             => 'bitdefenderBusy.lock',
        CommonOptions    => '--arc --mail --all',
        DisinfectOptions => '--disinfect',
        ScanOptions      => '',
        InitParser       => \&InitBitdefenderParser,
        ProcessOutput    => \&ProcessBitdefenderOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "drweb" => {
        Name             => 'DrWeb',
        Lock             => 'drwebBusy.lock',
        CommonOptions    => '-ar -fm -ha- -fl- -ml -sd -up',
        DisinfectOptions => '-cu',
        ScanOptions      => '',
        InitParser       => \&InitDrwebParser,
        ProcessOutput    => \&ProcessDrwebOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "css" => {
        Name             => 'SYMCScan',
        Lock             => 'symscanengineBusy.lock',
        CommonOptions    => '',
        DisinfectOptions => '',
        ScanOptions      => '',
        InitParser       => \&InitCSSParser,
        ProcessOutput    => \&ProcessCSSOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_NONE,
    },
    "symscanengine" => {
        Name             => 'SymantecScanEngine',
        Lock             => 'symscanengineBusy.lock',
        CommonOptions    => '-details -recurse',
        DisinfectOptions => '-mode scanrepair',
        ScanOptions      => '-mode scan',
        InitParser       => \&InitSymScanEngineParser,
        ProcessOutput    => \&ProcessSymScanEngineOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "avast" => {
        Name             => 'Avast',
        Lock             => 'avastBusy.lock',
        CommonOptions    => '-n -t=A',
        DisinfectOptions => '-p=3',
        ScanOptions      => '',
        InitParser       => \&InitAvastParser,
        ProcessOutput    => \&ProcessAvastOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "avastd" => {
        Name             => 'AvastDaemon',
        Lock             => 'avastBusy.lock',
        CommonOptions    => '-n',
        DisinfectOptions => '',
        ScanOptions      => '',
        InitParser       => \&InitAvastdParser,
        ProcessOutput    => \&ProcessAvastdOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "esets" => {
        Name             => 'esets',
        Lock             => 'esetsBusy.lock',
        CommonOptions    => '--arch --subdir',
        DisinfectOptions => '--action clean',
        ScanOptions      => '--action none',
        InitParser       => \&InitesetsParser,
        ProcessOutput    => \&ProcessesetsOutput,
        SupportScanning  => $S_SUPPORTED,
        SupportDisinfect => $S_SUPPORTED,
    },
    "none" => {
        Name             => 'None',
        Lock             => 'NoneBusy.lock',
        CommonOptions    => '',
        DisinfectOptions => '',
        ScanOptions      => '',
        InitParser       => \&NeverHappens,
        ProcessOutput    => \&NeverHappens,
        SupportScanning  => $S_NONE,
        SupportDisinfect => $S_NONE,
    },
);

# Initialise the scannerlist.
sub initialise {
    my (@scanners);
    $scannerlist = Baruwa::Scanner::Config::Value('virusscanners');

    # If they have not configured the list of virus scanners, then try to
    # use all the scanners they have installed, by using the same system
    # that update_virus_scanners uses to locate them all.
    #print STDERR "Scanner list read from baruwa.conf is \"$scannerlist\"\n";
    if ($scannerlist =~ /^\s*auto\s*$/i) {

        # If we have multiple clam types, then tend towards clamd
        my %installed = map {$_ => 1} InstalledScanners();
        $scannerlist = join(' ', keys %installed);
        Baruwa::Scanner::Log::InfoLog(
            "Found %s scanners installed, and will use them all.",
            $scannerlist);
        if ($scannerlist =~ /^\s*$/) {

            #print STDERR "No virus scanners found to be installed at all!\n";
            $scannerlist = "none";
        }
    }

    $scannerlist =~ tr/,//d;
}

# Do all the commercial virus checking in here.
# If 2nd parameter is "disinfect", then we are disinfecting not scanning.
sub ScanBatch {
    my $batch    = shift;
    my $ScanType = shift;

    my ($NumInfections, $success, $id, $BaseDir);
    my (%Types, %Reports);

    $NumInfections = 0;
    $BaseDir       = $global::MS->{work}->{dir};

    chdir $BaseDir or die "Cannot chdir $BaseDir for virus scanning, $!";

    #print STDERR (($ScanType =~ /dis/i)?"Disinfecting":"Scanning") . " using ".
    #             "commercial virus scanners\n";
    $success =
      TryCommercial($batch, '.', $BaseDir, \%Reports, \%Types, \$NumInfections,
        $ScanType);

    #print STDERR "Found $NumInfections infections\n";
    if ($success eq 'ScAnNeRfAiLeD') {

        # Delete all the messages from this batch as if we weren't scanning
        # them, and reject the batch.
        Baruwa::Scanner::Log::WarnLog(
            "Virus Scanning: No virus scanners worked, so message batch was abandoned and re-tried!"
        );
        $batch->DropBatch();
        return 1;
    }
    unless ($success) {

       # Virus checking the whole batch of messages timed out, so now check them
       # one at a time to find the one with the DoS attack in it.
        my $BaseDirH = new DirHandle;
        Baruwa::Scanner::Log::WarnLog(
            "Virus Scanning: Denial Of Service attack " . "detected!");
        $BaseDirH->open('.')
          or Baruwa::Scanner::Log::DieLog(
            "Can't open directory for scanning 1 message, $!");
        while (defined($id = $BaseDirH->read())) {
            next unless -d "$id";    # Only check directories
            next if $id =~ /^\.+$/;  # Don't check myself or my parent
            $id =~ /^(.*)$/;
            $id = $1;
            next
              unless Baruwa::Scanner::Config::Value('virusscan',
                $batch->{messages}{id}) =~ /1/;

            # The "./" is important as it gets the path right for parser code
            $success =
              TryCommercial($batch, "./$id", $BaseDir, \%Reports, \%Types,
                \$NumInfections, $ScanType);

            # If none of the scanners worked, then we need to abandon this batch
            if ($success eq 'ScAnNeRfAiLeD') {

             # Delete all the messages from this batch as if we weren't scanning
             # them, and reject the batch.
                Baruwa::Scanner::Log::WarnLog(
                    "Virus Scanning: No virus scanners worked, so message batch was abandoned and re-tried!"
                );
                $batch->DropBatch();
                last;
            }

            unless ($success) {

                # We have found the DoS attack message
                $Reports{"$id"}{""} .=
                  Baruwa::Scanner::Config::LanguageValue(
                    $batch->{messages}{$id}, 'dosattack')
                  . "\n";
                $Types{"$id"}{""} .= "d";
                Baruwa::Scanner::Log::WarnLog(
                    "Virus Scanning: Denial Of Service "
                      . "attack is in message %s",
                    $id
                );

              # No way here of incrementing the "otherproblems" counter. Ho hum.
            }
        }
        $BaseDirH->close();
    }

    # Add all the %Reports and %Types to the message batch fields
    MergeReports(\%Reports, \%Types, $batch);

    # Return value is the number of infections we found
    #print STDERR "Found $NumInfections infections!\n";
    return $NumInfections;
}

# Merge all the virus reports and types into the properties of the
# messages in the batch. Doing this separately saves me changing
# the code of all the parsers to support the new OO structure.
# If we have at least 1 report for a message, and the "silent viruses" list
# includes the special keyword "All-Viruses" then mark the message as silent
# right now.
sub MergeReports {
    my ($Reports, $Types, $batch) = @_;

    my ($id, $reports, $attachment, $text);
    my ($cachedid, $cachedsilentflag);
    my (%seenbefore);

    # Let's do all the reports first...
    $cachedid = 'uninitialised';
    while (($id, $reports) = each %$Reports) {

        #print STDERR "Report merging for \"$id\" and \"$reports\"\n";
        next unless $id && $reports;
        my $message = $batch->{messages}{"$id"};

        # Skip this message if we didn't actually want it to be scanned.
        next
          unless Baruwa::Scanner::Config::Value('virusscan', $message) =~ /1/;

        #print STDERR "Message is $message\n";
        $message->{virusinfected} = 1;

        # If the cached message id matches the current one, we are working on
        # the same message as last time, so don't re-fetch the silent viruses
        # list for this message.
        if ($cachedid ne $id) {
            my $silentlist = ' '
              . Baruwa::Scanner::Config::Value('silentviruses', $message) . ' ';
            $cachedsilentflag = ($silentlist =~ /\sall-viruses\s/i) ? 1 : 0;
            $cachedid = $id;
        }

        # We can't be here unless there was a virus report for this message
        $message->{silent} = 1 if $cachedsilentflag;

        while (($attachment, $text) = each %$reports) {

# print STDERR "\tattachment \"$attachment\" has text \"$text\"\n";
# print STDERR "\tEntity of \"$attachment\" is \"" . $message->{file2entity} . "\"\n";
            next unless $text;

            # Sanitise the reports a bit
            $text =~ s/\s{20,}/ /g;
            $message->{virusreports}{"$attachment"} .= $text;
        }
        unless ($seenbefore{$id}) {
            Baruwa::Scanner::Log::NoticeLog("Infected message %s came from %s",
                $id, $message->{clientip});
            $seenbefore{$id} = 1;
        }
    }

    # And then all the report types...
    while (($id, $reports) = each %$Types) {
        next unless $id && $reports;
        my $message = $batch->{messages}{"$id"};
        while (($attachment, $text) = each %$reports) {
            next unless $text;
            $message->{virustypes}{"$attachment"} .= $text;
        }
    }
}

# Try all the installed commercial virus scanners
# We are passed the directory to start scanning from,
#               the message batch we are scanning,
#               a ref to the infections counter.
# $ScanType can be one of "scan", "rescan", "disinfect".
sub TryCommercial {
    my ($batch, $dir, $BaseDir, $Reports, $Types, $rCounter, $ScanType) = @_;
    my ($scanner, @scanners, $disinfect, $result, $counter);
    my ($logtitle, $OneScannerWorked);

    # If we aren't virus scanning *anything* then don't call the scanner
    return 1
      if Baruwa::Scanner::Config::IsSimpleValue('virusscan')
      && !Baruwa::Scanner::Config::Value('virusscan');

    # $scannerlist is now a global for this file. If it was set to "auto"
    # then I will have searched for all the scanners that appear to be
    # installed. So by the time we get here, it should never be "auto" either.
    # Unless of course they really have no scanners installed at all!
    #$scannerlist = Baruwa::Scanner::Config::Value('virusscanners');
    $scannerlist =~ tr/,//d;
    $scannerlist = "none" unless $scannerlist;    # Catch empty setting
    @scanners = split(" ", $scannerlist);
    $counter = 0;

    # Change actions and outputs depending on what we are trying to do
    $disinfect = 0;
    $disinfect = 1 if $ScanType !~ /scan/i;
    $logtitle  = "Virus Scanning";
    $logtitle  = "Virus Re-scanning" if $ScanType =~ /re/i;    # Rescanning
    $logtitle  = "Disinfection" if $ScanType =~ /dis/i;        # Disinfection

    # Work out the regexp for matching the spam-infected messages
    # This is given by the user as a space-separated list of simple wildcard
    # strings. Must split it up, escape everything, spot the * characters
    # and join them together into one big regexp. Use lots of tricks from the
    # Phishing regexp generator I wrote a month or two back.
    my $spaminfsetting = Baruwa::Scanner::Config::Value('spaminfected');

    #$spaminfsetting = '*UNOFFICIAL HTML/* Sanesecurity.*'; # Test data
    $spaminfsetting =~ s/\s+/ /g;    # Squash multiple spaces
    $spaminfsetting =~ s/^\s+//;     # Trim leading and
    $spaminfsetting =~ s/\s+$//;     # trailing space.
    $spaminfsetting =~ s/\s/ /g;     # All tabs to spaces
    $spaminfsetting =~
      s/[^0-9a-z_ -]/\\$&/ig;        # Quote every non-alnum except space.
    $spaminfsetting =~
      s/\\\*/.*/g;    # Unquote any '*' characters as they map to .*
    my @spaminfwords = split " ", $spaminfsetting;

    # Combine all the words into an "or" list in a fast regexp,
    # and anchor them all to the start and end of the string.
    my $spaminfre = '(?:^\s*' . join('\s*$|^\s*', @spaminfwords) . '\s*$)';

    $OneScannerWorked = 0;
    foreach $scanner (@scanners) {
        my $r1Counter = 0;

        #print STDERR "Trying One Commercial: $scanner\n";
        $result = TryOneCommercial(
            $scanner,   Baruwa::Scanner::Config::ScannerCmds($scanner),
            $batch,     $dir,
            $BaseDir,   $Reports,
            $Types,     \$r1Counter,
            $disinfect, $spaminfre
        );

        # If all the scanners failed, we flag it and abandon the batch.
        # If even just one of them worked, we carry on.
        if ($result ne 'ScAnNeRfAiLeD') {
            $OneScannerWorked = 1;
        }
        unless ($result) {
            Baruwa::Scanner::Log::WarnLog("%s: Failed to complete, timed out",
                $scanner);
            return 0;
        }
        $counter += $result;
        Baruwa::Scanner::Log::NoticeLog(
            "%s: %s found %d infections", $logtitle,
            $Scanners{$scanner}{Name},    $r1Counter
        ) if $r1Counter;

        # Update the grand total of viruses found
        $$rCounter += $r1Counter;
    }

    # If none of the scanners worked, then reject this batch.
    if (!$OneScannerWorked) {
        return 'ScAnNeRfAiLeD';
    }

    return $counter;
}

# Try one of the commercial virus scanners
sub TryOneCommercial {
    my ($scanner,   $sweepcommandAndPath, $batch, $subdir,
        $BaseDir,   $Reports,             $Types, $rCounter,
        $disinfect, $spaminfre
    ) = @_;

    my ($sweepcommand, $instdir,   $ReportScanner);
    my ($rScanner,     $VirusLock, $voptions, $Name);
    my ($Counter,      $TimedOut,  $PipeReturn, $pid);
    my ($ScannerFailed);

    Baruwa::Scanner::Log::DieLog(
        "Virus scanner \"%s\" not found "
          . "in virus.scanners.conf file. Please check your "
          . "spelling in \"Virus Scanners =\" line of "
          . "baruwa.conf",
        $scanner
    ) if $sweepcommandAndPath eq "";

    # Split the sweepcommandAndPath into its 2 elements
    $sweepcommandAndPath =~ /^([^,\s]+)[,\s]+([^,\s]+)$/
      or Baruwa::Scanner::Log::DieLog("Your virus.scanners.conf file does not "
          . " have 3 words on each line. See if you "
          . " have an old one left over by mistake.");
    ($sweepcommand, $instdir) = ($1, $2);

    Baruwa::Scanner::Log::DieLog("Never heard of scanner '$scanner'!")
      unless $sweepcommand;

    $rScanner = $Scanners{$scanner};

    # November 2008: Always log the scanner name, strip it from the reports
    #                if the user doesn't want it.
    # If they want the scanner name, then set it to non-blank
    $Name =
      $rScanner->{"Name"};   # if Baruwa::Scanner::Config::Value('showscanner');
    $ReportScanner = Baruwa::Scanner::Config::Value('showscanner');

    if ($rScanner->{"SupportScanning"} == $S_NONE) {
        Baruwa::Scanner::Log::DebugLog("Scanning using scanner \"$scanner\" "
              . "not supported; not scanning");
        return 1;
    }

    if ($disinfect && $rScanner->{"SupportDisinfect"} == $S_NONE) {
        Baruwa::Scanner::Log::DebugLog(
                "Disinfection using scanner \"$scanner\" "
              . "not supported; not disinfecting");
        return 1;
    }

    CheckCodeStatus(
        $rScanner->{$disinfect ? "SupportDisinfect" : "SupportScanning"})
      or Baruwa::Scanner::Log::DieLog(
        "Bad return code from CheckCodeStatus - " . "should it have quit?");

    $VirusLock = Baruwa::Scanner::Config::Value('lockfiledir') . "/"
      . $rScanner->{"Lock"};    # lock file
    $voptions = $rScanner->{"CommonOptions"};  # Set common command line options

    # Add the configured value for scanner time outs  to the command line
    # if the scanner is  Panda
    $voptions .= " -t:" . Baruwa::Scanner::Config::Value('virusscannertimeout')
      if $rScanner->{"Name"} eq 'Panda';

    # Add command line options to "scan only", or to disinfect
    $voptions .=
      " " . $rScanner->{$disinfect ? "DisinfectOptions" : "ScanOptions"};
    &{$$rScanner{"InitParser"}}($BaseDir, $batch);

    my $Lock = new FileHandle;
    my $Kid  = new FileHandle;
    my $pipe;

    # Check that the virus checker files aren't currently being updated,
    # and wait if they are.
    if (open($Lock, ">$VirusLock")) {
        print $Lock "Virus checker locked for "
          . ($disinfect ? "disinfect" : "scann")
          . "ing by $scanner $$\n";
    } else {

        #The lock file already exists, so just open for reading
        open($Lock, "<$VirusLock")
          or Baruwa::Scanner::Log::WarnLog("Cannot lock $VirusLock, $!");
    }
    flock($Lock, $LOCK_SH);

    Baruwa::Scanner::Log::DebugLog("Commencing "
          . ($disinfect ? "disinfect" : "scann")
          . "ing by $scanner...");

    $disinfect = 0 unless $disinfect;    # Make sure it's not undef

    $TimedOut = 0;
    eval {
        $pipe = $disinfect ? '|-' : '-|';
        die "Can't fork: $!" unless defined($pid = open($Kid, $pipe));
        if ($pid) {

            # In the parent
            local $SIG{ALRM} = sub {$TimedOut = 1; die "Command Timed Out"};
            alarm Baruwa::Scanner::Config::Value('virusscannertimeout');
            $ScannerPID = $pid;

            # Only process the output if we are scanning, not disinfecting
            if ($disinfect) {

                # Tell sweep to disinfect all files
                print $Kid "A\n" if $scanner eq 'sophos';

                #print STDERR "Disinfecting...\n";
            } else {
                my ($ScannerOutput, $line);
                while (defined($line = <$Kid>)) {

                    # Note: this is a change in the spec for all the parsers
                    if ($line =~ /^ScAnNeRfAiLeD/) {

                   # The virus scanner failed for some reason, remove this batch
                        $ScannerFailed = 1;
                        last;
                    }

                    $ScannerOutput = &{$$rScanner{"ProcessOutput"}}
                      ($line, $Reports, $Types, $BaseDir, $Name, $spaminfre);

                    #print STDERR "Processing line \"$_\" produced $Counter\n";
                    if ($ScannerOutput eq 'ScAnNeRfAiLeD') {
                        $ScannerFailed = 1;
                        last;
                    }
                    $Counter += $ScannerOutput if $ScannerOutput > 0;

                    #print STDERR "Counter = \"$Counter\"\n";

             # 20090730 Add support for spam-viruses, ie. spam reported as virus
             # print STDERR "ScannerOutput = \"$ScannerOutput\"\n";
                    if ($ScannerOutput =~ s/^0\s+//) {

                  # It's a spam-virus and the infection name for the spam report
                  # is in $ScannerOutput
                        $ScannerOutput =~ /^(\S+)\s+(\S+)\s*$/;
                        my ($messageid, $report) = ($1, $2);

                        #print STDERR "Found spam-virus: $messageid, $report\n";
                        Baruwa::Scanner::Log::WarnLog(
                            "Found spam-virus %s in %s",
                            $report, $messageid);
                        $batch->{messages}{"$messageid"}->{spamvirusreport} .=
                          ', '
                          if $batch->{"$messageid"}->{spamvirusreport};
                        $batch->{messages}{"$messageid"}->{spamvirusreport} .=
                          $report;

           # print STDERR "id=" . $batch->{messages}{"$messageid"}->{id} . "\n";
                    }
                }

          # If they don't want the scanner name reported, strip the scanner name
                $line =~ s/^$Name: // unless $ReportScanner;
            }
            close $Kid;
            $PipeReturn = $?;
            $pid        = 0;    # 2.54
            alarm 0;

            # Workaround for bug in perl shipped with Solaris 9,
            # it doesn't unblock the SIGALRM after handling it.
            eval {
                my $unblockset = POSIX::SigSet->new(SIGALRM);
                sigprocmask(SIG_UNBLOCK, $unblockset)
                  or die "Could not unblock alarm: $!\n";
            };
        } else {

            # In the child
            POSIX::setsid();
            if ($scanner eq 'clamd') {
                ClamdScan($subdir, $disinfect, $batch);
                exit;
            } elsif ($scanner eq 'f-protd-6') {
                Fprotd6Scan($subdir, $disinfect, $batch);
                exit;
            } else {
                exec "$sweepcommand $instdir $voptions $subdir";
                Baruwa::Scanner::Log::WarnLog(
                        "Can't run commercial checker $scanner "
                      . "(\"$sweepcommand\"): $!");
                exit 1;
            }
        }
    };
    alarm 0;    # 2.53

    # Note to self: I only close the KID in the parent, not in the child.
    Baruwa::Scanner::Log::DebugLog("Completed scanning by $scanner");
    $ScannerPID = 0;    # Not running a scanner any more

    # Catch failures other than the alarm
    Baruwa::Scanner::Log::DieLog(
        "Commercial virus checker failed with real error: $@")
      if $@ and $@ !~ /Command Timed Out|[sS]yslog/;

    #print STDERR "pid = $pid and \@ = $@\n";

    # In which case any failures must be the alarm
    if ($@ or $pid > 0) {

        # Kill the running child process
        my ($i);
        kill -15, $pid;

        # Wait for up to 5 seconds for it to die
        for ($i = 0; $i < 5; $i++) {
            sleep 1;
            waitpid($pid, &POSIX::WNOHANG);
            ($pid = 0), last unless kill(0, $pid);
            kill -15, $pid;
        }

        # And if it didn't respond to 11 nice kills, we kill -9 it
        if ($pid) {
            kill -9, $pid;
            waitpid $pid, 0;    # 2.53
        }
    }

    flock($Lock, $LOCK_UN);
    close $Lock;

    # Use the maximum value of all the numbers of viruses found by each of
    # the virus scanners. This should hopefully reflect the real number of
    # viruses in the messages, in the case where all of them spot something,
    # but only a subset spot more/all of the viruses.
    # Viruses = viruses or phishing attacks in the case of ClamAV.
    $$rCounter = $Counter if $Counter > $$rCounter;    # Set up output value

    # If the virus scanner failed, bail out and tell the boss
    return 'ScAnNeRfAiLeD' if $ScannerFailed;

    # Return failure if the command timed out, otherwise return success
    Baruwa::Scanner::Log::WarnLog("Commercial scanner $scanner timed out!")
      if $TimedOut;
    return 0 if $TimedOut;
    return 1;
}

# Initialise any state variables the Generic output parser uses
sub InitGenericParser {
    return 1;
}

# Initialise any state variables the Sophos output parser uses
sub InitSophosParser {
    return 1;
}

# Initialise any state variables the McAfee6 output parser uses
sub InitMcAfee6Parser {
    return 1;
}

# Initialise any state variables the Command (CSAV) output parser uses
sub InitCommandParser {
    return 1;
}

# Initialise any state variables the Kaspersky output parser uses
my ($kaspersky_CurrentObject);

sub InitKasperskyParser {
    $kaspersky_CurrentObject = "";
    return 1;
}

# Initialise any state variables the Kaspersky Daemon Client output parser uses
sub InitKavDaemonClientParser {
    return 1;
}

# Initialise any state variables the F-Secure output parser uses
my ($fsecure_InHeader, $fsecure_Version, %fsecure_Seen);

sub InitFSecureParser {
    $fsecure_InHeader = (-1);
    $fsecure_Version  = 0;
    %fsecure_Seen     = ();
    return 1;
}

# Initialise any state variables the F-Prot-6 output parser uses
sub InitFProt6Parser {
    return 1;
}

# Initialise any state variables the F-Protd-6 output parser uses
my (%FPd6ParserFiles);

sub InitFProtd6Parser {
    %FPd6ParserFiles = ();
    return 1;
}

# Initialise any state variables the Nod32 output parser uses
my ($NOD32Version, $NOD32InHeading);

sub InitNOD32Parser {
    $NOD32Version   = undef;
    $NOD32InHeading = 1;
    return 1;
}

# Initialise any state variables the Panda output parser uses
sub InitPandaParser {
    return 1;
}

# Initialise any state variables the ClamAV Module output parser uses
sub InitClamAVModParser {
    my ($BaseDir, $batch) = @_;

    %ClamAVAlreadyLogged = ();
    if (Baruwa::Scanner::Config::Value('clamavspam')) {

        # Write the whole message into $id.message in the headers directory
        my ($id, $message);
        while (($id, $message) = each %{$batch->{messages}}) {
            next if $message->{deleted};
            my $filename = "$BaseDir/$id.message";
            my $target = new IO::File $filename, "w";
            Baruwa::Scanner::Log::DieLog("writing to $filename: $!")
              if not defined $target;
            $message->{store}->WriteEntireMessage($message, $target);
            $target->close;

            # Set the ownership and permissions on the .message like .header
            chown $global::MS->{work}->{uid}, $global::MS->{work}->{gid},
              $filename
              if $global::MS->{work}->{changeowner};
            chmod 0664, $filename;
        }
    }
    return 1;
}

# Initialise any state variables the Vscan output parser uses
my ($trend_prevline);

sub InitTrendParser {
    $trend_prevline = "";
    return 1;
}

# Initialise any state variables the Bitdefender output parser uses
sub InitBitdefenderParser {
    return 1;
}

# Initialise any state variables the DrWeb output parser uses
sub InitDrwebParser {
    return 1;
}

# Initialise any state variables the Symantec output parser uses
my ($css_filename, $css_infected);

sub InitCSSParser {
    $css_filename = "";
    $css_infected = "";
    return 1;
}

# Initialise any state variables the ScanEngine output parser uses
my ($SSEFilename, $SSEVirusname, $SSEVirusid, $SSEFilenamelog);

sub InitSymScanEngineParser {
    $SSEFilename    = '';
    $SSEVirusname   = '';
    $SSEVirusid     = 0;
    $SSEFilenamelog = '';
    return 1;
}

# Initialise any state variables the Avast output parser uses
sub InitAvastParser {
    return 1;
}

# Initialise any state variables the Avastd output parser uses
sub InitAvastdParser {
    return 1;
}

# Initialise any state variables the esets output parser uses
sub InitesetsParser {
    return 1;
}

# These functions must be called with, in order:
# * The line of output from the scanner
# * The MessageBatch object the reports are written to
# * The base directory in which we are working.
#
# The base directory must contain subdirectories named
# per message ID, and must have no trailing slash.
#
#
# These functions must return with:
# * return code 0 if no problem, 1 if problem.
# * type of problem (currently only "v" for virus)
#   appended to $types{messageid}{messagepartname}
# * problem report from scanner appended to
#   $infections{messageid}{messagepartname}
#   -- NOTE: Don't forget the terminating newline.
#
# If the scanner may refer to the same file multiple times,
# you should consider appending to the $infections rather
# than just setting it, I guess.
#

sub ProcessClamAVModOutput {
    my ($line, $infections, $types, $BaseDir, $Name, $spaminfre) = @_;
    my ($logout, $keyword, $virusname, $filename);
    my ($dot, $id, $part, @rest, $report);

    chomp $line;
    $logout = $line;
    $logout =~ s/\s{20,}/ /g;

    #$logout =~ s/%/%%/g;

    #print STDERR "Output is \"$logout\"\n";
    ($keyword, $virusname, $filename) = split(/:: /, $line, 3);

    # Remove any rogue spaces in virus names!
    # Thanks to Alvaro Marin <alvaro@hostalia.com> for this.
    $virusname =~ s/\s+//g;

    if ($keyword =~ /^error/i && $logout !~ /rar module failure/i) {
        Baruwa::Scanner::Log::InfoLog("%s::%s", $Name, $logout);
        return 1;
    } elsif ($keyword =~ /^info/i || $logout =~ /rar module failure/i) {
        return 0;
    } elsif ($keyword =~ /^clean/i) {
        return 0;
    } else {
        my $notype = '';

        # Must be an infection report
        ($dot, $id, $part, @rest) = split(/\//, $filename);
        $part = '' if (!defined($part));
        if ($part ne '') {
            $notype = substr($part, 1);
            $logout =~ s/\Q$part\E/$notype/;
        }

        Baruwa::Scanner::Log::InfoLog("%s::%s", $Name, $logout)
          unless $ClamAVAlreadyLogged{"$id"} && $part eq '';
        $ClamAVAlreadyLogged{"$id"} = 1;

        #print STDERR "virus = \"$virusname\" re = \"$spaminfre\"\n";
        if ($virusname =~ /$spaminfre/) {

            # It's spam found as an infection
            # This is for clamavmodule and clamd
            # Use "u" to signify virus reports that are really spam
            # 20090730
            return "0 $id $virusname";
        }

   # Only log the whole message if no attachment has been logged
   # print STDERR "Part = \"$part\"\n";
   # print STDERR "Logged(\"$id\") = \"" . $ClamAVAlreadyLogged{"$id"} . "\"\n";

        $report = $Name . ': ' if $Name;
        if ($part eq '') {

            # No part ==> entire message is infected.
            $infections->{"$id"}{""} .=
              "$report message was infected: $virusname\n";
        } else {
            $infections->{"$id"}{"$part"} .=
              "$report$notype was infected: $virusname\n";
        }
        $types->{"$id"}{"$part"} .= 'v';    # it's a real virus
        return 1;
    }
}

sub ProcessGenericOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;
    my ($logout, $keyword, $virusname, $filename);
    my ($id,     $part,    @rest,      $report);

    chomp $line;
    $logout = $line;
    $logout =~ s/\s{20,}/ /g;
    ($keyword, $virusname, $filename) = split(/::/, $line, 3);

    if ($keyword =~ /^error/i) {
        Baruwa::Scanner::Log::InfoLog("GenericScanner::%s", $logout);
        return 1;
    }

    # Must be an infection report
    ($id, $part, @rest) = split(/\//, $filename);
    my $notype = substr($part, 1);
    $logout =~ s/\Q$part\E/$notype/;

    Baruwa::Scanner::Log::InfoLog("GenericScanner::%s", $logout);
    return 0 if $keyword =~ /^clean|^info/i;

    $report = $Name . ': ' if $Name;
    $infections->{"$id"}{"$part"} .=
      "$report$notype was infected by $virusname\n";
    $types->{"$id"}{"$part"} .= "v";    # it's a real virus
    return 1;
}

sub ProcessSophosOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;
    my ($report, $infected, $dot, $id, $part, @rest, $error);
    my ($logout);

    #print "$line";
    chomp $line;
    $logout = $line;
    $logout =~ s/%/%%/g;
    $logout =~ s/\s{20,}/ /g;
    Baruwa::Scanner::Log::InfoLog($logout) if $line =~ /error/i;

  # JKF Improved to handle multi-part split archives,
  # JKF which Sophos whinges about
  # >>> Virus 'EICAR-AV-Test' found in file /root/q/qeicar/eicar.com
  # >>> Virus 'EICAR-AV-Test' found in file /root/q/qeicar/eicar.doc
  # >>> Virus 'EICAR-AV-Test' found in file /root/q/qeicar/eicar.rar/eicar.com
  # >>> Virus 'EICAR-AV-Test' found in file /root/q/qeicar/eicar.rar3a/eicar.doc
  # >>> Virus 'EICAR-AV-Test' found in file /root/q/qeicar/eicar.rar3a/eicar.com
  # >>> Virus 'EICAR-AV-Test' found in file /root/q/qeicar/eicar.zip/eicar.com

    return 0
      unless $line =~
      /(virus.*found)|(could not check)|(password[\s-]*protected)/i;
    $report   = $line;
    $infected = $line;
    $infected =~ s/^.*found\s*in\s*file\s*//i;

    # Catch the extra stuff on the end of the line as well as the start
    $infected =~ s/^Could not check\s*(.+) \(([^)]+)\)$/$1/i;

    #print STDERR "Infected = \"$infected\"\n";
    $error = $2;

    #print STDERR "Error = \"$error\"\n";
    if ($error eq "") {
        $error = "Sophos detected password protected file"
          if $infected =~ s/^Password[ -]*protected\s+file\s+(.+)$/$1/i;

        #print STDERR "Error 2 = \"$error\"\n";
    }

    # If the error is one of the allowed errors, then don't report any
    # infections on this file.
    if ($error ne "") {

        # Treat their string as a command-separated list of strings, each of
        # which is in quotes. Any of the strings given may match.
        # If there are no quotes, then there is only 1 string (for backward
        # compatibility).
        my ($errorlist, @errorlist, @errorregexps, $choice);
        $errorlist = Baruwa::Scanner::Config::Value('sophosallowederrors');
        $errorlist =~ s/^\"(.+)\"$/$1/;    # Remove leading and trailing quotes
        @errorlist = split(/\"\s*,\s*\"/, $errorlist);    # Split up the list
        foreach $choice (@errorlist) {
            push @errorregexps, quotemeta($choice) if $choice =~ /[^\s]/;
        }
        $errorlist = join('|', @errorregexps);    # Turn into 1 big regexp

        if ($errorlist ne "" && $error =~ /$errorlist/i) {
            Baruwa::Scanner::Log::InfoLog($logout);
            Baruwa::Scanner::Log::WarnLog("Ignored Sophos '%s' error", $error);
            return 0;
        }
    }

    #$infected =~ s/^Could not check\s*//i;
    # JKF 10/08/2000 Used to split into max 3 parts, but this doesn't handle
    # viruses in zip files in attachments. Now pull out first 3 parts instead.
    ($dot, $id, $part, @rest) = split(/\//, $infected);

    my $notype = substr($part, 1);
    $logout =~ s/\Q$part\E/$notype/;
    $report =~ s/\Q$part\E/$notype/;
    Baruwa::Scanner::Log::InfoLog($logout);
    $report = $Name . ': ' . $report if $Name;
    $infections->{"$id"}{"$part"} .= $report . "\n";
    $types->{"$id"}{"$part"} .= "v";    # it's a real virus
    return 1;
}

# McAfee6 parser provided in its entirety by Michael Miller
# <michaelm@aquaorange.net>
sub ProcessMcAfee6Output {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;

    my ($report, $dot, $id, $part, @rest);
    my ($logout);
    my ($filename, $virusname);

    chomp $line;

    #Baruwa::Scanner::Log::InfoLog("McAfee6 said \"$line\"");

    # Should we worry about any warnings/errors?
    return 0 unless $line =~ /Found/;

    # McAfee prints the whole path including
    # ./message/part so make it the same
    # eg: /var/spool/baruwa/incoming/4118/./o3B07pUD004176/eicar.com
    #
    # strip off leading BaseDir
    $line =~ s/^$BaseDir//;

    # and then remaining /. (which may be removed in future as per v5 uvscan)
    $line =~ s/^\/\.//;

    # and put the leading . back in place
    $line =~ s/^/\./;

    $filename = $line;
    $filename =~ s/ \.\.\. Found.*$//;

    # get the virus name - not used currently
    # $virusname = $line;
    # $virusname =~ s/^.* \.\.\. Found.?//;

    $report = $line;
    $logout = $line;
    $logout =~ s/%/%%/g;
    $logout =~ s/\s{20,}/ /g;

    # note: '$dot' does become '.'
    ($dot, $id, $part, @rest) = split(/\//, $filename);

    # Infections found in the header must be handled specially here
    if ($id =~ /\.(?:header|message)/) {

        # The attachment name is "" ==> infection is whole messsage
        $part = "";

        # Correct the message id by deleting all from .header onwards
        $id =~ s/\.(?:header|message).*$//;
    }

    my $notype = substr($part, 1);
    $logout =~ s/\Q$part\E/$notype/;
    $report =~ s/\Q$part\E/$notype/;
    $report =~ s/ \.\.\. Found/ Found/;
    Baruwa::Scanner::Log::InfoLog($logout);

    $report = $Name . ': ' . $report if $Name;

    $infections->{"$id"}{"$part"} .= $report . "\n";
    $types->{"$id"}{"$part"} .= "v";
    return 1;
}

# This next function originally contributed in its entirety by
# "Richard Brookhuis" <richard@brookhuis.ath.cx>
#
# ./gBJNiNQG014777/eicar.zip->eicar.com is what a zip file looks like.
sub ProcessCommandOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;

    #my($line) = @_;

    my ($report, $infected, $dot, $id, $part, @rest);
    my ($logout);

    #print "$line";
    chomp $line;
    $logout = $line;
    $logout =~ s/%/%%/g;
    $logout =~ s/\s{20,}/ /g;
    Baruwa::Scanner::Log::InfoLog($logout) if $line =~ /error/i;
    if ($line =~
        /(is|could be) a (security risk|virus construction|joke program)/) {

        # Reparse the rest of the line to turn it into an infection report
        $line =~
          s/(is|could be) a (security risk|virus construction|joke program).*$/Infection: /;
    }

    return 0 unless $line =~ /Infection:/i;
    $report   = $line;
    $infected = $line;
    $infected =~ s/\s+Infection:.*$//i;

    # JKF 10/08/2000 Used to split into max 3 parts, but this doesn't handle
    # viruses in zip files in attachments. Now pull out first 3 parts instead.
    $infected =~ s/-\>/\//;    # JKF Handle archives rather better
    ($dot, $id, $part, @rest) = split(/\//, $infected);
    my $notype = substr($part, 1);
    $logout =~ s/\Q$part\E/$notype/;
    $report =~ s/\Q$part\E/$notype/;

    Baruwa::Scanner::Log::InfoLog($logout);
    $report = $Name . ': ' . $report if $Name;
    $infections->{"$id"}{"$part"} .= $report . "\n";
    $types->{"$id"}{"$part"} .= "v";    # it's a real virus
         #print "ID: $id  PART: $part  REPORT: $report\n";
    return 1;
}

# If you use Kaspersky, look at this code carefully
# and then be very grateful you didn't have to write it.
# Note that Kaspersky will now change long paths so they have "..."
# in the middle of them, removing the middle of the path.
# *WHY* do people have to do dumb things like this?
#
sub ProcessKasperskyOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;

    #my($line) = @_;

    my ($report, $infected, $dot, $id, $part, @rest);
    my ($logout);

    # Don't know what kaspersky means by "object" yet...

    # Lose trailing cruft
    return 0 unless defined $kaspersky_CurrentObject;

    if ($line =~ /^Current\sobject:\s(.*)$/) {
        $kaspersky_CurrentObject = $1;
    } elsif ($kaspersky_CurrentObject eq "") {

        # Lose leading cruft
        return 0;
    } else {
        chomp $line;
        $line =~ s/^\r//;

        # We can rely on BaseDir not having trailing slash.
        # Prefer s/// to m// as less likely to do unpredictable things.
        if ($line =~ /\sinfected:\s/) {
            $line =~
              s/.* \.\.\. (.*)/\.$1/;    # Kav will now put ... in long paths
            $report = $line;
            $logout = $line;
            $logout =~ s/%/%%/g;
            $logout =~ s/\s{20,}/ /g;
            $line =~ s/^$BaseDir//;
            $line =~ s/(.*) infected:.*/\.$1/;    # To handle long paths again
            ($dot, $id, $part, @rest) = split(/\//, $line);
            my $notype = substr($part, 1);
            $logout =~ s/\Q$part\E/$notype/;
            $report =~ s/\Q$part\E/$notype/;

            Baruwa::Scanner::Log::InfoLog($logout);
            $report = $Name . ': ' . $report if $Name;
            $infections->{"$id"}{"$part"} .= $report . "\n";
            $types->{"$id"}{"$part"} .= "v";    # so we know what to tell sender
            return 1;
        }

        # see commented code below if you think this regexp looks fishy
        if ($line =~ /^([\r ]*)Scan\sprocess\scompleted\.\s*$/) {
            undef $kaspersky_CurrentObject;
        }
    }
    return 0;
}

# It uses AvpDaemonClient from /opt/AVP/DaemonClients/Sample
# or AvpTeamDream from /opt/AVP/DaemonClients/Sample2.
# This was contributed in its entirety by
# Nerijus Baliunas <nerijus@USERS.SOURCEFORGE.NET>.
#
sub ProcessKavDaemonClientOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;

    #my($line) = @_;

    my ($report, $infected, $dot, $id, $part, @rest);
    my ($logout);

    chomp $line;
    $line =~ s/^\r//;

    # We can rely on BaseDir not having trailing slash.
    # Prefer s/// to m// as less likely to do unpredictable things.
    if ($line =~ /infected: /) {
        $line =~ s/.* \.\.\. (.*)/\.$1/;    # Kav will now put ... in long paths
        $report = $line;
        $logout = $line;
        $logout =~ s/%/%%/g;
        $logout =~ s/\s{20,}/ /g;
        $line =~ s/^$BaseDir//;
        $line =~ s/(.*)\sinfected:.*/\.$1/;    # To handle long paths again
        ($dot, $id, $part, @rest) = split(/\//, $line);
        my $notype = substr($part, 1);
        $logout =~ s/\Q$part\E/$notype/;
        $report =~ s/\Q$part\E/$notype/;

        Baruwa::Scanner::Log::InfoLog($logout);
        $report = $Name . ': ' . $report if $Name;
        $infections->{"$id"}{"$part"} .= $report . "\n";
        $types->{"$id"}{"$part"} .= "v";       # so we know what to tell sender
        return 1;
    }
    return 0;
}

# Sample output from version 4.50 of F-Secure:
# [./eicar2/eicar.zip] eicar.com: Infected: EICAR-Test-File [AVP]
# ./eicar2/eicar.co: Infected: EICAR_Test_File [F-Prot]
sub ProcessFSecureOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;

    my ($report, $infected, $dot, $id, $part, @rest);
    my ($logout, $virus, $BeenSeen);

    chomp $line;

    # Lose header
    if (   $fsecure_InHeader < 0
        && $line =~ /version ([\d.]+)/i
        && !$fsecure_Version) {
        $fsecure_Version = $1 + 0.0;
        $fsecure_InHeader -= 2
          if $fsecure_Version >= 4.51
          && $fsecure_Version < 4.60;
        $fsecure_InHeader -= 2 if $fsecure_Version <= 3.0;    # For F-Secure 5.5
           # Baruwa::Scanner::Log::InfoLog("Found F-Secure version $1=$fsecure_Version\n");
           # print STDERR "Version = $fsecure_Version\n";
        return 0;
    }
    if ($line eq "") {
        $fsecure_InHeader++;
        return 0;
    }

    # This test is more vague than it used to be, but is more tolerant to
    # output changes such as extra headers. Scanning non-scanning data is
    # not a great idea but causes no harm.
    # Before version 7.01 this was 0, but header changed again!
    $fsecure_InHeader >= -1 or return 0;

    $report = $line;
    $logout = $line;
    $logout =~ s/%/%%/g;
    $logout =~ s/\s{20,}/ /g;

    # If we are running the new version then there's a totally new parser here
    # F-Secure 5.5 reports version 1.10
    if ($fsecure_Version <= 3.0 || $fsecure_Version >= 4.50) {

        # ./g4UFLJR23090/Keld Jrn Simonsen: Infected: EICAR_Test_File [F-Prot]
        # ./g4UFLJR23090/Keld Jrn Simonsen: Infected: EICAR-Test-File [AVP]
        # ./g4UFLJR23090/cokegift.exe: Infected:   is a joke program [F-Prot]
        # Version 4.61:
        # ./eicar.com: Infected: EICAR_Test_File [Libra]
        # ./eicar.com: Infected: EICAR Test File [Orion]
        # ./eicar.com: Infected: EICAR-Test-File [AVP]
        # ./eicar.doc: Infected: EICAR_Test_File [Libra]
        # ./eicar.doc: Infected: EICAR Test File [Orion]
        # ./eicar.doc: Infected: EICAR-Test-File [AVP]
        # [./eicar.zip] eicar.com: Infected: EICAR_Test_File [Libra]
        # [./eicar.zip] eicar.com: Infected: EICAR Test File [Orion]
        # [./eicar.zip] eicar.com: Infected: EICAR-Test-File [AVP]

        return 0 unless $line =~ /: Infected: /;

        # The last 3 words are "Infected:" + name of virus + name of scanner
        $line =~ s/: Infected: +(.+) \[.*?\]$//;

        #print STDERR "Line is \"$line\"\n";
        Baruwa::Scanner::Log::NoticeLog(
            "Virus Scanning: F-Secure matched virus signature %s", $1);

        # We are now left with the filename, or
        # then archive name followed by the filename within the archive.
        $line =~ s/^\[(.*?)\] .*$/$1/;    # Strip signs of an archive

        # We now just have the filename
        ($dot, $id, $part, @rest) = split(/\//, $line);
        my $notype = substr($part, 1);
        $logout =~ s/\Q$part\E/$notype/;
        $report =~ s/\Q$part\E/$notype/;

        Baruwa::Scanner::Log::InfoLog($logout);
        $report = $Name . ': ' . $report if $Name;
        $infections->{"$id"}{"$part"} .= $report . "\n";
        $types->{"$id"}{"$part"} .= "v";    # so we know what to tell sender
             # Only report results once for each file
        return 0 if $fsecure_Seen{$line};
        $fsecure_Seen{$line} = 1;
        return 1;
    } else {

        # We are running the old version, so use the old parser
        # Prefer s/// to m// as less likely to do unpredictable things.
        # We hope.
        if ($line =~ /\tinfection:\s/) {

            # Get to relevant filename in a reasonably but not
            # totally robust manner (*impossible* to be totally robust
            # if we have square brackets and spaces in filenames)
            # Strip archive bits if present
            $line =~ s/^\[(.*?)\] .+(\tinfection:.*)/$1$2/;

            # Get to the meat or die trying...
            $line =~ s/\tinfection:([^:]*).*$//
              or Baruwa::Scanner::Log::DieLog(
                "Dodgy things going on in F-Secure output:\n$report\n");
            $virus = $1;
            $virus =~
              s/^\s*(\S+).*$/$1/;    # 1st word after Infection: is the virus
            Baruwa::Scanner::Log::NoticeLog(
                "Virus Scanning: F-Secure matched virus signature %s", $virus);

            ($dot, $id, $part, @rest) = split(/\//, $line);
            my $notype = substr($part, 1);
            $logout =~ s/\Q$part\E/$notype/;
            $report =~ s/\Q$part\E/$notype/;

            Baruwa::Scanner::Log::InfoLog($logout);
            $report = $Name . ': ' . $report if $Name;
            $infections->{"$id"}{"$part"} .= $report . "\n";
            $types->{"$id"}{"$part"} .= "v";    # so we know what to tell sender
            return 1;
        }
        Baruwa::Scanner::Log::DieLog(
            "Either you've found a bug in Baruwa's
            F-Secure output parser, or F-Secure's output format has changed!\n"
        );
    }
}

#
# Process the output of the F-Prot Version 6 command-line scanner
#
sub ProcessFProt6Output {
    my ($line, $infections, $types, $BaseDir, $Name, $spaminfre) = @_;
    my ($report, $dot, $id, $part, @rest);
    my ($logout);

    # Output looks like this:

# [Unscannable] <File is encrypted>  eicarnest.rar->eicar.rar
# [Clean]    eicarnest.rar
# [Found virus] <EICAR_Test_File (exact, not disinfectable)>     eicar.rar->eicar.com
# [Contains infected objects]    eicar.rar
# [Found virus] <EICAR_Test_File (exact, not disinfectable)>     eicar.zip->eicar.exe
# [Contains infected objects]    eicar.zip

    chomp $line;
    $logout = $line;
    $logout =~ s/\s+/ /g;

    return 0 unless $line =~ /^\[([^\]]+)\]\s+(\<([^>]+)\>)?\s+(.+)$/;
    my $Result    = $1; # Clean or Unscannable or report of a nasty
    my $Infection = $3; # What it found in the file, optional
    my $Filepath  = $4; # Relative path and an optional multiple '->member_name'
                        #print STDERR "Result    = \"$Result\"\n";
                        #print STDERR "Infection = \"$Infection\"\n";
                        #print STDERR "Filepath  = \"$Filepath\"\n";

    return 0 if $Result =~ /^Clean|Unscannable$/i;

    # Now dismantle $Filepath
    ($dot, $id, $part, @rest) = split(/\//, $Filepath);
    $part =~ s/\-\>.*$//;    # Scrap all the sub-parts
    my $notype = substr($part, 1);
    $logout =~ s/\Q$part\E/$notype/;
    $report =~ s/\Q$part\E/$notype/;

    Baruwa::Scanner::Log::WarnLog($logout);

    if ($Infection =~ /$spaminfre/) {

        # It's spam found as an infection
        # 20090730
        return "0 $id $Infection";
    }

    $report = "Found virus $Infection in $notype";
    $report = $Name . ': ' . $logout if $Name;

    #print STDERR "$report\n";
    $infections->{"$id"}{"$part"} .= $report . "\n";
    $types->{"$id"}{"$part"} .= "v";    # it's a real virus
    return 1;
}

# This function provided in its entirety by Ing. Juraj Hanták <hantak@wg.sk>
#
sub ProcessNOD32Output {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;
    my ($report, $infected, $dot, $id, $part, @rest);
    my ($logout);

    chomp $line;
    $logout = $line;
    $logout =~ s/%/%%/g;
    $logout =~ s/\s{20,}/ /g;
    Baruwa::Scanner::Log::WarnLog($logout) if $line =~ /error/i;

    # Yet another new NOD32 parser! :-(
    # This one is for 2.04 in which the output, again, looks totally different
    # to all the previous versions.
    if ($line =~
        /^object=\"file\",\s*name=\"([^\"]+)\",\s*(virus=\"([^\"]+)\")?/i) {
        my ($fileentry, $virusname) = ($1, $3);
        $fileentry =~ s/^$BaseDir//;
        ($dot, $id, $part, @rest) = split(/\//, $fileentry);
        $part =~ s/^.*\-\> //g;
        my $notype = substr($part, 1);

        #$logout =~ s/$part/$notype/;
        $report =~ s/\Q$part\E/$notype/;

        $report = "Found virus $virusname in $notype";
        $report = $Name . ': ' . $report if $Name;
        $infections->{"$id"}{"$part"} .= $report . "\n";
        $types->{"$id"}{"$part"} .= "v";    # it's a real virus
        return 1;
    }

    if (  !$NOD32Version
        && $NOD32InHeading > 0
        && $line =~ /^NOD32.*Version[^\d]*([\d.]+)/) {
        $NOD32Version = $1;
        $NOD32InHeading--;    # = 0;
        return 0;
    }
    $NOD32InHeading-- if /^$/;    # Was = 0
    return 0 unless $line =~ /\s-\s/i;

    if ($NOD32Version >= 1.990) {

        # New NOD32 output parser
        $line =~ /(.*) - (.*)$/;
        my ($file, $virus) = ($1, $2);
        return 0 if $virus =~ /not an archive file|is OK/;
        return 0 if $file =~ /^  /;
        ($dot, $id, $part, @rest) = split(/\//, $file);
        my $notype = substr($part, 1);
        $line =~ s/\Q$part\E/$notype/;

        Baruwa::Scanner::Log::InfoLog("%s", $line);
        $report = $line;
        $report = $Name . ': ' . $report if $Name;
        $infections->{"$id"}{"$part"} .= $report . "\n";
        $types->{"$id"}{"$part"} .= "v";    # it's a real virus
        return 1;
    } else {

        # Pull out the last line of the output text
        my (@lines);
        chomp $line;
        chomp $line;
        @lines = split(/[\r\n]+/, $line);
        $line = $lines[$#lines];

        #my ($part1,$part2,$part3,$part4,@ostatne)=split(/\.\//,$line);
        #$line="./".$part4;
        $logout = $line;
        $logout =~ s/%/%%/g;
        $logout =~ s/\s{20,}/ /g;
        $report   = $line;
        $infected = $line;
        $infected =~ s/^.*\s*-\s*//i;

      # JKF 10/08/2000 Used to split into max 3 parts, but this doesn't handle
      # viruses in zip files in attachments. Now pull out first 3 parts instead.
        ($dot, $id, $part, @rest) = split(/[\/,-]/, $report);
        $part =~ s/\s$//g;
        my $notype = substr($part, 1);
        $logout =~ s/\Q$part\E/$notype/;
        $report =~ s/\Q$part\E/$notype/;

        Baruwa::Scanner::Log::InfoLog($logout);
        $report = $Name . ': ' . $report if $Name;
        $infections->{"$id"}{"$part"} .= $report . "\n";
        $types->{"$id"}{"$part"} .= "v";    # it's a real virus

        return 1;
    }
}

# This function originally contributed by Héctor García Álvarez
# <hector@lared.es>
# From comment (now removed), it looks to be based on Sophos parser at
# some point in its history.
# Updated by Rick Cooper <rcooper@dwford.com> 05/10/2005
#
sub ProcessPandaOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;
    my ($report, $infected, $dot, $id, $part, @rest);
    my ($numviruses);

    # Return if there were no viruses found
    return 0 if $line =~ /^Virus: 0/i;

    my $ErrStr = "";
    $ErrStr = $line if $line =~ /^Panda:ERROR:/;
    $ErrStr =~ s/^Panda:ERROR:(.+)/$1/ if $ErrStr ne "";
    chomp($ErrStr) if $ErrStr ne "";
    Baruwa::Scanner::Log::InfoLog("Panda WARNING: %s", $ErrStr)
      if $ErrStr ne "";
    return 0 if $ErrStr ne "";

# the wrapper returns the information in the following format
# EXAMPLE OUTPUT PLEASE? -- nwp 6/5/02
# FOUND: EICAR-AV-TEST-FILE  ##::##eicar_com.zip##::##1DVXmB-0006R4-Fv##::##/var/spool/baruwa/incoming/24686
# Virus Name                File Name          Message Dir               Base Dir

    my $temp = $line;
    $numviruses = 0;

    # If the line is a virus report line parse it
    # Simple
    while ($temp =~ /\t\tFOUND:(.+?)##::##(.+?)##::##(.+?)##::##(.+?)$/) {
        $part    = $2;
        $BaseDir = $4;
        $id      = $3;
        $report  = $1;
        $report =~ s/^\s+|\s+$|\t|\n//g;
        $report = $report . " found in $part";
        $report = $Name . ": " . $report if $Name;
        $report =~ s/\s{2,}/ /g;

        # Make Sure $part is the parent for reporting, otherwise this
        # doesn't show up in user reports.
        $part =~ s/^(.+)\-\>(.+)/$1/;
        my $notype = substr($part, 1);
        $report =~ s/\Q$part\E/$notype/;

        Baruwa::Scanner::Log::InfoLog("%s", $report);
        $infections->{"$id"}{"$part"} .= "$report\n";

        #print STDERR "'$part'\n";
        $types->{"$id"}{"$part"} .= "v";
        $numviruses++;
        $temp = $';
    }

    return $numviruses;

}

# Parse the output of the DrWeb output.
# Konrad Madej <kmadej@nask.pl>
sub ProcessDrwebOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;
    chomp $line;

    return 0 unless $line =~ /^(.+)\s+infected\s+with\s+(.*)$/i;

    my ($file, $virus) = ($1, $2);
    my $logout = $line;
    $logout =~ s/\s{20,}/ /g;

    # Sample output:
    #
    # /tmp/del.com infected with EICAR Test File (NOT a Virus!)
    # or
    # >/tmp/del1.com infected with EICAR Test File (NOT a Virus!)

    # Remove path elements before /./, // if any and
    # , >, $BaseDir leaving just id/part/rest
    $file =~ s/\/\.\//\//g;
    $file =~ s/\/\//\//g;
    $file =~ s/^>+//g;
    $file =~ s/^$BaseDir//;
    $file =~ s/^\///g;

    my ($id, $part, @rest) = split(/\//, $file);

    #Baruwa::Scanner::Log::InfoLog("#### $BaseDir - $id - $part");
    my $notype = substr($part, 1);
    $logout =~ s/\Q$part\E/$notype/;

    Baruwa::Scanner::Log::InfoLog("%s", $logout);

    $infections->{$id}{$part} .= $Name . ': ' if $Name;
    $infections->{$id}{$part} .= "Found virus $virus in file $notype\n";
    $types->{$id}{$part} .= "v";    # so we know what to tell sender
    return 1;
}

# Parse the output of the Trend VirusWall vscan output.
# Contributed in its entirety by Martin Lorensen <mlo@uni2.dk>
sub ProcessTrendOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;
    chomp $line;

    return
      if $line =~
      /^\s*(=====|Directory:|Searched :|File:|Searched :|Scan :|Infected :|Time:|Start :|Stop :|Used :|Configuration:|$)/;

    # Next line didn't work with zip (and other) archives
    #$line =~ y/\t//d and $trend_prevline = $line;
    $line =~ s/^\t+\././ and $trend_prevline = $line;

    #Baruwa::Scanner::Log::InfoLog("%s", $line);

# Sample output:
#
# Scanning 2 messages, 1944 bytes
# Virus Scanner v3.1, VSAPI v5.500-0829
# Trend Micro Inc. 1996,1997
# ^IPattern version 329
# ^IPattern number 46849
# Configuration: -e'{*
# Directory .
# Directory ./g72CdVd6018935
# Directory ./g72CdVd7018935
# ^I./g72CdVd7018935/eicar.com
# *** Found virus Eicar_test_file in file /var/spool/baruwa/incoming_virus/g72CdVd7018935/eicar.com

    if ($line =~ /Found virus (\S+) in file/i) {
        my ($virus) = $1;    # Name of virus found
          # Unfortunately vscan shows the full filename even though it was given
          # a relative name to scan. The previous line is relative, though.
          # So use that instead.

        my ($dot, $id, $part, @rest) = split(/\//, $trend_prevline);
        my $notype = substr($part, 1);
        $trend_prevline =~ s/\Q$part\E/$notype/;

        $infections->{$id}{$part} .= $Name . ': ' if $Name;
        $infections->{$id}{$part} .=
          "Found virus $virus in file $trend_prevline\n";
        $types->{$id}{$part} .= "v";    # so we know what to tell sender
        Baruwa::Scanner::Log::NoticeLog("Trend found %s in %s",
            $virus, $trend_prevline);
        return 1;
    }
    return 0;
}

# Parse the output of the Bitdefender bdc output.
sub ProcessBitdefenderOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;
    chomp $line;

    #print STDERR "$line\n";
    return 0 unless $line =~ /\t(infected|suspected): ([^\t]+)$/;

    my $virus  = $2;
    my $logout = $line;
    $logout =~ s/\s{20,}/ /g;

    #print STDERR "virus = \"$virus\"\n";
    # strip the base from the message dir and remove the ^I junk
    $logout =~ s/^.+\/\.\///;    # New
    $logout =~ s/\cI/:/g;        # New

    # Sample output:
    #
    # /var/spool/baruwa/incoming/1234/./msgid/filename  infected: virus
    # /var/spool/baruwa/incoming/1234/./msgid/filename=>subpart infected: virus

    # Remove path elements before /./ leaving just id/part/rest
    # 20090311 Remove leading BaseDir if it's there too.
    $line =~ s/^$BaseDir\///;
    $line =~ s/^.*\/\.\///;
    my ($id, $part, @rest) = split(/\//, $line);

    $part =~ s/\t.*$//;
    $part =~ s/=\>.*$//;

    my $notype = substr($part, 1);
    $logout =~ s/\Q$part\E/$notype/;

    Baruwa::Scanner::Log::InfoLog("%s", $logout);

    #print STDERR "id = $id\npart = $part\n";
    $infections->{$id}{$part} .= $Name . ': ' if $Name;
    $infections->{$id}{$part} .= "Found virus $virus in file $notype\n";
    $types->{$id}{$part} .= "v";    # so we know what to tell sender
    return 1;
}

# Parse Symantec CSS Output.
# Written by Martin Foster <martin_foster@pacific.net.au>.
# Modified by Kevin Spicer <kevin@kevinspicer.co.uk> to handle output
# of cscmdline.
sub ProcessCSSOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;
    my ($css_virus, $css_report, $logline, $file, $ReportStart);

    chomp $line;
    $logline = $line;
    $logline =~ s/%/%%/g;
    $logline =~ s/\s{20,}/ /g;
    if ($line =~ /^\*\*\*\*\s+ERROR!/) {
        Baruwa::Scanner::Log::WarnLog($logline);
        return 0;
    }

    if ($line =~ /^File:\s+(.*)$/) {
        $css_filename = $1;
        $css_infected = "";
        return 0;
    }
    if ($line =~ /^Infected:\s+(.*)$/) {
        $css_infected = $1;
        return 0;
    }
    if ($line =~ /^Info:\s+(.*)\s*\(.*\)$/) {
        $css_virus = $1;

        # Okay, we have three pieces of information...
        # $css_filename - the name of the scanned file
        # $css_infected - the name of the infected file (maybe subpart of
        #                 an archive)
        # $css_virus    - virus name etc.

        # Wipe out the original filename from the infected report
        $css_infected =~ s/^\Q$css_filename\E(\/)?//;

        # If anything is left this is a subfile of an archive
        if ($css_infected ne "") {$css_infected = "in part $css_infected"}

        $file = $css_filename;
        $file =~ s/^(.\/)?$BaseDir\/?//;
        $file =~ s/^\.\///;
        my ($id, $part) = split /\//, $file, 2;
        my $notype = substr($part, 1);
        $logline =~ s/\Q$part\E/$notype/;
        Baruwa::Scanner::Log::WarnLog($logline);

        $ReportStart = $notype;
        $ReportStart = $Name . ': ' . $ReportStart if $Name;
        $infections->{"$id"}{"$part"} .=
          "$ReportStart contains $css_virus $css_infected\n";
        $types->{"$id"}{"$part"} .= "v";
        return 1;
    }

    # Drop through - weed out known reporting lines
    if (   $line =~ /^Symantec CarrierScan Version/
        || $line =~ /^Cscmdline Version/
        || $line =~ /^Command Line:/
        || $line =~ /^Completed.\s+Directories:/
        || $line =~ /^Virus Definitions:/
        || $line =~ /^File \[.*\] was infected/
        || $line =~ /^Scan (start)|(end):/
        || $line =~
        /^\s+(Files Scanned:)|(Files Infected:)|(Files Repaired:)|(Errors:)|(Elapsed:)/
      ) {
        return 0;
    }

    return 0 if $line =~ /^$/;    # Catch blank lines
    $logline = $line;
    $logline =~ s/%/%%/g;
    Baruwa::Scanner::Log::WarnLog("ProcessCSSOutput: unrecognised "
          . "line \"$logline\". Please contact the authors!");

    return 0;
}

#my($SSEFilename, $SSEVirusname, $SSEVirusid, $SSEFilenamelog);
sub ProcessSymScanEngineOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;

    chomp $line;

    if ($line =~ /^(\.\/.*) had [0-9]+ infection\(s\):/) {

        # Start of the report for a new file. Initialise state machine.
        #print STDERR "Found report about $1\n";
        $SSEFilename    = $1;
        $SSEVirusname   = '';
        $SSEVirusid     = 0;
        $SSEFilenamelog = '';
        return 0;
    }
    if ($line =~ /^\s+File Name:\s+(.*)$/) {

        #print STDERR "Filenamelog = $1\n";
        $SSEFilenamelog = $1;
        return 0;
    }
    if ($line =~ /^\s+Virus Name:\s+(.*)$/) {

        #print STDERR "Virusname = $1\n";
        $SSEVirusname = $1;
        return 0;
    }
    if ($line =~ /^\s+Virus ID:\s+(.*)$/) {

        #print STDERR "Virusid = $1\n";
        $SSEVirusid = $1 + 0;
        return 0;
    }
    if ($line =~ /^\s+Disposition:\s+(.*)$/) {

        #print STDERR "Got Disposition\n";
        # This is the last lin of each file report, so use as the trigger
        # to process the file. But we can have multiple reports for the same
        # $SSEFilename, the other lines are just repeated.

        # If the Virusid < 0 then we don't care about this report.
        # If the report was about a message header then we also don't care.
        return 0 if $SSEVirusid < 0 || $SSEFilename =~ /\.header$/;

      # # If the report was about the full message file, then handle that too.
      # $SSEFilename =~ s/\/message$// if $SSEFilename =~ /^\.\/[^/]+\/message/;

        # If there were lines missing, then scream about it!
        if ($SSEVirusname eq '' || $SSEFilenamelog eq '') {
            Baruwa::Scanner::Log::WarnLog(
                "SymantecScanEngine: Output Parser Failure!");
        }

        #print STDERR "Building report about $SSEFilename $SSEVirusname\n";
        # It's a report we care about
        my ($dot, $id, $part, @rest) = split(/\//, $SSEFilename);
        my $notype = substr($part, 1);

        Baruwa::Scanner::Log::InfoLog(
            "SymantecScanEngine::$notype $SSEVirusname");
        my $report = $Name . ': ' if $Name;
        $infections->{"$id"}{"$part"} .=
          "$report$notype was infected: $SSEVirusname\n";
        $types->{"$id"}{"$part"} .= "v";    # it's a real virus
             #print STDERR "id=$id\tpart=$part\tVirusname=$SSEVirusname\n";
        return 1;
    }
    return 0;
}

sub ProcessAvastOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;

    chomp $line;

    #Baruwa::Scanner::Log::InfoLog("Avast said \"$line\"");

    # Extract the infection report. Return 0 if it's not there or is OK.
    return 0 unless $line =~ /\t\[(.+)\]$/;
    my $infection = $1;
    return 0 if $infection =~ /^OK$/i;
    my $logout = $line;

    # Avast prints the whole path as opposed to
    # ./messages/part so make it the same
    $line =~ s/^Archived\s//i;
    $line =~ s/^$BaseDir//;

    #my $logout = $line;
    #$logout =~ s/%/%%/g;
    #$logout =~ s/\s{20,}/ /g;
    #$logout =~ s/^\///;
    #Baruwa::Scanner::Log::InfoLog("%s found %s", $Name, $logout);

    # note: '$dot' does not become '.'
    # This removes the "Archived" bit off the front if present, too :)
    $line =~ s/\t\[.+\]$//;    # Trim the virus report off the end
    my ($dot, $id, $part, @rest) = split(/\//, $line);
    my $notype = substr($part, 1);
    $logout =~ s/\Q$part\E/$notype/;
    $infection =~ s/\Q$part\E/$notype/;

    Baruwa::Scanner::Log::InfoLog("%s", $logout);

    #print STDERR "Dot, id, part = \"$dot\", \"$id\", \"$part\"\n";
    $infection = $Name . ': ' . $infection if $Name;
    $infections->{"$id"}{"$part"} .= $infection . "\n";
    $types->{"$id"}{"$part"} .= "v";

    #print STDERR "Infection = $infection\n";
    return 1;
}

sub ProcessAvastdOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;

    chomp $line;

    #Baruwa::Scanner::Log::InfoLog("Avastd said \"$line\"");

    # Extract the infection report. Return 0 if it's not there or is OK.
    return 0 unless $line =~ /\t\[([^[]+)\](\t(.*))?$/;
    my $result    = $1;
    my $infection = $3;
    return 0 if $result eq '+';
    my $logout = $line;
    Baruwa::Scanner::Log::WarnLog(
        "Avastd scanner found new response type \"%s\"", $result)
      if $result ne 'L';

    # Avast prints the whole path as opposed to
    # ./messages/part so make it the same
    $line =~ s/^$BaseDir//;

    # my $logout = $line;
    # $logout =~ s/%/%%/g;
    # $logout =~ s/\s{20,}/ /g;
    # $logout =~ s/^\///;
    # Baruwa::Scanner::Log::InfoLog("%s found %s", $Name, $logout);

    # note: '$dot' does not become '.'
    # This removes the "Archived" bit off the front if present, too :)
    $line =~ s/\t\[[^[]+\]\t.*$//;    # Trim the virus report off the end
    my ($dot, $id, $part, @rest) = split(/\//, $line);

    #print STDERR "Dot, id, part = \"$dot\", \"$id\", \"$part\"\n";
    my $notype = substr($part, 1);
    $logout =~ s/\Q$part\E/$notype/;
    $infection =~ s/\Q$part\E/$notype/;

    Baruwa::Scanner::Log::InfoLog("%s", $logout);
    $infection = $Name . ': ' . $infection if $Name;
    $infections->{"$id"}{"$part"} .= $infection . "\n";
    $types->{"$id"}{"$part"} .= "v";

    #print STDERR "Infection = $infection\n";
    return 1;
}

# This function provided in its entirety by Phil (UxBoD)
#
sub ProcessesetsOutput {
    my ($line, $infections, $types, $BaseDir, $Name) = @_;
    my ($report, $infected, $dot, $id, $part, @rest);
    my ($logout);

    chomp $line;
    $logout = $line;
    $logout =~ s/%/%%/g;
    $logout =~ s/\s{20,}/ /g;
    Baruwa::Scanner::Log::WarnLog($logout)
      if $line =~ /error/i && $line !~ /error - unknown compression method/i;

    if ($line =~
        /^object=\"file\",\s*name=\"([^\"]+)\",\s*(virus=\"([^\"]+)\")?/i) {
        my ($fileentry, $virusname) = ($1, $3);
        $fileentry =~ s/^$BaseDir//;
        ($dot, $id, $part, @rest) = split(/\//, $fileentry);
        $part =~ s/^.*\-\> //g;
        my $notype = substr($part, 1);
        $logout =~ s/\Q$part\E/$notype/;

        Baruwa::Scanner::Log::InfoLog($logout);
        $report = "Found virus $virusname in $notype";
        $report = $Name . ': ' . $report if $Name;
        $infections->{"$id"}{"$part"} .= $report . "\n";
        $types->{"$id"}{"$part"} .= "v";    # it's a real virus
        return 1;
    }

    # This is for Esets 3.0.
    # name="./1/eicar.com", threat="Eicar test file", action="", info=""
    # Added modified patch from Alex Broens to pull out virus members.
    if ($line =~ /^\s*name=\"([^\"]+)\",\s*threat=\"([^\"]+)\"/i) {
        my ($filename, $virusname) = ($1, $2);

        #print STDERR "Found filename \"$filename\" and virusname $virusname\n";
        $filename =~ s/ \xbb .*$//;    # Delete rest of archive internal names
        ($dot, $id, $part, @rest) = split(/\//, $filename);
        my $notype = substr($part, 1);
        $logout =~ s/\Q$part\E/$notype/;

        Baruwa::Scanner::Log::InfoLog($logout);
        $report = "Found virus $virusname in $notype";
        $report = $Name . ': ' . $report if $Name;
        $infections->{"$id"}{"$part"} .= $report . "\n";
        $types->{"$id"}{"$part"} .= "v";    # it's a real virus
        return 1;
    }
}

# Generate a list of all the virus scanners that are installed. It may
# include extras that are not installed in the case where there are
# scanners whose name includes a version number and we could not tell
# the difference.
sub InstalledScanners {

    my (@installed, $scannername, $nameandpath, $name, $path, $command,
        $result);

    # Get list of all the names of the scanners to look up. There are a few
    # rogue ones!
    my @scannernames = keys %Scanners;
    # print STDERR "Keys=>@scannernames\n";

    foreach $scannername (@scannernames) {
        next unless $scannername;
        next if $scannername =~ /generic|none/i;
        # print STDERR "NAME=>$scannername\n";
        $nameandpath = Baruwa::Scanner::Config::ScannerCmds($scannername);
        # print STDERR "NAME=>$nameandpath\n";
        next unless defined($nameandpath);
        ($name, $path) = split(',', $nameandpath);
        $command = "$name $path -IsItInstalled";

        # print STDERR "$command gave: ";
        # $result = system($command) >> 8;
        $result = call_system($command);

        #print STDERR "\"$result\"\n";
        push @installed, $scannername unless $result;
    }

    if (ClamdScan('ISITINSTALLED') eq 'CLAMDOK') {

        # If clamav is in the list, replace it with clamd, else add clamd
        my $foundit = 0;
        foreach (@installed) {
            if ($_ eq 'clamav') {
                s/^clamav$/clamd/;
                $foundit = 1;
                last;
            }
        }
        push @installed, 'clamd' unless $foundit;
    }
    if (Fprotd6Scan('ISITINSTALLED') eq 'FPSCANDOK') {

       # If f-prot-6 is in the list, replace it with f-protd6, else add f-protd6
        my $foundit = 0;
        foreach (@installed) {
            if ($_ eq 'f-prot-6') {
                s/^f-prot-6$/f-protd-6/;
                $foundit = 1;
                last;
            }
        }
        push @installed, 'f-protd-6' unless $foundit;
    }

    # print STDERR "Found list of installed scanners \"" . join(', ', @installed) . "\"\n";
    return @installed;
}

# Should be called when we're about to try to run some code to
# scan or disinfect (after checking that code is present).
# Nick: I'm not convinced this is really worth the bother, it causes me
#       quite a lot of work explaining it to people, and I don't think
#       that the people who should be worrying about this understand
#       enough about it all to know that they *should* worry about it.
sub CheckCodeStatus {
    my ($codestatus) = @_;
    my ($allowedlevel);

    my $statusname = Baruwa::Scanner::Config::Value('minimumcodestatus');

    $allowedlevel = $S_SUPPORTED;
    $allowedlevel = $S_BETA if $statusname =~ /^beta/i;
    $allowedlevel = $S_ALPHA if $statusname =~ /^alpha/i;
    $allowedlevel = $S_UNSUPPORTED if $statusname =~ /^unsup/i;
    $allowedlevel = $S_NONE if $statusname =~ /^none/i;

    return 1 if $codestatus >= $allowedlevel;

    Baruwa::Scanner::Log::WarnLog("FATAL: Encountered code that does not meet "
          . "configured acceptable stability");
    Baruwa::Scanner::Log::DieLog("FATAL: Baruwa is unable to start");
}

sub ClamdScan {
    my ($dirname, $disinfect, $messagebatch) = @_;
    my ($dir, $child, $childname, $filename, $results, $virus);

    my $lintonly = 0;
    $lintonly = 1 if $dirname eq 'ISITINSTALLED';

    # Clamd MUST have the full path to the file/dir it's scanning
    # so let's build the scan dir here and remove that pesky \. at the end
    my $ScanDir = "$global::MS->{work}->{dir}/$dirname";
    $ScanDir =~ s/\/\.$//;

    # The default scan type is set here and if threading has been enabled
    # switch to threaded scanning
    my $ScanType = "CONTSCAN";
    my $LockFile = Baruwa::Scanner::Config::Value('clamdlockfile');
    $LockFile = '' if $lintonly;    # Not dependent on this for --lint
    my $TCP        = 1;
    my $TimeOut    = Baruwa::Scanner::Config::Value('virusscannertimeout');
    my $UseThreads = Baruwa::Scanner::Config::Value('clamdusethreads');
    $ScanType = "MULTISCAN" if $UseThreads;

    my $PingTimeOut = 90;    # should respond much faster than this to PING
    my $Port   = Baruwa::Scanner::Config::Value('clamdport');
    my $Socket = Baruwa::Scanner::Config::Value('clamdsocket');
    my $line   = '';
    my $sock;

    # If we did not receive a socket file name then we run in TCP mode

    $TCP = 0 if $Socket =~ /^\//;

    # Print our current parameters if we are in debug mode
    Baruwa::Scanner::Log::DebugLog("Debug Mode Is On");
    Baruwa::Scanner::Log::DebugLog("Use Threads : YES") if $UseThreads;
    Baruwa::Scanner::Log::DebugLog("Use Threads : NO") unless $UseThreads;
    Baruwa::Scanner::Log::DebugLog("Socket    : %s", $Socket) unless $TCP;
    Baruwa::Scanner::Log::DebugLog("IP        : %s", $Socket) if $TCP;
    Baruwa::Scanner::Log::DebugLog("IP        : Using Sockets") unless $TCP;
    Baruwa::Scanner::Log::DebugLog("Port      : %s", $Port) if $TCP;
    Baruwa::Scanner::Log::DebugLog("Lock File : %s", $LockFile)
      if $LockFile ne '';
    Baruwa::Scanner::Log::DebugLog("Lock File : NOT USED", $LockFile)
      unless $LockFile ne '';
    Baruwa::Scanner::Log::DebugLog("Time Out  : %s", $TimeOut);
    Baruwa::Scanner::Log::DebugLog("Scan Dir  : %s", $ScanDir);

    # Exit if we cannot find the socket file, or we find the file but it's not
    # a socket file (and of course we are not using TCP sockets)

    if (!$TCP && !-e $Socket) {
        Baruwa::Scanner::Log::WarnLog("Cannot find Socket (%s) Exiting!",
            $Socket)
          if !$TCP && !-e $Socket && !$lintonly;
        print "ScAnNeRfAiLeD\n" unless $lintonly;
        return 1;
    }

    if (!$TCP && !-S $Socket) {
        Baruwa::Scanner::Log::WarnLog(
            "Found %s but it is not a valid UNIX Socket. " . "Exiting", $Socket)
          if !$TCP && !-S $Socket && !$lintonly;
        print "ScAnNeRfAiLeD\n" unless $lintonly;
        return 1;
    }

    # If there should be a lock file, and it's missing the we assume
    # the daemon is not running and warn, pass error to parser and leave
    if ($LockFile ne '' && !-e $LockFile) {
        Baruwa::Scanner::Log::WarnLog(
            "Lock File %s Not Found, Assuming Clamd " . "Is Not Running",
            $LockFile)
          unless $lintonly;
        print "ERROR:: Lock File $LockFile was not found, assuming Clamd  "
          . "is not currently running :: $dirname\n"
          unless $lintonly;
        print "ScAnNeRfAiLeD\n" unless $lintonly;
        return 1;
    }

    # Connect to the clamd daemon, If we don't connect send the log and
    # parser an error message and exit.
    $sock = ConnectToClamd($TCP, $Socket, $Port, $TimeOut);
    unless ($sock || $lintonly) {
        print "ERROR:: COULD NOT CONNECT TO CLAMD, RECOMMEND RESTARTING DAEMON "
          . ":: $dirname\n";
        print "ScAnNeRfAiLeD\n" unless $lintonly;
        return 1;
    }
    unless ($sock) {
        Baruwa::Scanner::Log::WarnLog("ERROR:: COULD NOT CONNECT TO CLAMD, "
              . "RECOMMEND RESTARTING DAEMON ")
          unless $sock || $lintonly;
        print "ScAnNeRfAiLeD\n" unless $lintonly;
        return 1;
    }

    # If we got here we know we have a socket file but it could be dead
    # or clamd may not be listening on the TCP socket we are using, either way
    # we exit with error if we could not open the connection

    if (!$sock) {    # socket file from a dead clamd or clamd is not listening
        Baruwa::Scanner::Log::WarnLog("Could not connect to clamd")
          unless $lintonly;
        print "ERROR:: COULD NOT CONNECT TO CLAMD DAEMON  " . ":: $dirname\n"
          unless $lintonly;
        print "ScAnNeRfAiLeD\n" unless $lintonly;
        return 1;
    } else {

        # Make sure the daemon is responsive before passing it something to
        # scan
        if ($sock->connected) {
            Baruwa::Scanner::Log::DebugLog("Clamd : Sending PING");
            $sock->send("PING\n");
            $PingTimeOut += time();
            $line = '';

            while ($line eq '') {
                $line = <$sock>;

              # if we timeout then print error (if debugging) and exit with erro
                Baruwa::Scanner::Log::WarnLog(
                    "ClamD Timed Out During PING " . "Check!")
                  if $PingTimeOut < time && !$lintonly;
                print "ERROR:: CLAM PING TIMED OUT! :: " . "$dirname\n"
                  if time > $PingTimeOut && !$lintonly;
                if (time > $PingTimeOut) {
                    print "ScAnNeRfAiLeD\n" unless $lintonly;
                    return 1;
                }
                last if time > $PingTimeOut;
                chomp($line);
            }

            Baruwa::Scanner::Log::DebugLog("Clamd : GOT '%s'", $line);
            Baruwa::Scanner::Log::WarnLog(
                "ClamD Responded '%s' Instead of PONG "
                  . "During PING Check, Recommend Restarting Daemon",
                $line
            ) if $line ne 'PONG' && !$lintonly;
            unless ($line eq "PONG" || $lintonly) {
                print "ERROR:: CLAMD DID NOT RESPOND PROPERLY TO PING! PLEASE "
                  . "RESTART DAEMON :: $dirname\n";
                print "ScAnNeRfAiLeD\n" unless $lintonly;
            }
            close($sock);
            return 1 unless $line eq "PONG";
            Baruwa::Scanner::Log::DebugLog("ClamD is running\n");
        } else {
            Baruwa::Scanner::Log::WarnLog(
                "ClamD has an Unknown problem, recommend you re-start the daemon!"
            ) unless $lintonly;
            print "ERROR:: CLAMD HAS AN UNKNOWN PROBLEM, RECOMMEND YOU "
              . "RESTART THE DAEMON :: $dirname\n"
              unless $lintonly;
            print "ScAnNeRfAiLeD\n" unless $lintonly;
            return 1;
        }
    }

    # If we are just checking to see if it's installed, bail out now
    return 'CLAMDOK' if $lintonly;

    # Attempt to reopen the connection to clamd
    $sock = ConnectToClamd($TCP, $Socket, $Port, $TimeOut);
    unless ($sock) {
        print "ERROR:: COULD NOT CONNECT TO CLAMD, RECOMMEND RESTARTING DAEMON "
          . ":: $dirname\n";
        Baruwa::Scanner::Log::WarnLog("ERROR:: COULD NOT CONNECT TO CLAMD, "
              . "RECOMMEND RESTARTING DAEMON ");
        print "ScAnNeRfAiLeD\n" unless $lintonly;
        return 1;
    }

    if ($sock->connected) {

        # Going to Scan the entire batch at once, should really speed things
        # up especially on SMP hosts running mutli-threaded scaning
        $TimeOut += time();

        $sock->send("$ScanType $ScanDir\n");
        Baruwa::Scanner::Log::DebugLog("SENT : $ScanType %s ", "$ScanDir");
        $results = '';
        my $ResultString = '';

        while ($results = <$sock>) {

            # if we timeout then print error and exit with error
            if (time > $TimeOut) {
                Baruwa::Scanner::Log::WarnLog("ClamD Timed Out!");
                close($sock);
                print "ERROR:: CLAM TIMED OUT! :: " . "$dirname\n";
                print "ScAnNeRfAiLeD\n" unless $lintonly;
                return 1;
            }

            # Append this file to any others already found
            $ResultString .= $results;
        }

        # Remove the trailing line feed and create an array of
        # lines for sending to the parser
        chomp($ResultString);
        my @report = split("\n", $ResultString);

        foreach $results (@report) {

            #print STDERR "Read \"$results\"\n";
            # Pull the basedir out and change it to a dot for the parser
            $results =~ s/$ScanDir/\./;
            $results =~ s/:\s/\//;

            # If we get an access denied error then print the properly
            # formatted error and leave
            print STDERR
              "ERROR::Permissions Problem. Clamd was denied access to "
              . "$ScanDir::$ScanDir\n"
              if $results =~ /\.\/Access denied\. ERROR/;
            last if $results =~ /\.\/Access denied\. ERROR/;

            # If scanning full batch clamd returns OK on the directory
            # name at the end of the scan so we discard that result when
            # we get to it
            next if $results =~ /^\.\/OK/;

            # Workaround for MSRBL-Images (www.msrbl.com/site/msrblimagesabout)
            $results =~ s#MSRBL-Images/#MSRBL-Images\.#;
            my ($dot, $childname, $filename, $rest) =
              split('/', $results, 4);

            unless ($results) {
                print "ERROR:: $results :: $dirname/$childname/$filename\n";
                next;
            }

            # SaneSecurity ClamAV database can find things in the headers
            # of the message. The parser above results in $childname ending
            # in '.header' and $rest ends in ' FOUND'. In this case we need
            # to report a null childname so the infection is mapped to the
            # entire message.
            if (   $childname =~ /\.(?:header|message)$/
                && $filename =~ /\sFOUND$/) {
                $rest     = $filename;
                $filename = '';
                $childname =~ s/\.(?:header|message)$//;
                print "INFECTED::";
                $rest =~ s/\sFOUND$//;
                print " $rest :: $dirname/$childname/$filename\n";
            }

            elsif ($rest =~ s/\sFOUND$//) {
                print "INFECTED::";
                print " $rest :: $dirname/$childname/$filename\n";
            } elsif ($rest =~ /\sERROR$/) {
                print "ERROR:: $rest :: $dirname/$childname/$filename\n";
                next;
            } else {
                print "ERROR:: UNKNOWN CLAMD RETURN $results :: $ScanDir\n";
            }
        }

        close($sock);
    } else {

        # We were able to open the socket but could not actually connect
        # to the daemon so something odd is amiss and we send error to
        # parser and log, then exit
        print "ERROR:: UNKNOWN ERROR HAS OCCURED WITH CLAMD, SUGGEST YOU "
          . "RESTART DAEMON :: $dirname\n";
        print "ScAnNeRfAiLeD\n" unless $lintonly;
        Baruwa::Scanner::Log::DebugLog(
                "UNKNOWN ERROR HAS OCCURED WITH THE CLAMD "
              . "DAEMON SUGGEST YOU RESTART CLAMD!");
        return 1;
    }

}    # EO ClamdScan

# This function just opens the connection to the clamd daemon
# and returns either a valid resource or undef if the connection
# fails
sub ConnectToClamd {
    my ($TCP, $Socket, $Port, $TimeOut) = @_;
    my $sock;

    # Attempt to open the appropriate socket depending on the type (TCP/UNIX)
    if ($TCP) {
        $sock = IO::Socket::INET->new(
            PeerAddr => $Socket,
            PeerPort => $Port,
            Timeout  => $TimeOut,
            Proto    => 'tcp'
        );
    } else {
        $sock = IO::Socket::UNIX->new(
            Timeout => $TimeOut,
            Peer    => $Socket
        );
    }
    return undef unless $sock;
    return $sock;
}    # EO ConnectToClamd

sub ConnectToFpscand {
    my ($Port, $TimeOut) = @_;

    #print STDERR "Fpscand Port = $Port\nTimeout = $TimeOut\n";
    my $sock = IO::Socket::INET->new(
        PeerAddr => "localhost",
        PeerPort => $Port,
        Timeout  => $TimeOut,
        Proto    => 'tcp',
        Type     => SOCK_STREAM
    );

    #print STDERR "Fpscand sock is $sock\n";
    return undef unless $sock;
    return $sock;
}

sub Fprotd6Scan {
    my ($dirname, $disinfect, $messagebatch) = @_;

    my $lintonly = 0;
    $lintonly = 1 if $dirname eq 'ISITINSTALLED';

    # Clamd MUST have the full path to the file/dir it's scanning
    # so let's build the scan dir here and remove that pesky \. at the end
    my $ScanDir = "$global::MS->{work}->{dir}/$dirname";
    $ScanDir =~ s/\/\.$//;

    my $TimeOut = Baruwa::Scanner::Config::Value('virusscannertimeout');
    my $Port    = Baruwa::Scanner::Config::Value('fprotd6port');
    my $line    = '';
    my $sock;

    # Attempt to open the connection to fpscand
    $sock = ConnectToFpscand($Port, $TimeOut);
    print "ERROR:: COULD NOT CONNECT TO FPSCAND, RECOMMEND RESTARTING DAEMON "
      . ":: $dirname\n"
      unless $sock || $lintonly;
    print "ScAnNeRfAiLeD\n" unless $sock || $lintonly;
    Baruwa::Scanner::Log::WarnLog("ERROR:: COULD NOT CONNECT TO FPSCAND, "
          . "RECOMMEND RESTARTING DAEMON ")
      unless $sock || $lintonly;
    return 1 unless $sock;

    return 'FPSCANDOK' if $lintonly;

    # Walk the directory tree from $ScanDir downwards
    %FPd6ParserFiles = ();

    #Baruwa::Scanner::Log::InfoLog("fpscand: RESET");
    print $sock "QUEUE\n";
    Fpscand($ScanDir, $sock);
    print $sock "SCAN\n";
    $sock->flush;

    # Read back all the reports
    while (keys %FPd6ParserFiles) {
        $_ = <$sock>;
        chomp;
        next unless /^(\d+) <(.+)> (.+)$/; # Assume virus name is 1 word for now
        my ($code, $text, $path) = ($1, $2, $3);

        #print STDERR "Code = *$code* Text = *$text* Path = *$path*\n";
        my $attach = $path;
        $attach =~ s/-\>.*$//;

        #Baruwa::Scanner::Log::InfoLog("fpscand: Removed \"%s\"", $attach);
        delete $FPd6ParserFiles{$attach};

        # Strip any surrounding <> braces
        $path =~ s/^$ScanDir/./;    # Processor expects ./id/attachname/.....

        #JJnext if $code == 0 || $text eq 'clean'; # Skip clean files

        if (($code & 3) || $text =~ /^infected: /i) {
            $text =~ s/^infected: //i;
            $path =~ s/\.(?:header|message)$//; # Look for infections in headers
                #print "INFECTED:: $text :: $path\n";
            print "INFECTED:: $text :: $path\n";
        } elsif ($code == 0 || $text =~ /^clean/i) {
            print "CLEAN:: $text :: $path\n";
        } else {
            print "ERROR:: $code $text :: $path\n";
        }
    }
    $sock->close;
}

# Recursively walk the directory tree from $dir downwards, sending instructions
# to $sock as we go, one line for each file
sub Fpscand {
    my ($dir, $sock) = @_;

    my $dh = new DirHandle $dir
      or
      Baruwa::Scanner::Log::WarnLog("FProt6d: failed to process directory %s",
        $dir);
    my $file;
    while (defined($file = $dh->read)) {
        my $f = "$dir/$file";
        $f =~ /^(.*)$/;
        $f = $1;
        next if $file =~ /^\./ && -d $f;    # Is it . or ..
        if (-d $f) {
            Fpscand($f, $sock);
        } else {
            print $sock "SCAN FILE $f\n";

            #print STDERR "Added $f to list\n";
            #Baruwa::Scanner::Log::InfoLog("fpscand: Added \"%s\"", $f);
            $FPd6ParserFiles{$f} = 1;
        }
    }
    $dh->close;
}

sub ProcessFProtd6Output {
    my ($line, $infections, $types, $BaseDir, $Name, $spaminfre) = @_;
    my ($logout, $keyword, $virusname, $filename);
    my ($dot, $id, $part, @rest, $report, $attach);

    chomp $line;
    $logout = $line;
    $logout =~ s/\s{20,}/ /g;

    #$logout =~ s/%/%%/g;

    #print STDERR "Output is \"$logout\"\n";
    ($keyword, $virusname, $filename) = split(/:: /, $line, 3);

    if ($keyword =~ /^error/i) {
        Baruwa::Scanner::Log::InfoLog("%s::%s", 'FProtd6', $logout);
        return 1;
    } elsif ($keyword =~ /^info|^clean/i || $logout =~ /rar module failure/i) {
        return 0;
    } else {

        # Must be an infection reports

        ($dot, $id, $part, @rest) = split(/\//, $filename);
        $attach = $part;
        $attach =~ s/-\>.*$//;    # This gives us the actual attachment name
        my $notype = substr($attach, 1);
        $logout =~ s/\Q$part\E/$notype/;
        $report =~ s/\Q$part\E/$notype/;
        Baruwa::Scanner::Log::InfoLog("%s::%s", 'FProtd6', $logout);

        if ($virusname =~ /$spaminfre/) {

            # It's spam found as an infection
            # 20090730
            return "0 $id $virusname";
        }

        $report = $Name . ': ' if $Name;

# print STDERR "Got an infection report of \"$virusname\" for \"$id\" \"$attach\"\n";
        if ($attach eq '') {

            # No part ==> entire message is infected.
            $infections->{"$id"}{""} .=
              "$report message was infected: $virusname\n";
        } else {
            $infections->{"$id"}{"$attach"} .=
              "$report$notype was infected: $virusname\n";
        }
        $types->{"$id"}{"$part"} .= "v";    # it's a real virus
        return 1;
    }
}

sub call_system {
    my ($command) = @_;
    # print STDERR "SAS=>$command\n";
    my $result = system($command) >> 8;
    return $result;
}

1;
