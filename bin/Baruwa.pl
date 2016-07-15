#!/usr/bin/perl
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

use strict;
no strict 'subs';
use POSIX;
require 5.005;

use FileHandle;
use File::Path;
use IO::Handle;
use IO::File;
use Getopt::Long;
use Time::HiRes qw ( time );
use Filesys::Df;
use IO::Stringy;
use Sys::Hostname::Long;
use DBI;
use Baruwa::Scanner::Antiword;
use Baruwa::Scanner::Config;
use Baruwa::Scanner::CustomConfig;
use Baruwa::Scanner::GenericSpam;
use Baruwa::Scanner::Lock;
use Baruwa::Scanner::Log;
use Baruwa::Scanner::Mail;
use Baruwa::Scanner::MessageBatch;
use Baruwa::Scanner::Quarantine;
use Baruwa::Scanner::Queue;
use Baruwa::Scanner::RBLs;
use Baruwa::Scanner::MCPMessage;
use Baruwa::Scanner::Message;
use Baruwa::Scanner::MCP;
use Baruwa::Scanner::SA;
use Baruwa::Scanner::SweepContent;
use Baruwa::Scanner::SweepOther;
use Baruwa::Scanner::SweepViruses;
use Baruwa::Scanner::TNEF;
use Baruwa::Scanner::Unzip;
use Baruwa::Scanner::WorkArea;
use Baruwa::Scanner;

my $autoinstalled = 0;
# Needed for Sys::Syslog, as Debian Potato (at least) doesn't
# appear to have "gethostname" syscall as used (indirectly) by Sys::Syslog
# So it uses `hostname` instead, which it can't do if PATH is tainted.
# It's good to have this anyway, although we may need to modify it for
# other OS when we find that something we need isn't here -- nwp 14/01/02
$ENV{PATH} = "/sbin:/bin:/usr/sbin:/usr/bin";

# We *really* should clear *all* environment bar what we *know* we
# need here. It will avoid surprises (like bash running BASH_ENV or
# SpamAssassin using $ENV{HOME} rather than getpwnam to decide where
# to drop its load.

# Needed for -T:
delete $ENV{'BASH_ENV'};    # Don't run things on bash startup

# Needed for SpamAssassin:
delete $ENV{'HOME'};

# Need the parent process to ignore SIGHUP, and catch SIGTERM
$SIG{'HUP'}  = 'IGNORE';
$SIG{'TERM'} = \&ExitParent;
$SIG{'INT'}  = \&ExitParent;

# Remember to update this before releasing a new version of Baruwa.
#
# Version numbering scheme is this:
# 4   Major release
# 00  Minor release, incremented for new features and major changes
# 0   Incremented for bug fixes and beta releases
# Any numbers after a "-" are packaging release numbers. They reflect
# changes in the packaging, and occasionally very small changes to the code.
$Baruwa::Scanner::Config::BaruwaVersion = '4.86.0';

my $WantHelp           = 0;
my $Versions           = 0;
my $WantProcDBDumpOnly = -1;
my $WantLintOnly       = 0;
my $WantLintLiteOnly   = 0;
my $WantChangedOnly    = 0;
my $WantRuleCheck      = "";
my $RuleCheckFrom      = "";
my @RuleCheckTo        = "";
my $RuleCheckIP        = "";
my $RuleCheckVirus     = "";
my $IDToScan           = "";
my $DirToScan          = "";
my $PidFile            = "";
my $Debug              = "";
my $DebugSpamAssassin  = 0;
my $result             = GetOptions(
    "h|H|help"            => \$WantHelp,
    "v|V|version|Version" => \$Versions,
    "lint"                => \$WantLintOnly,
    "lintlite|lintlight"  => \$WantLintLiteOnly,
    "processing:1"        => \$WantProcDBDumpOnly,
    "c|C|changed"         => \$WantChangedOnly,
    "value=s"             => \$WantRuleCheck,
    "from=s"              => \$RuleCheckFrom,
    "to=s@"               => \@RuleCheckTo,
    "ip=s"                => \$RuleCheckIP,
    "inqueuedir=s"        => \$DirToScan,
    "virus=s"             => \$RuleCheckVirus,
    "id=s"                => \$IDToScan,
    "debug"               => \$Debug,
    "debug-sa"            => \$DebugSpamAssassin
);

if ($WantHelp) {
    print STDERR "Usage:\n";
    print STDERR "Baruwa      [ -h|-v|--debug|--debug-sa|--lint ] |\n";
    print STDERR "            [ --processing | --processing=<minimum> ] |\n";
    print STDERR "            [ -c|--changed ] |\n";
    print STDERR "            [ --id=<message-id> ] |\n";
    print STDERR "            [ --inqueuedir=<dir-name|glob> ] |\n";
    print STDERR "            [--value=<option-name> --from=<from-address>\n";
    print STDERR "             --to=<to-address>,    --to=<to-address-2>, ...]\n";
    print STDERR "             --ip=<ip-address>,    --virus=<virus-name> ]\n";
    print STDERR "            <baruwa.conf-file-location>\n";
    exit 0;
}

# Are we just printing version numbers and exiting?
if ($Versions) {
    my @Modules = qw/
    AnyDBM_File
    Archive::Zip
    bignum
    Carp
    Compress::Zlib
    Convert::BinHex
    Convert::TNEF
    Data::Dumper
    Date::Parse
    DirHandle
    Fcntl
    File::Basename
    File::Copy
    FileHandle
    File::Path
    File::Temp
    Filesys::Df
    HTML::Entities
    HTML::Parser
    HTML::TokeParser
    IO
    IO::File
    IO::Pipe
    Mail::Header
    Math::BigInt
    Math::BigRat
    MIME::Base64
    MIME::Decoder
    MIME::Decoder::UU
    MIME::Head
    MIME::Parser
    MIME::QuotedPrint
    MIME::Tools
    Net::CIDR
    Net::IP
    OLE::Storage_Lite
    Pod::Escapes
    Pod::Simple
    POSIX
    Scalar::Util
    Socket
    Storable
    Sys::Hostname::Long
    Sys::Syslog
    Test::Pod
    Test::Simple
    Time::HiRes
    Time::localtime/;
    my @Optional = qw#Archive/Tar.pm
    bignum.pm
    Business/ISBN.pm
    Business/ISBN/Data.pm
    Data/Dump.pm
    DB_File.pm
    DBD/SQLite.pm
    DBI.pm
    Digest.pm
    Digest/HMAC.pm
    Digest/MD5.pm
    Digest/SHA1.pm
    Encode/Detect.pm
    Error.pm
    ExtUtils/CBuilder.pm
    ExtUtils/ParseXS.pm
    Getopt/Long.pm Inline.pm
    IO/String.pm
    IO/Zlib.pm
    IP/Country.pm
    Mail/ClamAV.pm
    Mail/SpamAssassin.pm
    Mail/SPF.pm
    Mail/SPF/Query.pm
    Module/Build.pm
    Net/CIDR/Lite.pm
    Net/DNS.pm
    Net/DNS/Resolver/Programmable.pm
    Net/LDAP.pm
    NetAddr/IP.pm
    Parse/RecDescent.pm
    SAVI.pm
    Test/Harness.pm
    Test/Manifest.pm
    Text/Balanced.pm
    URI.pm
    version.pm
    YAML.pm#;

    my ( $module, $s, $v, $m );

    printf( "Running on\n%s", `uname -a` );
    printf( "This is %s",     `cat /etc/redhat-release` ) if -f "/etc/redhat-release";
    printf( "This is Perl version %f (%vd)\n", $], $^V );
    print "\nThis is Baruwa version " . $Baruwa::Scanner::Config::BaruwaVersion . "\n";
    print "Module versions are:\n";
    open STDERR, "> /dev/null";
    foreach $module (@Modules) {
        $s = "use $module; \$$module" . '::VERSION';
        $v = eval("$s") || "missing";
        print "$v\t$module\n" if $v ne "";
    }
    print "\nOptional module versions are:\n";
    foreach $module (@Optional) {
        $m = $module;
        $m =~ s/\//::/g;
        $m =~ s/\.pm$//;
        $s = '$' . "$m" . '::VERSION';
        $v = eval("require \"$module\"; $s") || "missing";
        print "$v\t$m\n";
    }
    exit;
}

# Set the Debug flag if the DebugSpamAssassin flag was set
$Debug = 1 if $DebugSpamAssassin;

# Check version of MIME-tools against its requirements
my $error = 0;
if ( $MIME::Tools::VERSION > 5.420 ) {
    if ( $IO::VERSION < 1.23 ) {
        print STDERR "\n\n**** ERROR: Perl IO module > 1.23 required\n\n";
        $error = 1;
    }
    if ( $IO::Stringy::VERSION < 2.110 ) {
        print STDERR "\n\n**** ERROR: Perl IO::Stringy module > 2.110 required\n\n";
        $error = 1;
    }
}
exit 1 if $error;

# Work out what directory we're in and add it onto the front
# of the include path so that we can work if we're just chucked
# any old where in a directory with the modules. 
#
# Also get process name while we're at it.
#
my $dir = $0;

# can't use s/// as it doesn't untaint $dir
$dir =~ m#^(.*)/([^/]+)$#;
$dir = $1;
$Baruwa::Scanner::Config::BaruwaProcessCommand = "$1/$2";
$Baruwa::Scanner::Config::BaruwaProcessName = "";
$Baruwa::Scanner::Config::BaruwaProcessName = $2;

# Add my directory onto the front of the include path
unless ($autoinstalled) {
    unshift @INC, "$dir/Baruwa";
    unshift @INC, $dir;
}

# Set umask nice and safe so no-one else can access anything!
umask 0077;

# Fix bug in GetOptions where it rarely leaves switches on the command-line.
if ( $WantLintOnly || $WantLintLiteOnly ) {
    shift unless -f $ARGV[0];
}

# Find the baruwa.conf file, with a default just in case.
my $ConfFile = $ARGV[0];

# Use the default if we couldn't find theirs. Will save a lot of grief.
$ConfFile = '/etc/mail/baruwa/baruwa.conf' if $ConfFile eq "" || !( -f $ConfFile );

# Tell ConfigSQL where the configuration file is.
$Baruwa::Scanner::ConfigSQL::ConfFile = $ConfFile;

# Do they just want a dump of the processing-database table?
if ( $WantProcDBDumpOnly >= 0 ) {
    my $dbname = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'processingattemptsdatabase' );
    if ( $dbname && -f $dbname ) {
        DumpProcessingDatabase( $dbname, $WantProcDBDumpOnly );
    }
    exit 0;
}

# Check the Baruwa version number against what is in baruwa.conf
my $NeedVersion = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'baruwaversionnumber' );
if ($NeedVersion) {
    my ( $ConfMajor, $ConfMinor, $ConfRelease );
    my ( $Error, $AreMajor, $AreMinor, $AreRelease );
    $Error = 0;
    $NeedVersion =~ /^(\d+)\.(\d+)\.(\d+)$/;
    ( $ConfMajor, $ConfMinor, $ConfRelease ) = ( $1 + 0, $2 + 0, $3 + 0 );
    $ConfMajor   = 0 unless $ConfMajor;
    $ConfMinor   = 0 unless $ConfMinor;
    $ConfRelease = 0 unless $ConfRelease;
    $Baruwa::Scanner::Config::BaruwaVersion =~ /^(\d+)\.(\d+)\.(\d+)$/;
    ( $AreMajor, $AreMinor, $AreRelease ) = ( $1 + 0, $2 + 0, $3 + 0 );
    $AreMajor   = 0 unless $AreMajor;
    $AreMinor   = 0 unless $AreMinor;
    $AreRelease = 0 unless $AreRelease;

    if ( $ConfMajor > $AreMajor ) {
        $Error = 1;
    }
    elsif ( $ConfMajor == $AreMajor ) {
        if ( $ConfMinor > $AreMinor ) {
            $Error = 1;
        }
        elsif ( $ConfMinor == $AreMinor ) {
            if ( $ConfRelease > $AreRelease ) {
                $Error = 1;
            }
        }
    }
    if ($Error) {
        print STDERR "The configuration file $ConfFile\n mismatch.\nThis is version "
          . $Baruwa::Scanner::Config::BaruwaVersion
          . " but the config file is for at least version $NeedVersion\n";
        exit 1;
    }
}

my $NotConfigured = 0;
$NotConfigured++ if Baruwa::Scanner::Config::QuickPeek( $ConfFile, '%org-name%', 'notifldap' ) =~
  /yoursite|unconfigured-\w+-site/i;
$NotConfigured++ if Baruwa::Scanner::Config::QuickPeek( $ConfFile, '%org-long-name%', 'notifldap' )
  eq "Your Organisation Name Here";
$NotConfigured++ if Baruwa::Scanner::Config::QuickPeek( $ConfFile, '%web-site%', 'notifldap' ) eq
  "www.your-organisation.com";
if ( $NotConfigured == 3 ) {
    # Set them all to be something sensible
    my $domain_name = hostname_long;
    $domain_name =~ s/^[^.]+\.//;
    my $header_domain = $domain_name;
    $header_domain =~ tr/./_/;    # So as not to kill Symantec's broken scanner

    Baruwa::Scanner::Config::SetPercent( 'org-name',      $header_domain );
    Baruwa::Scanner::Config::SetPercent( 'org-long-name', $domain_name );
    Baruwa::Scanner::Config::SetPercent( 'web-site',      'www.' . $domain_name );
}

# Set an indication of the version number for rules.
Baruwa::Scanner::Config::SetPercent( 'version', $Baruwa::Scanner::Config::BaruwaVersion );

# Load the MTA modules we need
my ( $MTAmod, $MTADSmod );

# LEOH:if (Baruwa::Scanner::Config::QuickPeek($ConfFile, 'mta') =~ /exim/i) {
$_ = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'mta' );
$_ = 'sendmail' if $WantLintOnly || $WantLintLiteOnly || $WantRuleCheck;
if (/exim/i) {
    $MTAmod   = 'Exim.pm';
    $MTADSmod = 'EximDiskStore.pm';
}
else {
    $MTAmod   = 'Sendmail.pm';
    $MTADSmod = 'SMDiskStore.pm';
}
require "Baruwa/$MTAmod";
require "Baruwa/$MTADSmod";

# All they want is the list of settings that have been changed from the
# default values hard-coded into ConfigDefs.pl. These values may well be
# different from those supplied in the default baruwa.conf file.
if ($WantChangedOnly) {
    Baruwa::Scanner::Config::Read( $ConfFile, $WantLintOnly );
    Baruwa::Scanner::Config::PrintNonDefaults();
    exit 0;
}

# If all we are doing is linting the configuration file, then do it here
# and get out.
if ( $WantLintOnly || $WantLintLiteOnly ) {
    # Start logging to syslog/stderr
    Baruwa::Scanner::Log::WarningsOnly() if $WantLintLiteOnly;
    StartLogging($ConfFile);
    my $logbanner = "Baruwa E-Mail Content Scanner version "
      . $Baruwa::Scanner::Config::BaruwaVersion
      . " checking configuration...\n";
    Baruwa::Scanner::Log::Configure( $logbanner, 'stderr' );

    # Check -autoupdate lock files
    my $lockdir = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'lockfiledir' );
    if ( $lockdir eq "" || $lockdir =~ /tmp$/i ) {
        print STDERR "Please move your \"Lockfile Dir\" setting in baruwa.conf.\n";
        print STDERR "It should point outside /tmp, preferably /var/lock/baruwa/Locks\n";
    }
    my $cluid = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'runasuser' );
    my $clgid = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'runasgroup' );
    my $clr   = system("/usr/sbin/baruwa_create_locks \"$lockdir\" \"$cluid\" \"$clgid\"");
    print STDERR "Error: Attempt to create locks in $lockdir failed!\n" if ( $clr >> 8 ) != 0;

    # Read the directory containing all the custom code
    Baruwa::Scanner::Config::initialise(
        Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'customfunctionsdir' )
    );

    # Read the configuration file properly
    print STDERR "\n";
    Baruwa::Scanner::Config::Read( $ConfFile, $WantLintOnly );
    print STDERR "\n";

    # Tried to set [u,g]id after writing pid, but then it fails when it re-execs
    # itself. Using the posix calls because I don't want to have to bother to
    # find out what happens when "$< = $uid" fails (i.e. not running as root).
    # This needs to be global so checking functions can all get at them.
    # This now also adds group membership for the quarantine and work directories.
    my ( $uname, $gname, $qgname, $igname, $uid, $gid, $qgid, $igid );
    $uname  = Baruwa::Scanner::Config::Value('runasuser');
    $gname  = Baruwa::Scanner::Config::Value('runasgroup');
    $qgname = Baruwa::Scanner::Config::Value('quarantinegroup');
    $igname = Baruwa::Scanner::Config::Value('workgroup');
    $uid    = $uname ? getpwnam($uname) : 0;
    $gid    = $gname ? getgrnam($gname) : 0;
    $qgid   = $qgname ? getgrnam($qgname) : 0;
    $igid   = $igname ? getgrnam($igname) : 0;

    # Check the version number in baruwa.conf is correct.
    my ( $currentver, $confver );
    $currentver = $Baruwa::Scanner::Config::BaruwaVersion;
    $confver    = Baruwa::Scanner::Config::Value('baruwaversionnumber');

    #print STDERR "Running ver = $currentver\nConf ver = $confver\n";
    unless ($WantLintLiteOnly) {
        print STDERR "Checking version numbers...\n";
        if ( $currentver ne $confver ) {
            print STDERR "Version to configuration mismatch $currentver != $confver\n";
        }
        else {
            print STDERR "Version number in baruwa.conf ($confver) is correct.\n";
        }
    }

    my $mailheader = Baruwa::Scanner::Config::Value('mailheader');
    if ( $mailheader !~ /^[_a-zA-Z0-9-]+:?$/ ) {
        print STDERR "\n";
        print STDERR
          "Your setting \"Mail Header\" contains illegal characters.\n";
        print STDERR
          "This is most likely caused by your \"%org-name%\" setting\n";
        print STDERR
          "which must not contain any spaces, \".\" or \"_\" characters\n";
        print STDERR
          "as these are known to cause problems with many mail systems.\n";
        print STDERR "\n";
    }

    # Check that unrar is installed
    if ($WantLintOnly) {
        my $unrar = Baruwa::Scanner::Config::Value('unrarcommand');
        unless ( -x $unrar ) {
            print STDERR "\n";
            print STDERR "Unrar is not installed, it should be in $unrar.\n";
            print STDERR "This is required for RAR archives to be read to check\n";
            print STDERR "filenames and filetypes. Virus scanning is not affected.\n";
            print STDERR "\n";
        }
    }

    # Check envelope_sender_header in spam.assassin.prefs.conf is correct
    if ($WantLintOnly) {
        my ( $msfromheader, $etc, $saprefs );
        $msfromheader = Baruwa::Scanner::Config::Value('envfromheader');
        $msfromheader =~ s/:$//;
        $etc = $1 if $ConfFile =~ m#^(.*)/[^/]+$#;
        $saprefs = new FileHandle("$etc/spam.assassin.prefs.conf");
        if ($saprefs) {
            while ( defined( $_ = <$saprefs> ) ) {
                chomp;
                if (s/^\s*envelope_sender_header\s+//) {
                    if ( $msfromheader ne $_ ) {
                        print STDERR "\nERROR: The \"envelope_sender_header\" in your spam.assassin.prefs.conf\n";
                        print STDERR "ERROR: is not correct, it should match $msfromheader\n\n";
                    }
                    else {
                        print STDERR "\nThe envelope_sender_header in spam.assassin.prefs.conf is correct.\n";
                    }
                    last;
                }
            }
            $saprefs->close();
        }
        else {
            print STDERR "\nWarning: Could not read the spam.assassin.prefs.conf file!\n\n";
        }
    }

    # Check permissions on /tmp
    if ($WantLintOnly) {
        my $handle = IO::File->new_tmpfile or print STDERR "\nThe /tmp needs to be set to \"chmod 1777 /tmp\"\n";
        close($handle);
    }

    # If it's a "light" check, then just bail out here, I've checked enough.
    exit if $WantLintLiteOnly;

    my $workarea = new Baruwa::Scanner::WorkArea;
    my $inqueue = new Baruwa::Scanner::Queue( @{ Baruwa::Scanner::Config::Value('inqueuedir') } );
    my $mta  = new Baruwa::Scanner::Sendmail;
    my $quar = new Baruwa::Scanner::Quarantine;

    $global::MS = new Baruwa::Scanner(
        WorkArea   => $workarea,
        InQueue    => $inqueue,
        MTA        => $mta,
        Quarantine => $quar
    );
    SetUidGid( $uid, $gid, $qgid, $igid );

    # Other initialisation needed to fake a batch for scanner testing
    Baruwa::Scanner::MessageBatch::initialise();
    print STDERR "\nChecking for SpamAssassin errors (if you use it)...\n";
    Baruwa::Scanner::SA::CreateTempDir( $uid,
        Baruwa::Scanner::Config::Value('spamassassintempdir') )
      unless Baruwa::Scanner::Config::IsSimpleValue('usespamassassin')
      && !Baruwa::Scanner::Config::Value('usespamassassin');
    Baruwa::Scanner::SA::initialise( 0, 1 );    # Just do a Lint check
    Baruwa::Scanner::Log::Reset();
    Baruwa::Scanner::TNEF::initialise();
    Baruwa::Scanner::Sendmail::initialise();
    Baruwa::Scanner::SweepViruses::initialise();
    CreateProcessingDatabase(1);            # Just do a Lint check

    # Find the list of virus scanners installed
    print STDERR "baruwa.conf says \"Virus Scanners = "
      . Baruwa::Scanner::Config::Value('virusscanners') . "\"\n";
    my @scannerlist = Baruwa::Scanner::SweepViruses::InstalledScanners();
    print STDERR "Found these virus scanners installed: "
      . join( ', ', @scannerlist ) . "\n";
    print STDERR "=" x 75 . "\n";

    # Create a fake message batch containing EICAR and virus-scan it
    my $batch;
    $workarea->Clear();
    $batch = new Baruwa::Scanner::MessageBatch( 'lint', undef );
    $global::MS->{batch} = $batch;
    $global::MS->{work}->BuildInDirs($batch);
    $batch->Explode($Debug);

    $batch->CreateEntitiesHelpers();
    Baruwa::Scanner::Config::SetValue( 'showscanner', 1 );
    $batch->VirusScan();

    # Print all the v infections in the batch
    my $m   = $batch->{messages}->{"1"};
    my $rep = $m->{virusreports}->{'neicar.com'};
    my @rep = split "\n", $rep;
    print STDERR "=" x 75 . "\n";
    print STDERR "Virus Scanner test reports:\n" if @rep;
    foreach my $l (@rep) {
        my ( $scanner, $report ) = split /:/, $l, 2;
        chomp $report;
        $report =~ s/^\s+//g;
        $report =~ s/\s+$//g;
        print STDERR $scanner . " said \"$report\"\n";
    }
    my $scannerlist = join( ',', @scannerlist );
    print STDERR <<EOWarn;

If any of your virus scanners ($scannerlist)
are not listed there, you should check that they are installed correctly
and that Baruwa is finding them correctly via its virus.scanners.conf.
EOWarn

    $workarea->Destroy();
    Baruwa::Scanner::Config::EndCustomFunctions();
    Baruwa::Scanner::Config::DisconnectLDAP();
    Baruwa::Scanner::Log::Stop();
    unlink "/tmp/MSLint.body.$$";
    exit 0;
}

# Do they want us to work out the value of a rule
if ( $WantRuleCheck ne "" ) {
    my ( $rule, $user, $domain, $to, $msg, $result );

    # Read the configuration file properly
    Baruwa::Scanner::Config::Read( $ConfFile, $WantLintOnly );

    # Need to fake that we're running sendmail for the static code to work,
    # just like in --lint ($WantLintOnly).
    my $workarea = new Baruwa::Scanner::WorkArea;
    my $inqueue =
      new Baruwa::Scanner::Queue( @{ Baruwa::Scanner::Config::Value('inqueuedir') } );
    my $mta  = new Baruwa::Scanner::Sendmail;
    my $quar = new Baruwa::Scanner::Quarantine;
    $global::MS = new Baruwa::Scanner(
        WorkArea   => $workarea,
        InQueue    => $inqueue,
        MTA        => $mta,
        Quarantine => $quar
    );

    # We have external configuration name, first translate it to internal
    $WantRuleCheck = lc($WantRuleCheck);
    $WantRuleCheck =~ s/[^a-z0-9]//g;    # Leave numbers and letters only
    $rule = Baruwa::Scanner::Config::EtoI($WantRuleCheck);
    $rule = $WantRuleCheck if $rule eq "";

    $msg = Baruwa::Scanner::Message->new( '1', '/tmp', 'fake' );

    $RuleCheckFrom = lc($RuleCheckFrom);
    ( $user, $domain ) = ( $1, $2 ) if $RuleCheckFrom =~ /^([^@]*)@(.*)$/;
    $msg->{from}       = $RuleCheckFrom;
    $msg->{fromdomain} = $domain;
    $msg->{fromuser}   = $user;

    $msg->{clientip} = $RuleCheckIP;
    %{ $msg->{allreports} } = ();
    $msg->{allreports}{""} = $RuleCheckVirus;

    foreach $to (@RuleCheckTo) {
        $to = lc($to);
        next unless $to;
        ( $user, $domain ) = ( $1, $2 ) if $to =~ /^([^@]*)@(.*)$/;
        push @{ $msg->{to} },       $to;
        push @{ $msg->{todomain} }, $domain;
        push @{ $msg->{touser} },   $user;
    }

    $result = Baruwa::Scanner::Config::Value( $rule, $msg );
    print STDERR "Looked up internal option name \"$rule\"\n";
    print STDERR "With sender = " . $msg->{from} . "\n";
    foreach $to ( @{ $msg->{to} } ) {
        next unless $to;
        print STDERR "  recipient = " . $to . "\n";
    }
    print STDERR "Client IP = " . $msg->{clientip} . "\n";
    print STDERR "Virus = " . $msg->{allreports}{""} . "\n";
    print STDERR "Result is \"$result\"\n";
    print STDERR "\n0=No 1=Yes\n" if $result =~ /^[01]$/;

    exit 0;
}

## We are probably running for real by now, not in any "check a few things
## and then quit" mode such as --lint or --versions, so do a quick syntax
## check of the entire configuration before we fork off any children.
#Baruwa::Scanner::Config::Read($ConfFile, 'ThrowItAllAway');

# In case we lose privs to the file later, delete the SA signaller now
my $startlock = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'lockfiledir' )
  . '/Baruwa.bayes.starting.lock';
unlink $startlock if $startlock && -f $startlock;

# Tried to set [u,g]id after writing pid, but then it fails when it re-execs
# itself. Using the posix calls because I don't want to have to bother to
# find out what happens when "$< = $uid" fails (i.e. not running as root).
# This needs to be global so checking functions can all get at them.
# This now also adds group membership for the quarantine and work directories.
my ( $uname, $gname, $qgname, $igname, $uid, $gid, $qgid, $igid );
$uname  = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'runasuser' );
$gname  = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'runasgroup' );
$qgname = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'quarantinegroup' );
$igname = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'incomingworkgroup' );
$uid  = $uname  ? getpwnam($uname)  : 0;
$gid  = $gname  ? getgrnam($gname)  : 0;
$qgid = $qgname ? getgrnam($qgname) : 0;
$igid = $igname ? getgrnam($igname) : 0;

# Need to find the PidFile before changing uid/gid as its ownership will need
# to be set to the new uid/gid. It must be created first if necessary.
# Need     PidFile     to be able to manage pid of parent process
$PidFile = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'pidfile' );
WritePIDFile("Baruwa");
chown $uid, $gid, $PidFile;

# Create the SpamAssassin temporary working dir
Baruwa::Scanner::SA::CreateTempDir( $uid,
    Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'spamassassintemporarydir' ) );

# Check and create -autoupdate lock files
my $locksdir = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'lockfiledir' );
if ( $locksdir eq "" || $locksdir =~ /tmp$/i ) {
    print STDERR "Please move your \"Lockfile Dir\" setting in baruwa.conf.\n";
    print STDERR "It should point outside /tmp, preferably /var/lock/baruwa/Locks\n";
}
my $cl = system("/usr/sbin/baruwa_create_locks \"$locksdir\" \"$uname\" \"$gname\"");
print STDERR "Error: Attempt to create locks in $locksdir failed!\n" if ( $cl >> 8 ) != 0;

SetUidGid( $uid, $gid, $qgid, $igid );
CheckModuleVersions();

# Can't do this here, config not read yet: CheckQueuesAreTogether();

#
# Need MaxChildren to know how many children to fork
#      Debug       to know whether to terminate
#      WorkDir     to be able to clean up after killed children
#      BayesRebuildPeriod to be able to rebuild the Bayes database regularly
#
use vars qw($RunInForeground);
$RunInForeground =
  Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'runinforeground' );
my $MaxChildren = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'maxchildren' );
$Debug .= Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'debug' );
my $WorkDir = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'incomingworkdir' );
my $BayesRebuildPeriod =
  Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'rebuildbayesevery' );

# FIXME: we should check that the ownership and modes on piddir do not
# allow random people to do nasty things in there (like create symlinks
# to critical system files, or create pidfiles that point to critical
# system processes)
$Debug = ( $Debug =~ /yes|1/i ) ? 1 : 0;
$RunInForeground = 0 unless $RunInForeground =~ /yes|1/i;

my $WantLiteCheck = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'automaticsyntaxcheck' );
if ( $WantLiteCheck =~ /1|y/i ) {
    #print STDERR "About to run $0 --lintlite $ConfFile\n";
    system( $Baruwa::Scanner::Config::BaruwaProcessCommand . " --lintlite $ConfFile" );
}

# Enable STDOUT flushing if running in foreground
# to be able to actively capture it with a logger
$| = 1 if $RunInForeground;

# Give the user their shell back
ForkDaemon($Debug);

# Only write the parent pid, not the children yet
WritePIDFile($$);

#
# Do it only once when debugging.
#
if ($Debug) {
    my $mailheader = Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'mailheader' );
    #print STDERR "Mail Header is \"$mailheader\"\n";
    if ( $mailheader !~ /^[_a-zA-Z0-9-]+:?$/ ) {
        print STDERR <<EOMAILHEADER;

************************************************************************
In baruwa.conf, your "%org-name%" or "Mail Header" setting
contains spaces and/or other illegal characters.

Including any spaces will break all your mail system (but do not worry,
baruwa will fix this for you on the fly).

Otherwise, it should only contain characters from the set a-z, A-Z,
0-9, "-" and "_". While theoretically some other characters are allowed,
some commercial mail systems fail to handle them correctly.

This is clearly noted in the baruwa.conf file, immediately above
the %org-name% setting. Please read the documentation!
************************************************************************

EOMAILHEADER
    }
    WorkForHours();
    &KillBaruwa();
    print STDERR "Stopping now as you are debugging me.\n";
    exit 0;
}

#
# Start forking off child workers.
#

setpgrp();
$MaxChildren = 1 if $MaxChildren < 1;    # You can't have 0 workers
my $NumberOfChildren = 0;
my %Children;
my $NextRebuildDueTime = 0;
my $RebuildDue         = 0;

# Set when the next rebuild is due if regular rebuilds are being done
$NextRebuildDueTime = time + $BayesRebuildPeriod if $BayesRebuildPeriod;

# If we run in foreground, SIGKILL to the parent will try to reload
# by SIGKILLing its children
$SIG{'HUP'} = 'ReloadParent';    # JKF 20060731 if $RunInForeground;

for ( ; ; ) {
    while ( $NumberOfChildren < $MaxChildren ) {
        $0 = 'Baruwa: starting children';

        # Trigger 1 Bayes rebuild if the period has expired
        $RebuildDue = 0;
        if ( time > $NextRebuildDueTime && $BayesRebuildPeriod > 0 ) {
            $RebuildDue         = 1;
            $NextRebuildDueTime = time + $BayesRebuildPeriod;
        }
        print STDOUT sprintf( "About to fork child #%d of %d...\n",
            $NumberOfChildren + 1, $MaxChildren )
          if $RunInForeground;
        my $born_pid = fork();
        if ( !defined($born_pid) ) {
            die "Cannot fork off child process, $!";
        }
        if ( $born_pid == 0 ) {
            # I am a child process.
            # Set up SIGHUP handler and
            # Run Baruwa for a few hours.
            WorkForHours($RebuildDue);
            exit 0;
        }
        print STDOUT "\tForked OK - new child is [$born_pid]\n" if $RunInForeground;

        # I am the parent process.
        $Children{$born_pid} = 1;
        $NumberOfChildren++;
        sleep 5;    # Dropped this from 11 2006-11-01
    }

    # I have started enough children. Let's wait for one to die...
    my $dying_pid;
    $0 = 'Baruwa: master waiting for children, sleeping';
    until ( ( $dying_pid = wait() ) == -1 ) {
        my $exitstatus = $?;
        $0 = 'Baruwa: waiting for children to die';
        if ( $dying_pid > 0 && exists( $Children{$dying_pid} ) ) {
            # Knock the dying process off the list and decrement the counter.
            delete $Children{$dying_pid};
            $NumberOfChildren--;

            if ($exitstatus) {
                my $code   = $exitstatus >> 8;
                my $signal = $exitstatus & 0xFF;

                Baruwa::Scanner::Log::WarnLog(
                    "Process did not exit cleanly, returned "
                      . "%d with signal %d",
                    $code, $signal
                );
            }

            # Clean up after the dying process in case it left a mess.
            # If they change the work dir they really will have to stop and re-start.
            rmtree( "$WorkDir/$dying_pid", 0, 1 ) if -d "$WorkDir/$dying_pid";

            #
            # Re-spawn a replacement child process
            #
            # Trigger 1 Bayes rebuild if the period has expired
            $RebuildDue = 0;
            if ( time > $NextRebuildDueTime && $BayesRebuildPeriod > 0 ) {
                $RebuildDue         = 1;
                $NextRebuildDueTime = time + $BayesRebuildPeriod;
            }
            print STDOUT sprintf( "About to re-fork child #%d of %d...\n",
                $NumberOfChildren + 1, $MaxChildren )
              if $RunInForeground;
            $0 = 'Baruwa: starting child';
            my $born_pid = fork();
            if ( !defined($born_pid) ) {
                die "Cannot fork off child process, $!";
            }
            if ( $born_pid == 0 ) {

                # I am a child process.
                # Set up SIGHUP handler and
                # Run Baruwa for a few hours.
                WorkForHours($RebuildDue);
                exit 0;
            }
            print STDOUT "\tRe-forked OK - new child is [$born_pid]\n"
              if $RunInForeground;

            # I am the parent process.
            $Children{$born_pid} = 1;
            $NumberOfChildren++;
            sleep 5;
        }
        else {
            warn "We have just tried to reap a process which wasn't one of ours!, $!";
        }
    }
}

print STDERR "Oops, tried to go into Never Never Land!\n";
exit 1;

# The End

#
# Start each of the worker processes here.
# Just run for a few hours and then terminate.
# If we are debugging, then just run once.
#
sub WorkForHours {
    my ($BayesRebuild) = @_;    # Should we start by rebuilding Bayes databases

    # Tell ConfigSQL that this is now a child
    $Baruwa::Scanner::ConfigSQL::child = 1;

    # Read the configuration file and start logging to syslog/stderr
    StartLogging($ConfFile);

    # Setup SIGHUP and SIGTERM handlers
    $SIG{'HUP'} = \&ExitChild;

    #$SIG{'CHLD'}  = \&Reaper; # Addition by Bart Jan Buijs
    $SIG{'TERM'} = 'DEFAULT';

    # Read the directory containing all the custom code
    Baruwa::Scanner::Config::initialise(
        Baruwa::Scanner::Config::QuickPeek( $ConfFile, 'customfunctionsdir' ) );

    # Read the configuration file properly
    Baruwa::Scanner::Config::Read( $ConfFile, 0 );

    # If they have set Debug SpamAssassin = yes, ignore unless Debug is also set
    unless ( Baruwa::Scanner::Config::Value('debug') =~ /1/ ) {
        Baruwa::Scanner::Config::SetValue( 'debugspamassassin', 0 );
    }

    # Over-ride the incoming queue directory if necessary
    Baruwa::Scanner::Config::OverrideInQueueDirs($DirToScan) if $DirToScan;

    # Check the home directory exists and is writable,
    # otherwise SA will fail, as it wants to write Bayes databases and all
    # sorts of other stuff in the home directory.
    CheckHomeDir()
      if Baruwa::Scanner::Config::Value('spamassassinuserstatedir') eq "";

    # Initialise class variables now we are the right user
    Baruwa::Scanner::MessageBatch::initialise();
    Baruwa::Scanner::MCP::initialise();
    Baruwa::Scanner::Log::InfoLog("Bayes database rebuild is due") if $BayesRebuild;
    $Baruwa::Scanner::SA::Debug = $DebugSpamAssassin
      || Baruwa::Scanner::Config::Value('debugspamassassin');
    Baruwa::Scanner::SA::initialise($BayesRebuild);
    Baruwa::Scanner::Log::Reset();
    Baruwa::Scanner::TNEF::initialise();

    # Setup the Sendmail and Sendmail2 variables if they aren't set yet
    Baruwa::Scanner::Sendmail::initialise();
    CheckQueuesAreTogether();    # Can only do this after reading conf file
    Baruwa::Scanner::SweepViruses::initialise();    # Setup Sophos SAVI library
    CreateProcessingDatabase();

    my $workarea = new Baruwa::Scanner::WorkArea;
    my $inqueue =
      new Baruwa::Scanner::Queue( @{ Baruwa::Scanner::Config::Value('inqueuedir') } );
    my $mta  = new Baruwa::Scanner::Sendmail;
    my $quar = new Baruwa::Scanner::Quarantine;

    $global::MS = new Baruwa::Scanner(
        WorkArea   => $workarea,
        InQueue    => $inqueue,
        MTA        => $mta,
        Quarantine => $quar
    );

    my $batch;    # Looks pretty insignificant, doesn't it? :-)

    # Restart periodically, and handle time_t rollover in the year 2038
    my ( $StartTime, $RestartTime );
    $StartTime   = time;
    $RestartTime = $StartTime + Baruwa::Scanner::Config::Value('restartevery');

    my $FirstCheck = Baruwa::Scanner::Config::Value('firstcheck');
    Baruwa::Scanner::Log::WarnLog("First Check must be set to MCP or spam")
      unless $FirstCheck =~ /mcp|spam/i;
    my $VirusBeforeSpamMCP = Baruwa::Scanner::Config::Value('virusbeforespammcp');

    while ( time >= $StartTime && time < $RestartTime && !$BayesRebuild ) {
        $workarea->Clear();
        $0 = 'Baruwa: waiting for messages';
        print STDERR "Building a message batch to scan...\n" if $Debug;

        # Possibly restrict contents of batch to just $IDToScan
        $batch = new Baruwa::Scanner::MessageBatch( 'normal', $IDToScan );
        $global::MS->{batch} =
          $batch;    # So MailWatch can read the batch properties
                     #print STDERR "Batch is $batch\n";

        # Print current size of batch.
        if ($Debug) {
            my $msgs     = $batch->{messages};
            my $msgcount = scalar( keys %$msgs );
            my $msgss    = ( $msgcount == 1 ) ? '' : 's';
            print STDERR "Have a batch of $msgcount message$msgss.\n";
        }

        # Bail out immediately if we are using the Sophos SAVI library and it
        # has been updated since the last batch. This has to be done after the
        # batch has been created since it may sit for minutes/hours in
        # Baruwa::Scanner::MessageBatch::new.
        if ( Baruwa::Scanner::SweepViruses::SAVIUpgraded() ) {
            Baruwa::Scanner::Log::InfoLog( "Sophos SAVI library has been "
                  . "updated, killing this child" );
            last;
        }

        # Also bail out if the LDAP configuration serial number has changed.
        if ( Baruwa::Scanner::Config::LDAPUpdated() ) {
            Baruwa::Scanner::Log::InfoLog(
                "LDAP configuration has changed, " . "killing this child" );
            last;
        }

        # Check for SQL updates
        if ( Baruwa::Scanner::ConfigSQL::CheckForUpdate() ) {
            Baruwa::Scanner::Log::InfoLog(
                "SQL configuration has changed, " . "killing this child" );
            last;
        }

        #$batch->print();

        # Archive untouched incoming messages to directories
        $batch->ArchiveToFilesystem();

        # Do this first as it is very cheap indeed. Reject unwanted messages.
        $batch->RejectMessages();

        # 20090730 Moved from below as it's a very early check.
        # Deliver all the messages we are not scanning at all,
        # and mark them for deletion.
        # Then purge the deleted messages from disk.
        $batch->DeliverUnscanned();
        $batch->RemoveDeletedMessages();

        # Have to do this very early as it's needed for MCP and spam bouncing
        $global::MS->{work}->BuildInDirs($batch);

        #
        ## 20090730 Start of virus-scanning code moved to before spam-scanning
        #

        # Extract all the attachments
        $batch->StartTiming( 'virus', 'Virus Scanning' );

        # Moved upwards: $global::MS->{work}->BuildInDirs($batch);
        $0 = 'Baruwa: extracting attachments';
        $batch->Explode($Debug);

        # Report all the unparsable messages, but don't delete anything
        $batch->ReportBadMessages();

        # Build all the MIME entities helper structures
        $batch->CreateEntitiesHelpers();

        #$batch->PrintNumParts();
        #$batch->PrintFilenames();

        # Do the virus scanning
        $0 = 'Baruwa: virus scanning';
        $batch->VirusScan();

        #$batch->PrintInfections();
        $batch->StopTiming( 'virus', 'Virus Scanning' );

        # Combine all the infection/problem reports
        $batch->CombineReports();

        # Find all the messages infected with "silent" viruses
        # This excludes all Spam-Viruses
        $batch->FindSilentAndNoisyInfections();

        # Quarantine all the infected attachments
        # Except for Spam-Viruses
        $0 = 'Baruwa: quarantining infections';
        $batch->QuarantineInfections();

        # Deliver all the "silent" infected messages
        # and mark them for deletion
        $0 = 'Baruwa: processing silent viruses';
        $batch->DeliverOrDeleteSilentExceptSpamViruses();

        #
        ## 20090730 End of virus-scanning code moved to before spam-scanning
        #

        # Yes I know this isn't elegant, but it's very short so it will do :-)
        my $UsingMCP = 0;
        $UsingMCP = 1
          unless Baruwa::Scanner::Config::IsSimpleValue('mcpchecks')
          && !Baruwa::Scanner::Config::Value('mcpchecks');
        if ( $FirstCheck =~ /mcp/i ) {

            # Do the MCP checks
            if ($UsingMCP) {
                $0 = 'Baruwa: MCP checks';
                $batch->StartTiming( 'mcp', 'MCP Checks' );
                $batch->MCPChecks();
                $batch->HandleMCP();
                $batch->HandleNonMCP();
                $batch->StopTiming( 'mcp', 'MCP Checks' );
            }

            # Do the spam checks
            $0 = 'Baruwa: spam checks';
            $batch->StartTiming( 'spam', 'Spam Checks' );
            $batch->SpamChecks();
            $batch->HandleSpam();
            $batch->HandleHam();
            $batch->StopTiming( 'spam', 'Spam Checks' );
        }
        else {
            # Do the spam checks
            $0 = 'Baruwa: spam checks';
            $batch->StartTiming( 'spam', 'Spam Checks' );
            $batch->SpamChecks();
            $batch->HandleSpam();
            $batch->HandleHam();
            $batch->StopTiming( 'spam', 'Spam Checks' );

            # Do the MCP checks
            if ($UsingMCP) {
                $0 = 'Baruwa: MCP checks';
                $batch->StartTiming( 'mcp', 'MCP Checks' );
                $batch->MCPChecks();
                $batch->HandleMCP();
                $batch->HandleNonMCP();
                $batch->StopTiming( 'mcp', 'MCP Checks' );
            }
        }

        # Deliver all the messages we are not scanning at all,
        # and mark them for deletion.
        # Then purge the deleted messages from disk.
        $batch->DeliverUnscanned2();
        $batch->RemoveDeletedMessages();

        # Add the virus stats to the SpamAssassin cache so we know
        # to keep this data for much longer.
        $batch->AddVirusInfoToCache();

        # Strip the HTML tags out of messages which the spam
        # settings have asked us to strip.
        # We want to do this to both messages for which the config
        # option says we should strip, and for messages for which
        # the spam actions say we should strip.
        $batch->StartTiming( 'virus_processing', 'Virus Processing' );
        $0 = 'Baruwa: disarming and stripping HTML';
        $batch->StripHTML();
        $batch->DisarmHTML();

        # Quarantine all the disarmed HTML and others
        $batch->QuarantineModifiedBody();

        # Remove any infected spam from the spam+mcp archives
        $batch->RemoveInfectedSpam();

        # Clean all the infections out of the messages
        $0 = 'Baruwa: cleaning messages';
        $batch->Clean();

        # Zip up all the attachments to compress them
        $0 = 'Baruwa: compressing attachments';
        $batch->ZipAttachments();

        # Encapsulate the messages into message/rfc822 attachments as needed
        $batch->Encapsulate();

        # Sign all the uninfected messages
        $batch->SignUninfected();

        # Deliver all the uninfected messages
        # and mark them for deletion
        $batch->DeliverUninfected();

        # Delete cleaned messages that are from a local domain if we
        # aren't delivering cleaned messages from local domains,
        # by marking them for deletion. This will also stop them being
        # disinfected, which is fine. Also mark that they still need
        # relevant warnings/notices to be sent about them.
        # Then purge the deleted messages from disk.
        $batch->DeleteUnwantedCleaned();
        $batch->RemoveDeletedMessages();

        # Deliver all the cleaned messages
        # and mark them for deletion
        $0 = 'Baruwa: delivering cleaned messages';
        $batch->DeliverCleaned();
        $batch->RemoveDeletedMessages();

        # Warn all the senders of messages with any non-silent infections
        $0 = 'Baruwa: sending warnings';
        $batch->WarnSenders();

        # Warn all the notice recipents about all the viruses
        $batch->WarnLocalPostmaster();
        $batch->StopTiming( 'virus_processing', 'Virus Processing' );

        # Disinfect all possible messages and deliver to original recipients,
        # and delete them as we go.
        $batch->StartTiming( 'disinfection', 'Disinfection' );
        $0 = 'Baruwa: disinfecting macros';
        $batch->DisinfectAndDeliver();
        $batch->StopTiming( 'disinfection', 'Disinfection' );

        # JKF 20090301 Anything without the "deleted" flag set has been
        # dropped from the batch. Anything else has been successfully dealt
        # with.
        $batch->ClearOutProcessedDatabase();

        # Do all the time and speed logging
        $batch->EndBatch();

        # Look up a configuration parameter as the last thing we do so that the
        # lookup operation can have side-effects such as logging stats about the
        # message.
        $0 = 'Baruwa: finishing batch';
        $batch->LastLookup();

        #print STDERR "\n\n3 times are $StartTime " . time . " $RestartTime\n\n\n";

        # Only do 1 batch if debugging
        last if $Debug;
    }

    $0 = 'Baruwa: child dying';

    # Destroy the incoming work dir
    $global::MS->{work}->Destroy();

    # Close down all the user's custom functions
    Baruwa::Scanner::Config::EndCustomFunctions();

    # Tear down any LDAP connection
    Baruwa::Scanner::Config::DisconnectLDAP();

    if ($BayesRebuild) {
        Baruwa::Scanner::Log::InfoLog("Baruwa child dying after Bayes rebuild");
    }
    else {
        Baruwa::Scanner::Log::InfoLog("Baruwa child dying of old age");
    }

    # Don't want to leave connections to 514/udp open
    Baruwa::Scanner::Log::Stop();
}

#
# SIGHUP handler. Just make the child exit neatly and the parent
# farmer process will create a new one which will re-read the config.
#
sub ExitChild {
    my ($sig) = @_;    # Arg is signal name
    Baruwa::Scanner::Log::InfoLog( "Baruwa child caught a SIG%s", $sig );

    # Finish off any incoming queue file deletes that were pending
    Baruwa::Scanner::SMDiskStore::DoPendingDeletes();

    # Delete SpamAssassin rebuild signaller
    unlink $Baruwa::Scanner::SA::BayesRebuildStartLock
      if $Baruwa::Scanner::SA::BayesRebuildStartLock;

    # Kill off any commercial virus scanner process groups that are still running
    kill -15, $Baruwa::Scanner::SweepViruses::ScannerPID
      if $Baruwa::Scanner::SweepViruses::ScannerPID;

    # Destroy the incoming work dir
    $global::MS->{work}->Destroy() if $global::MS && $global::MS->{work};

    # Decrement the counters in the Processing Attempts Database
    $global::MS->{batch}->DecrementProcDB()
      if $global::MS && $global::MS->{batch};

    # Close down all the user's custom functions
    Baruwa::Scanner::Config::EndCustomFunctions();

    # Shut down the Processing Attempts Database
    $Baruwa::Scanner::ProcDBH->disconnect() if $Baruwa::Scanner::ProcDBH;

    # Close down logging neatly
    Baruwa::Scanner::Log::Stop();
    exit 0;
}

sub KillChildren {
    my ( $child, @dirlist );

    $0 = 'Baruwa: killing children, bwahaha!';

    #print STDERR "Killing child processes...\n";
    if ($RunInForeground) {
        print STDOUT "Killing child processes ";
        print STDOUT join( '/', keys %Children );
    }
    kill 1, keys %Children;
    print STDOUT " and giving them time to die...\n" if $RunInForeground;

    sleep 3;    # Give them time to die peacefully
    print STDOUT "Cleaning up..." if $RunInForeground;

    # Clean up after the dying processes in case they left a mess.
    foreach $child ( keys %Children ) {

        #push @dirlist, "$WorkDir/$child" if -d "$WorkDir/$child";
        rmtree( "$WorkDir/$child", 0, 1 ) if -d "$WorkDir/$child";
    }
    print STDOUT "Done\n" if $RunInForeground;
}

#
# Kill the Baruwa Logger
#
sub KillBaruwa {
    $0 = 'Baruwa: killing baruwa!';
    print STDOUT "Killing baruwa process " if $RunInForeground;
    my $currentpid;
    my $pid_dir = '/var/lib/baruwa/scanner';
    my $pid_file = "$pid_dir/baruwa-bs.pid";
    open PID, "<$pid_file" or return;
    $currentpid = <PID>;
    close PID;
    $currentpid =~ m|(\d+)|;
    $currentpid = $1;

    if ($currentpid) {
        print STDOUT "$currentpid" if $RunInForeground;
        kill 1, int($currentpid);
    }
    print STDOUT " and letting it cleanup...." if $RunInForeground;
    sleep 3;
    print STDOUT " Done\n" if $RunInForeground;
}

#
# SIGKILL handler for parent process.
# HUP all the children, then keep working.
#
sub ReloadParent {
    my ($sig) = @_;    # Arg is the signal name

    print STDOUT "Baruwa parent caught a SIG$sig - reload\n"
      if $RunInForeground;

    KillChildren();

    KillBaruwa();

    print STDOUT "Baruwa reloaded.\n" if $RunInForeground;
}

#
# SIGTERM handler for parent process.
# HUP all the children, then commit suicide.
# Cannot log as no logging in the parent.
#
sub ExitParent {
    my ($sig) = @_;    # Arg is the signal name

    print STDOUT "Baruwa parent caught a SIG$sig\n" if $RunInForeground;

    KillChildren();

    KillBaruwa();

    print STDOUT "Exiting Baruwa - Bye.\n" if $RunInForeground;

    unlink $PidFile;    # Ditch the pid file, thanks Res
    exit 0;
}

#
# Start logging
#
sub StartLogging {
    my ($filename) = @_;

    # Create the syslog process name from stripping the conf filename down
    # to the basename without the extension.
    my $procname = $filename;
    $procname =~ s#^.*/##;
    $procname =~ s#\.conf$##;

    my $logbanner =
        "Baruwa E-Mail Content Scanner version "
      . $Baruwa::Scanner::Config::BaruwaVersion
      . " starting...";

    Baruwa::Scanner::Log::Configure( $logbanner, 'syslog' );    #'stderr');

    # Need to know log facility *before* we have read the whole config file!
    my $facility =
      Baruwa::Scanner::Config::QuickPeek( $filename, 'syslogfacility' );
    my $logsock =
      Baruwa::Scanner::Config::QuickPeek( $filename, 'syslogsockettype' );

    Baruwa::Scanner::Log::Start( $procname, $facility, $logsock );
}

#
# Function to harvest dead children
#
sub Reaper {
    1 until waitpid( -1, WNOHANG ) == -1;
    $SIG{'CHLD'} = \&Reaper;    # loathe sysV
}

#
# Fork off and become a daemon so they get their shell back
#
sub ForkDaemon {
    my ($debug) = @_;
    if ($debug) {
        print STDERR "In Debugging mode, not forking...\n";
    }
    elsif ($RunInForeground) {

        # PERT-BBY we don't close STDXX neither fork() nor setsid()
        #          if we want to run in the foreground
        print STDOUT "Baruwa $Baruwa::Scanner::Config::BaruwaVersion "
          . "starting in foreground mode - pid is [$$]\n";
    }
    else {
        $SIG{'CHLD'} = \&Reaper;
        if ( fork == 0 ) {

            # This child's parent is perl
            #print STDERR "In the child\n";
            # Close i/o streams to break connection with tty
            close(STDIN);
            close(STDOUT);
            close(STDERR);

            # Re-open the stdin, stdout and stderr file descriptors for
            # sendmail's benefit. Should stop it squawking!
            open( STDIN,  "</dev/null" );
            open( STDOUT, ">/dev/null" );
            open( STDERR, ">/dev/null" );

            fork && exit 0;

            # This new grand-child's parent is init
            #print STDERR "In the grand-child\n";
            $SIG{'CHLD'} = 'DEFAULT';

            # Auto-reap children
            # Causes problems on some OS's when wait is called
            #$SIG{'CHLD'} = 'IGNORE';
            setsid();
        }
        else {
            #print STDERR "In the parent\n";
            wait;    # Ensure child has exited
            exit 0;
        }

        # This was the old simple code in the 2nd half of the if statement
        #fork && exit;
        #setsid();
    }
}

sub SetUidGid {
    my ( $uid, $gid, $qgid, $igid ) = @_;

    if ($gid) {    # Only do this if setting to non-root
                   #print STDERR "Setting GID to $gid\n";
        Baruwa::Scanner::Log::InfoLog("Baruwa setting GID to $gname ($gid)");

        # assign in parallel to avoid tripping taint mode on
        ( $(, $) ) = ( $gid, $gid );
        $( == $gid && $) == $gid or die "Can't set GID $gid";

        # We add 2 copies of the $gid as the second one is ignored by BSD!
        $) = "$gid $gid $qgid $igid";  # Set the extra group memberships we need
    }
    else {
        $) = $(;
    }
    if ($uid) {                        # Only do this if setting to non-root
                                       #print STDERR "Setting UID to $uid\n";
        Baruwa::Scanner::Log::InfoLog("Baruwa setting UID to $uname ($uid)");

        # assign in parallel to avoid tripping taint mode on
        ( $<, $> ) = ( $uid, $uid );
        $< == $uid && $> == $uid or die "Can't set UID $uid";
    }
    else {
        $> = $<;
    }
}

#
# Check the home directory of the user exists and is writable
#
sub CheckHomeDir {
    my $home = ( getpwuid($<) )[7];

    Baruwa::Scanner::Log::WarnLog("User's home directory $home does not exist")
      unless -d $home;
    unless (
        -w $home
        || ( Baruwa::Scanner::Config::IsSimpleValue('usespamassassin')
            && !Baruwa::Scanner::Config::Value('usespamassassin') )
      )
    {
        Baruwa::Scanner::Log::WarnLog(
            "User's home directory $home is not writable");
        Baruwa::Scanner::Log::WarnLog( "You need to set the \"SpamAssassin User "
              . "State Dir\" to a directory that the \"Run As User\" can write to"
        );
    }
}

#
# Check the versions of the MIME and SpamAssassin modules
#
sub CheckModuleVersions {
    my ($module_version);

    # Check the MIME-tools version
    Baruwa::Scanner::Log::DieLog(
            "FATAL: Newer MIME::Tools module needed: "
          . "MIME::Tools is only %s -- 5.412 required", $MIME::Tools::VERSION
      )
      if defined $MIME::Tools::VERSION
      && $MIME::Tools::VERSION < "5.412";

    # And check the SpamAssassin version
    Baruwa::Scanner::Log::DieLog(
        "FATAL: Newer Mail::SpamAssassin module needed: "
          . "Mail::SpamAssassin is only %s -- 2.1 required",
        $Mail::SpamAssassin::VERSION
      )
      if defined $Mail::SpamAssassin::VERSION
      && $Mail::SpamAssassin::VERSION < "2.1";
}

#
# Check the incoming and (default) outgoing queues are on the same filesystem.
# Baruwa cannot work fast enough if they are in different filesystems.
#
#
# Check the incoming and outgoing queues are on the same device.
# Can only check the default outgoing queue, but that will be
# enough for most users.
#
sub CheckQueuesAreTogether {
    my ( $indevice, $outdevice, @instat, @outstat );
    my ( $inuid,    $outuid,    $ingrp,  $outgrp );

    my @inqdirs;
    my $outqdir = Baruwa::Scanner::Config::Value('outqueuedir');
    push @inqdirs, @{ Baruwa::Scanner::Config::Value('inqueuedir') };

    #print STDERR "Queues are \"" . join('","',@inqdirs) . "\"\n";

    #Baruwa::Scanner::Log::WarnLog("Queuedir is %s", $outqdir);
    #Outq cannot be split: Baruwa::Scanner::Sendmail::CheckQueueIsFlat($outqdir);
    chdir($outqdir);    # This should be the default
    @outstat = stat('.');
    ( $outdevice, $outuid, $outgrp ) = @outstat[ 0, 4, 5 ];
    Baruwa::Scanner::Log::DieLog( "%s is not owned by user %d !", $outqdir, $uid )
      if $uid && ( $outuid != $uid );

    my ($inqdir);
    foreach $inqdir (@inqdirs) {

        # FIXME: $inqdir is somehow tained: work out why!
        $inqdir =~ /(.*)/;
        $inqdir = $1;

        #Baruwa::Scanner::Log::WarnLog("Inq %s", $inqdir);
        Baruwa::Scanner::Sendmail::CheckQueueIsFlat($inqdir);
        chdir($inqdir);
        @instat = stat('.');
        ( $indevice, $inuid, $ingrp ) = @instat[ 0, 4, 5 ];

        Baruwa::Scanner::Log::DieLog(
            "%s & %s must be on the same filesystem/" . "partition!",
            $inqdir, $outqdir )
          unless $indevice == $outdevice;
        Baruwa::Scanner::Log::DieLog( "%s is not owned by user %d !",
            $inqdir, $uid )
          if $uid && ( $inuid != $uid );
    }
}

#
# Create and write a PID file for a given process id
#
sub WritePIDFile {
    my ($process) = @_;

    my $pidfh = new FileHandle;
    $pidfh->open(">$PidFile")
      or
      Baruwa::Scanner::Log::WarnLog( "Cannot write pid file %s, %s", $PidFile, $! );
    print $pidfh "$process\n";
    $pidfh->close();
}

#
# Dump the contents of the "Processing Attempts Database"
sub DumpProcessingDatabase {
    my ( $filename, $minimum ) = @_;

    unless ( eval "require DBD::SQLite" ) {
        Baruwa::Scanner::Log::WarnLog(
            "WARNING: DBI and/or DBD::SQLite Perl modules are not properly installed!"
        );
        return;
    }

    my $DBH = DBI->connect( "dbi:SQLite:$filename", "", "",
        { PrintError => 0, InactiveDestroy => 1 } );

    # Do they just want a dump of the database table?
    if ($DBH) {
        my $currenttable = '';
        my $rows         = $DBH->selectall_arrayref(
            "SELECT id,count,nexttime FROM processing WHERE count>$minimum ORDER BY nexttime DESC",
            { Slice => {} }
        );
        foreach my $row (@$rows) {
            my $now = localtime( $row->{nexttime} );
            $currenttable .=
              $row->{count} . "\t" . $row->{id} . "\t" . $now . "\n";
        }
        if ($currenttable) {
            my $count = @$rows;
            print "Currently being processed:\n\n";
            print "Number of messages: $count\n";
            print "Tries\tMessage\tNext Try At\n=====\t=======\t===========\n";
            print $currenttable;
        }

        my $archivetable = '';
        my $rows         = $DBH->selectall_arrayref(
            "SELECT id,count,nexttime FROM archive WHERE count>$minimum ORDER BY nexttime DESC",
            { Slice => {} }
        );
        foreach my $row (@$rows) {
            my $now = localtime( $row->{nexttime} );
            $archivetable .=
              $row->{count} . "\t" . $row->{id} . "\t" . $now . "\n";
        }
        if ($archivetable) {
            my $count = @$rows;
            print "\n\n" if $currenttable;    # Separator between tables
            print "Archive:\n\n";
            print "Number of messages: $count\n";
            print "Tries\tMessage\tLast Tried\n=====\t=======\t==========\n";
            print $archivetable;
        }
        $DBH->disconnect;
        return;
    }
}

#
# Create the "Processing Attempts Database"
#
sub CreateProcessingDatabase {
    my ($WantLint) = @_;

    # Master switch!
    return unless Baruwa::Scanner::Config::Value('procdbattempts');

    unless ( eval "require DBD::SQLite" ) {
        Baruwa::Scanner::Log::WarnLog(
            "WARNING: DBI and/or DBD::SQLite Perl modules are not properly installed!"
        );
    }

    $Baruwa::Scanner::ProcDBName = Baruwa::Scanner::Config::Value("procdbname");
    if ($WantLint) {
        unless ($Baruwa::Scanner::ProcDBName) {
            Baruwa::Scanner::Log::WarnLog(
                "WARNING: Your Processing Attempts Database name is not set!");
            return;
        }
        unless (
            eval {
                $Baruwa::Scanner::ProcDBH =
                  DBI->connect( "dbi:SQLite:$Baruwa::Scanner::ProcDBName",
                    "", "", { PrintError => 0, InactiveDestroy => 1 } );
            }
          )
        {
            Baruwa::Scanner::Log::WarnLog(
                "ERROR: Could not connect to SQLite database %s.",
                $Baruwa::Scanner::ProcDBName
            );
            return;
        }
    }
    else {
        $Baruwa::Scanner::ProcDBH =
          DBI->connect( "dbi:SQLite:$Baruwa::Scanner::ProcDBName",
            "", "", { PrintError => 0, InactiveDestroy => 1 } );
    }

    if ($Baruwa::Scanner::ProcDBH) {
        Baruwa::Scanner::Log::InfoLog("Connected to Processing Attempts Database");

        # Rebuild all the tables and indexes. The PrintError=>0 will make it
        # fail quietly if they already exist.
        # Speed up writes at the cost of integrity. It's only temp data anyway.
        $Baruwa::Scanner::ProcDBH->do("PRAGMA default_synchronous = OFF");
        $Baruwa::Scanner::ProcDBH->do(
            "CREATE TABLE processing (id TEXT, count INT, nexttime INT)");
        $Baruwa::Scanner::ProcDBH->do(
            "CREATE UNIQUE INDEX id_uniq ON processing(id)");
        $Baruwa::Scanner::ProcDBH->do(
            "CREATE TABLE archive (id TEXT, count INT, nexttime INT)");
        print STDERR "Created Processing Attempts Database successfully\n"
          if $WantLint;
        my $rows = $Baruwa::Scanner::ProcDBH->selectrow_array(
            "SELECT COUNT(*) FROM processing");
        print STDERR "There "
          . ( $rows == 1 ? 'is' : 'are' )
          . " $rows message"
          . ( $rows == 1 ? '' : 's' )
          . " in the Processing Attempts Database\n"
          if $WantLint;
        Baruwa::Scanner::Log::InfoLog(
            "Found %d messages in the Processing Attempts Database", $rows )
          unless $WantLint;

        # Prepare all the SQL statements we will need
        $Baruwa::Scanner::SthSelectId = $Baruwa::Scanner::ProcDBH->prepare(
            "SELECT id,count,nexttime FROM processing WHERE (id=?)");
        $Baruwa::Scanner::SthDeleteId =
          $Baruwa::Scanner::ProcDBH->prepare("DELETE FROM processing WHERE (id=?)");
        $Baruwa::Scanner::SthInsertArchive = $Baruwa::Scanner::ProcDBH->prepare(
            "INSERT INTO archive (id,count,nexttime) VALUES (?,?,?)");
        $Baruwa::Scanner::SthIncrementId = $Baruwa::Scanner::ProcDBH->prepare(
            "UPDATE processing SET count=count+1, nexttime=? WHERE (id=?)");
        $Baruwa::Scanner::SthInsertProc = $Baruwa::Scanner::ProcDBH->prepare(
            "INSERT INTO processing (id,count,nexttime) VALUES (?,?,?)");
        $Baruwa::Scanner::SthSelectRows = $Baruwa::Scanner::ProcDBH->prepare(
            "SELECT id,count,nexttime FROM processing WHERE (id=?)");
        $Baruwa::Scanner::SthSelectCount = $Baruwa::Scanner::ProcDBH->prepare(
            "SELECT count FROM processing WHERE (id=?)");
        $Baruwa::Scanner::SthDecrementId = $Baruwa::Scanner::ProcDBH->prepare(
            "UPDATE processing SET count=count-1 WHERE (id=?)");

        unless ( $Baruwa::Scanner::SthSelectId
            && $Baruwa::Scanner::SthDeleteId
            && $Baruwa::Scanner::SthInsertArchive
            && $Baruwa::Scanner::SthIncrementId
            && $Baruwa::Scanner::SthInsertProc
            && $Baruwa::Scanner::SthSelectRows
            && $Baruwa::Scanner::SthSelectCount
            && $Baruwa::Scanner::SthDecrementId )
        {
            Baruwa::Scanner::Log::WarnLog(
                    "Preparing SQL statements for processing-"
                  . "messages database failed!" );
        }

    }
    else {
        Baruwa::Scanner::Log::WarnLog(
            "Could not create Processing Attempts Database \"%s\"",
            $Baruwa::Scanner::ProcDBName );
    }

}

1;
