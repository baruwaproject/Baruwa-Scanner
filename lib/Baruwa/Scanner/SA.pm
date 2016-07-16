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

package Baruwa::Scanner::SA;

use strict 'vars';
use strict 'refs';
no strict 'subs';    # Allow bare words for parameter %'s

#use English; # Needed for $PERL_VERSION to work in all versions of Perl

use IO qw(Pipe);
use POSIX qw(:signal_h);    # For Solaris 9 SIG bug workaround
use DBI;
use DBD::SQLite;
use Digest::MD5;
use Compress::Zlib;
use Mail::SpamAssassin;

our $VERSION = '4.086000';

# Attributes are
#
#

my ($LOCK_SH) = 1;
my ($LOCK_EX) = 2;
my ($LOCK_NB) = 4;
my ($LOCK_UN) = 8;

my @SAsuccessqueue;    # queue of failure history
my $SAsuccessqsum;     # current sum of history queue

my ( $SAspamtest, $SABayesLock, $SABayesRebuildLock );

my ( $SQLiteInstalled, $cachedbh, $cachefilename, $NextCacheExpire );

my $HamCacheLife  = 30 * 60;    # Lifetime of non-spam from first seen
my $SpamCacheLife = 5 * 60;     # Lifetime of low-scoring spam from first seen
my $HighSpamCacheLife = 3 * 60 * 60;  # Lifetime of high spam from last seen
my $VirusesCacheLife  = 48 * 60 * 60; # Lifetime of viruses from last seen
my $ExpireFrequency   = 10 * 60;      # How often to run the expiry of the cache

sub CreateTempDir {
    my ( $runasuser, $satmpdir ) = @_;

    # Create the $TMPDIR for SpamAssassin if necessary, then check we can
    # write to it. If not, change to /tmp.
    lstat $satmpdir;
    unless ( -d _ ) {
        unlink $satmpdir;
        mkdir $satmpdir
          or warn
          "Could not create SpamAssassin temporary directory $satmpdir, $!";
    }
    chmod 0700, $satmpdir unless $satmpdir =~ /^\/tmp/;
    chown $runasuser, -1, $satmpdir;

    $ENV{'TMPDIR'} = $satmpdir;
}

sub initialise {
    my ( $RebuildBayes, $WantLintOnly ) =
      @_;    # Start by rebuilding the Bayes database?

    my ( %settings, $val, $val2, $prefs );

    # Initialise the class variables
    @SAsuccessqueue = ();
    $SAsuccessqsum  = 0;

    # If the "debug-sa" command-line flag was given, then we want to print out
    # the current time at the start of each line that is sent to STDERR,
    # in particular the stuff from SpamAssassin.
    if ($Baruwa::Scanner::SA::Debug) {
        my $result;

        open STDERR, "| awk '{printf \"%s %s\\n\", strftime(\"%T\"), \$0}'";
        select STDOUT;
    }

    # Only do this if we want to use SpamAssassin and therefore have it installed.
    # Justin Mason advises only creating 1 Mail::SpamAssassin object, so I do it
    # here while we are starting up.

    # N.B. SpamAssassin will use home dir defined in ENV{HOME}
    #      'if $ENV{HOME} =~ /\//'
    # So, set ENV{HOME} to desired directory, or undef it to force it to get home
    # using getpwnam of $> (EUID)

    unless ( Baruwa::Scanner::Config::IsSimpleValue('usespamassassin')
        && !Baruwa::Scanner::Config::Value('usespamassassin') )
    {
        $settings{post_config_text} = Baruwa::Scanner::ConfigSQL::ReturnSpamAssassinConfig();
        if (defined $settings{post_config_text}) {
            $settings{post_config_text} .= Baruwa::Scanner::Config::SpamAssassinPostConfig();
        }else{
            $settings{post_config_text} = Baruwa::Scanner::Config::SpamAssassinPostConfig();
        }
        $settings{dont_copy_prefs} = 1;    # Removes need for home directory
        # This file is now read directly by SpamAssassin's normal startup code.
        #$prefs = Baruwa::Scanner::Config::Value('spamassassinprefsfile');
        #$settings{userprefs_filename} = $prefs if defined $prefs;
        $val = $Baruwa::Scanner::SA::Debug;
        $settings{debug} = $val;

        # for unusual bayes and auto whitelist database locations
        $val = Baruwa::Scanner::Config::Value('spamassassinuserstatedir');
        $settings{userstate_dir} = $val if $val ne "";
        $val = Baruwa::Scanner::Config::Value('spamassassinlocalrulesdir');
        $settings{LOCAL_RULES_DIR} = $val if $val ne "";
        $val = Baruwa::Scanner::Config::Value('spamassassinlocalstatedir');
        $settings{LOCAL_STATE_DIR} = $val if $val ne "";
        $val = Baruwa::Scanner::Config::Value('spamassassindefaultrulesdir');
        $settings{DEF_RULES_DIR} = $val if $val ne "";
        $val = Baruwa::Scanner::Config::Value('spamassassininstallprefix');

        # For version 3 onwards, shouldn't cause problems with earlier code
        $val2 = Baruwa::Scanner::Config::Value('spamassassinautowhitelist');
        $settings{use_auto_whitelist} = $val2 ? 1 : 0;
        $settings{save_pattern_hits} = 1;

        if ( $val ne "" ) {
            $settings{PREFIX} = $val;
            my $perl_vers = $] < 5.006 ? $] : sprintf( "%vd", $^V );
            unshift @INC, "$val/lib/perl5/site_perl/$perl_vers";
        }

        # Load the SQLite support for the SA data cache
        $SQLiteInstalled = 0;
        unless (Baruwa::Scanner::Config::IsSimpleValue('usesacache') && !Baruwa::Scanner::Config::Value('usesacache'))
        {
            Baruwa::Scanner::Log::InfoLog("Using SpamAssassin results cache");
            $SQLiteInstalled = 1;
            # Put the SA cache database initialisation code here!
            $Baruwa::Scanner::SA::cachefilename = Baruwa::Scanner::Config::Value("sacache");
            $Baruwa::Scanner::SA::cachedbh = DBI->connect(
                "dbi:SQLite:$Baruwa::Scanner::SA::cachefilename",
                "", "", { PrintError => 0, InactiveDestroy => 1 } );
            $NextCacheExpire = $ExpireFrequency + time;
            if ($Baruwa::Scanner::SA::cachedbh) {
                Baruwa::Scanner::Log::InfoLog("Connected to SpamAssassin cache database");
                # Rebuild all the tables and indexes. The PrintError=>0 will make it
                # fail quietly if they already exist.
                # Speed up writes at the cost of database integrity. Only tmp data!
                $Baruwa::Scanner::SA::cachedbh->do("PRAGMA default_synchronous = OFF");
                $Baruwa::Scanner::SA::cachedbh->do("CREATE TABLE cache (
                    md5 TEXT, count INTEGER, last TIMESTAMP, first TIMESTAMP,
                    sasaysspam INT, sahighscoring INT, sascore FLOAT, saheader BLOB,
                    salongreport BLOB, virusinfected INT)"
                );
                $Baruwa::Scanner::SA::cachedbh->do("CREATE UNIQUE INDEX md5_uniq ON cache(md5)");
                $Baruwa::Scanner::SA::cachedbh->do("CREATE INDEX last_seen_idx ON cache(last)");
                $Baruwa::Scanner::SA::cachedbh->do("CREATE INDEX first_seen_idx ON cache(first)");
                $SQLiteInstalled = 1;
                SetCacheTimes();
                # Now expire all the old tokens
                CacheExpire() unless $WantLintOnly;
            }
            else {
                Baruwa::Scanner::Log::WarnLog("Could not create SpamAssassin cache database %s",
                    $Baruwa::Scanner::SA::cachefilename );
                $SQLiteInstalled = 0;
                print STDERR "Could not create SpamAssassin cache database $Baruwa::Scanner::SA::cachefilename\n"
                  if $WantLintOnly;
            }
        }

        $Baruwa::Scanner::SA::SAspamtest = new Mail::SpamAssassin(\%settings);

        if ($WantLintOnly) {
            my $errors = $Baruwa::Scanner::SA::SAspamtest->lint_rules();
            if ($errors) {
                print STDERR "SpamAssassin reported an error.\n";
                $Baruwa::Scanner::SA::SAspamtest->debug_diagnostics();
            }
            else {
                print STDERR "SpamAssassin reported no errors.\n";
            }
            return;
        }

        # Rebuild the Bayes database if it is due
        $Baruwa::Scanner::SA::BayesRebuildLock = Baruwa::Scanner::Config::Value('lockfiledir') . '/Baruwa.bayes.rebuild.lock';
        $Baruwa::Scanner::SA::BayesRebuildStartLock = Baruwa::Scanner::Config::Value('lockfiledir') . '/Baruwa.bayes.starting.lock';
        $Baruwa::Scanner::SA::WaitForRebuild = Baruwa::Scanner::Config::Value('bayeswait');
        $Baruwa::Scanner::SA::DoingBayesRebuilds = Baruwa::Scanner::Config::Value('bayesrebuild');
        if ($RebuildBayes) {
            #Baruwa::Scanner::Log::InfoLog('SpamAssassin Bayes database rebuild preparing');
            # Tell the other children that we are trying to start a rebuild
            my $RebuildStartH = new FileHandle;
            unless ($RebuildStartH->open("+>$Baruwa::Scanner::SA::BayesRebuildStartLock"))
            {
                Baruwa::Scanner::Log::WarnLog(
                    "Bayes rebuild process could not write to "
                      . "%s to signal starting",
                    $Baruwa::Scanner::SA::BayesRebuildStartLock
                );
            }

            # 20090107 Get exclusive lock on the startlock
            #flock($RebuildStartH, $LOCK_EX);
            flock( $RebuildStartH, $LOCK_EX );
            $RebuildStartH->seek( 0, 0 );
            $RebuildStartH->autoflush();
            print $RebuildStartH "1\n";
            flock( $RebuildStartH, $LOCK_UN );
            $RebuildStartH->close();

            # Get an exclusive lock on the bayes rebuild lock file
            my $RebuildLockH = new FileHandle;
            if ( $RebuildLockH->open("+>$Baruwa::Scanner::SA::BayesRebuildLock") ) {
                flock( $RebuildLockH, $LOCK_EX )
                  or Baruwa::Scanner::Log::WarnLog(
                    "Failed to get exclusive lock on %s, %s",
                    $Baruwa::Scanner::SA::BayesRebuildLock, $! );

                # Do the actual expiry run
                $0 = 'Baruwa: rebuilding Bayes database';
                Baruwa::Scanner::Log::InfoLog('SpamAssassin Bayes database rebuild starting');
                eval {
                    $Baruwa::Scanner::SA::SAspamtest->init_learner(
                        {
                            force_expire      => 1,
                            learn_to_journal  => 0,
                            wait_for_lock     => 1,
                            caller_will_untie => 1
                        }
                    );
                    $Baruwa::Scanner::SA::SAspamtest->rebuild_learner_caches(
                        {
                            verbose  => 0,
                            showdots => 0
                        }
                    );
                    $Baruwa::Scanner::SA::SAspamtest->finish_learner();
                };
                Baruwa::Scanner::Log::WarnLog("SpamAssassin Bayes database rebuild "
                      . "failed with error: %s", $@
                ) if $@;

                # Unlock the "starting" lock
                $RebuildStartH = new FileHandle;
                $RebuildStartH->open("+>$Baruwa::Scanner::SA::BayesRebuildStartLock");
                flock( $RebuildStartH, $LOCK_EX );
                $RebuildStartH->seek( 0, 0 );
                $RebuildStartH->autoflush();
                print $RebuildStartH "0\n";
                flock( $RebuildStartH, $LOCK_UN );
                $RebuildStartH->close();
                flock( $RebuildLockH, $LOCK_UN );
                $RebuildLockH->close();
                Baruwa::Scanner::Log::InfoLog('SpamAssassin Bayes database rebuild completed');
            }

            # Now the rebuild has properly finished, we let the other children back
            $RebuildStartH->close();
        }

        if ( Baruwa::Scanner::Config::Value('spamassassinautowhitelist') ) {
            Baruwa::Scanner::Log::InfoLog("Enabling SpamAssassin auto-whitelist functionality...");
        }

        # If the Bayes database lock file is still present due to the process
        # being killed, we must delete it. The difficult bit is finding it.
        # Wrap this in an eval for those using old versions of SA which don't
        # have the Bayes engine at all.
        eval {
            my $t = $Baruwa::Scanner::SA::SAspamtest;
            $Baruwa::Scanner::SA::SABayesLock = $t->sed_path( $t->{conf}->{bayes_path} ) . '.lock';
            #print STDERR "SA bayes lock is $Baruwa::Scanner::SA::SABayesLock\n";
        };

        #print STDERR "Bayes lock is at $Baruwa::Scanner::SA::SABayesLock\n";

        # Need to delete lock file now or compile_now may never return
        unlink $Baruwa::Scanner::SA::SABayesLock;

        # If they are using MCP at all, then we need to compile SA differently
        # here due to object clashes within SA.
        if ( Baruwa::Scanner::Config::IsSimpleValue('mcpchecks')
            && !Baruwa::Scanner::Config::Value('mcpchecks') )
        {
            # They are definitely not using MCP
            $Baruwa::Scanner::SA::SAspamtest->compile_now();
        }
        else {
            # They are possibly using MCP somewhere
            # Next line should have a 0 parameter in it
            #$Baruwa::Scanner::SA::SAspamtest->compile_now(0);
            $Baruwa::Scanner::SA::SAspamtest->read_scoreonly_config($prefs);
        }
    }

    # Turn off warnings again, as SpamAssassin switches them on
    $^W = 0;
}

# Set all the cache expiry timings from the cachetiming conf option
sub SetCacheTimes {
    my $line = Baruwa::Scanner::Config::Value('cachetiming');
    $line =~ s/^\D+//;
    return unless $line;
    my @numbers = split /\D+/, $line;
    return unless @numbers;

    $HamCacheLife      = $numbers[0] if $numbers[0];
    $SpamCacheLife     = $numbers[1] if $numbers[1];
    $HighSpamCacheLife = $numbers[2] if $numbers[2];
    $VirusesCacheLife  = $numbers[3] if $numbers[3];
    $ExpireFrequency   = $numbers[4] if $numbers[4];
    #print STDERR "Timings are \"" . join(' ',@numbers) . "\"\n";
}

# Constructor.
sub new {
    my $type = shift;
    my $this = {};

    bless $this, $type;
    return $this;
}

# Do the SpamAssassin checks on the passed in message
sub Checks {
    my $message = shift;

    my ( $dfhandle,    $SAReqHits, $HighScoreVal );
    my ( $dfilename,   $dfile,     @WholeMessage, $SAResult, $SAHitList );
    my ( $HighScoring, $SAScore,   $maxsize, $SAReport, $GSHits );
    my $GotFromCache = undef;    # Did the result come from the cache?
    $SAReqHits = Baruwa::Scanner::Config::Value( 'reqspamassassinscore', $message ) + 0.0;
    $HighScoreVal = Baruwa::Scanner::Config::Value( 'highspamassassinscore', $message );
    $GSHits = $message->{gshits} || 0.0;

    # Bail out and fake a miss if too many consecutive SA checks failed
    my $maxfailures = Baruwa::Scanner::Config::Value('maxspamassassintimeouts');

    # If we get maxfailures consecutive timeouts, then disable the
    # SpamAssassin RBL checks in an attempt to get it working again.
    # If it continues to time out for another maxfailures consecutive
    # attempts, then disable it completely.
    if ( $maxfailures > 0 ) {
        if ( $SAsuccessqsum >= 2 * $maxfailures ) {
            return (
                0, 0,
                sprintf(
                    Baruwa::Scanner::Config::LanguageValue(
                        $message, 'sadisabled'
                    ),
                    2 * $maxfailures
                ),
                0
            );
        }
        elsif ( $SAsuccessqsum > $maxfailures ) {
            $Baruwa::Scanner::SA::SAspamtest->{conf}->{local_tests_only} = 1;
        }
        elsif ( $SAsuccessqsum == $maxfailures ) {
            $Baruwa::Scanner::SA::SAspamtest->{conf}->{local_tests_only} = 1;
            Baruwa::Scanner::Log::WarnLog("Disabling SpamAssassin network checks");
        }
    }

    # If the Bayes rebuild is in progress, then either wait for it to
    # complete, or just bail out as we are busy.
    # Get a shared lock on the bayes rebuild lock file.
    # If we don't want to wait for it, then do a non-blocking call and
    # just return if it couldn't be locked.
    my $BayesIsLocked = 0;
    my ( $RebuildLockH, $Lockopen );
    if ($Baruwa::Scanner::SA::DoingBayesRebuilds) {
        # If the lock file exists at all, do not try to get a lock on it.
        # Shared locks are handed out even when someone else is trying to
        # get an exclusive lock, so long as at least 1 other shared lock
        # already exists.
        my $fh = new FileHandle;
        $fh->open( "+<" . $Baruwa::Scanner::SA::BayesRebuildStartLock );
        flock( $fh, $LOCK_EX );
        $fh->seek( 0, 0 );
        my $line = <$fh>;
        flock( $fh, $LOCK_UN );
        $fh->close();

        if ( $line =~ /1/ ) {
            # Do we wait for Bayes rebuild to occur?
            if ($Baruwa::Scanner::SA::WaitForRebuild) {
                $0 = 'Baruwa: waiting for Bayes rebuild';
                # Wait quietly for the file to disappear
                # This must not take more than 1 hour or we are in trouble!
                #Baruwa::Scanner::Log::WarnLog("Waiting for rebuild start request to disappear");
                my $waiter = 0;
                for (
                    $waiter = 0 ;
                    $waiter < 3600 && $line =~ /1/ ;
                    $waiter += 30
                  )
                {
                    sleep 30;
                    $fh = new FileHandle;
                    $fh->open( "+<" . $Baruwa::Scanner::SA::BayesRebuildStartLock );
                    flock( $fh, $LOCK_EX );
                    $fh->seek( 0, 0 );
                    $line = <$fh>;
                    flock( $fh, $LOCK_UN );
                    $fh->close();
                }

                if ( $waiter >= 4000 ) {
                    $fh = new FileHandle;
                    $fh->open( "+>" . $Baruwa::Scanner::SA::BayesRebuildStartLock );
                    flock( $fh, $LOCK_EX );
                    $fh->seek( 0, 0 );
                    $fh->autoflush();
                    print $fh "0\n";
                    flock( $fh, $LOCK_UN );
                    $fh->close();
                }

                #Baruwa::Scanner::Log::WarnLog("Start request has disappeared");
                $0 = 'Baruwa: checking with SpamAssassin';
            }
            else {
                # Return saying we are skipping SpamAssassin this time
                return ( 0, 0, 'SpamAssassin rebuilding', 0 );
            }
        }

        $Lockopen     = 0;
        $RebuildLockH = new FileHandle;

        if ( open( $RebuildLockH, "+>" . $Baruwa::Scanner::SA::BayesRebuildLock ) )
        {
            print $RebuildLockH "SpamAssassin Bayes database locked for use by "
              . "Baruwa $$\n";

            #Baruwa::Scanner::Log::InfoLog("Bayes lock is $RebuildLockH");
            #Baruwa::Scanner::Log::InfoLog("Bayes lock is read-write");
            $Lockopen = 1;

            #The lock file already exists, so just open for reading
        }
        elsif ( open( $RebuildLockH, $Baruwa::Scanner::SA::BayesRebuildLock ) ) {
            #Baruwa::Scanner::Log::InfoLog("Bayes lock is $RebuildLockH");
            #Baruwa::Scanner::Log::InfoLog("Bayes lock is read-only");
            $Lockopen = 1;
        }
        else {
            # Could not open the file at all
            $Lockopen = 0;
            Baruwa::Scanner::Log::WarnLog(
                "Could not open Bayes rebuild lock file %s, %s",
                $Baruwa::Scanner::SA::BayesRebuildLock, $! );
        }

        if ($Lockopen) {
            #Baruwa::Scanner::Log::InfoLog("Bayes lock is open");
            if ($Baruwa::Scanner::SA::WaitForRebuild) {
                # Do a normal lock and wait for it
                flock( $RebuildLockH, $LOCK_SH )
                  or Baruwa::Scanner::Log::WarnLog(
                    "At start of SA checks could not get "
                      . "shared lock on %s, %s",
                    $Baruwa::Scanner::SA::BayesRebuildLock, $!
                  );
                $BayesIsLocked = 1;
            }
            else {
                #Baruwa::Scanner::Log::InfoLog("Bayes lock2 is %s", $RebuildLockH);
                if ( flock( $RebuildLockH, ( $LOCK_SH | $LOCK_NB ) ) ) {
                    # Baruwa::Scanner::Log::InfoLog("Got non-blocking shared lock on Bayes lock");
                    $BayesIsLocked = 1;
                }
                else {
                    #Baruwa::Scanner::Log::InfoLog("Skipping Bayes due to %s", $!);
                    $RebuildLockH->close();
                    #Baruwa::Scanner::Log::InfoLog("Skipping SpamAssassin while waiting for Bayes database to rebuild");
                    return ( 0, 0, 'SpamAssassin rebuilding', 0 );
                }
            }
        }
        else {
            Baruwa::Scanner::Log::WarnLog("At start of SA checks could not open %s, %s",
                $Baruwa::Scanner::SA::BayesRebuildLock, $! );
        }
    }

    $maxsize = Baruwa::Scanner::Config::Value('maxspamassassinsize');

    # Construct the array of lines of the header and body of the message
    # JKF 30/1/2002 Don't chop off the line endings. Thanks to Andreas Piper
    #               for this.
    # For SpamAssassin 3 we add the "EnvelopeFrom" header to make SPF work
    my $fromheader = Baruwa::Scanner::Config::Value( 'envfromheader', $message );
    $fromheader =~ s/:$//;

    # Build a list of all the headers, so we can remove any $fromheader that
    # is already in there.
    my @SAheaders = $global::MS->{mta}->OriginalMsgHeaders( $message, "\n" );
    @SAheaders = grep !/^$fromheader\:/i, @SAheaders;
    @SAheaders = grep !/^\s*$/,           @SAheaders;    # ditch blank lines

    # Fix for RP_8BIT rule issue by Steve Freegard
    #push(@WholeMessage, $fromheader . ': ' . $message->{from} . "\n")
    unshift( @SAheaders, $fromheader . ': ' . $message->{from} . "\n" )
      if $fromheader;

    # Add the spamvirusreport to the input to SA.
    # The header name should be documented in the baruwa.conf docs.
    my $svheader = Baruwa::Scanner::Config::Value( 'spamvirusheader', $message );
    if ( $svheader && $message->{spamvirusreport} ) {
        $svheader =~ s/:$//;
        unshift( @SAheaders,
            $svheader . ': ' . $message->{spamvirusreport} . "\n" );
        #print STDERR "Added $svheader: " . $message->{spamvirusreport} . "\n";
    }

    # Return-Path header should only be present on final delivery.
    # See RFC5321 Section 4.4.
    # Sendmail appears to add a placeholder Return-Path header which it uses
    # for expansion later, unfortunately this placeholder uses high-bit chars.
    # So we remove the header and create one from the envelope for SA.
    @SAheaders = grep !/^Return-Path\:/i, @SAheaders;
    unshift( @SAheaders, 'Return-Path: <' . $message->{from} . ">\n" );

    push( @WholeMessage, @SAheaders );

    #print STDERR "Headers are : " . join(', ', @WholeMessage) . "\n";
    unless (@WholeMessage) {
        flock( $RebuildLockH, $LOCK_UN ) if $BayesIsLocked;
        $RebuildLockH->close() if $Baruwa::Scanner::SA::DoingBayesRebuilds;
        return ( 0, 0,
            Baruwa::Scanner::Config::LanguageValue( $message, 'sanoheaders' ), 0 );
    }

    push( @WholeMessage, "\n" );

    my (@WholeBody);
    $message->{store}->ReadBody( \@WholeBody, $maxsize );
    push( @WholeMessage, @WholeBody );

    # Work out the MD5 sum of the body
    my ( $testcache, $md5, $md5digest );
    if ($SQLiteInstalled) {
        $testcache = Baruwa::Scanner::Config::Value( "usesacache", $message );
        $testcache = ( $testcache =~ /1/ ) ? 1 : 0;
        $md5 = Digest::MD5->new;
        eval { $md5->add(@WholeBody) };
        if ( $@ ne "" || @WholeBody <= 1 ) {
            # The eval failed
            $md5digest = "unknown";
            $testcache = 0;
        }
        else {
            # The md5->add worked okay, so use the results
            # Get the MD5 digest of the message body
            $md5digest = $md5->hexdigest;
        }

        # Store it for later
        $message->{md5} = $md5digest;

        #print STDERR "MD5 digest is $md5digest\n";
    }
    else {
        $testcache = 0;

        #print STDERR "Not going to use cache\n";
    }

    if ($testcache) {
        if ( my $cachehash = CheckCache($md5digest) ) {

            #print STDERR "Cache hit for " . $message->{id} . "\n";
            Baruwa::Scanner::Log::InfoLog( "SpamAssassin cache hit for message %s",
                $message->{id} );

            # Read the cache result and update the timestamp *****
            ( $SAHitList, $SAScore, $SAReport ) = (
                uncompress( $cachehash->{saheader} ),
                $cachehash->{sascore}, uncompress( $cachehash->{salongreport} )
            );

            # calculate SAResult and HighScoring from actual message
            ( $SAResult, $HighScoring ) =
              SATest_spam( $message, $GSHits, $SAScore );

            # Log the fact we got it from the cache. Must not add the "cached"
            # word on the front here or it will be put into the cache itself!
            $GotFromCache = 1;

           # Need to make sure that any differences in scores are being utilized
            if ( $SAScore >= $SAReqHits ) {
                $SAResult = 1;
                $SAHitList =~ s/required ([\d\.]+)\,/required $SAReqHits\,/;
                $HighScoring = 1 if !$HighScoring && $SAScore >= $HighScoreVal;
            }
            elsif ( $SAScore < $SAReqHits ) {
                $SAResult = 0;
                $SAHitList =~ s/required ([\d\.]+)\,/required $SAReqHits\,/;
                $HighScoring = 0 if $HighScoring && $SAScore < $HighScoreVal;
            }

            #print STDERR "Cache results are $SAResult, $HighScoring, $SAHitList, $SAScore, $SAReport\n";
            # Unlock and close the lockfile
            flock( $RebuildLockH, $LOCK_UN )
              if $Baruwa::Scanner::SA::DoingBayesRebuilds;    # $BayesIsLocked;
            $RebuildLockH->close() if $Baruwa::Scanner::SA::DoingBayesRebuilds;
        }
        else {
            # Do the actual SpamAssassin call
            #print STDERR "Cache miss for " . $message->{id} . "\n";

            #print STDERR "Check 1, report template = \"" .
            #      $Baruwa::Scanner::SA::SAspamtest->{conf}->{report_template} . "\"\n";
            ($SAResult, $HighScoring, $SAHitList, $SAScore, $SAReport) =
              SAForkAndTest( $GSHits, $Baruwa::Scanner::SA::SAspamtest, \@WholeMessage, $message );

            # Log the fact we didn't get it from the cache. Must not add the
            # "not cached" word on the front here or it will be put into the
            # cache itself!
            $GotFromCache = 0;

            #Baruwa::Scanner::Log::WarnLog("Done SAForkAndTest");
            #print STDERR "SAResult = $SAResult\nHighScoring = $HighScoring\n" .
            #             "SAHitList = $SAHitList\n";

            # Write the record to the cache *****
            # Don't cache "timed out" results.
            if ( $SAHitList ne
                Baruwa::Scanner::Config::LanguageValue( $message, 'satimedout' ) )
            {
                CacheResult( $md5digest, $SAResult, $HighScoring,
                    compress($SAHitList), $SAScore, compress($SAReport) );
            }

            # Unlock and close the lockfile
            flock( $RebuildLockH, $LOCK_UN )
              if $Baruwa::Scanner::SA::DoingBayesRebuilds;    # $BayesIsLocked;
            $RebuildLockH->close() if $Baruwa::Scanner::SA::DoingBayesRebuilds;
        }

        # Add the cached / not cached tag to $SAHitList if appropriate
        if ( defined($GotFromCache) ) {
            if ($GotFromCache) {
                $SAHitList =
                    Baruwa::Scanner::Config::LanguageValue( $message, 'cached' )
                  . ', '
                  . $SAHitList;
            }
            else {
                $SAHitList =
                    Baruwa::Scanner::Config::LanguageValue( $message, 'notcached' )
                  . ', '
                  . $SAHitList;
            }
        }

    }
    else {
        # No cache here

        #print STDERR "Check 1, report template = \"" .
        #      $Baruwa::Scanner::SA::SAspamtest->{conf}->{report_template} . "\"\n";
        ($SAResult, $HighScoring, $SAHitList, $SAScore, $SAReport) =
          SAForkAndTest($GSHits, $Baruwa::Scanner::SA::SAspamtest, \@WholeMessage, $message);

        #Baruwa::Scanner::Log::WarnLog("Done SAForkAndTest");
        #print STDERR "SAResult = $SAResult\nHighScoring = $HighScoring\n" .
        #             "SAHitList = $SAHitList\n";
        # Unlock and close the lockfile
        flock( $RebuildLockH, $LOCK_UN ) if $Baruwa::Scanner::SA::DoingBayesRebuilds;    # $BayesIsLocked;
        $RebuildLockH->close() if $Baruwa::Scanner::SA::DoingBayesRebuilds;
    }

    return ( $SAResult, $HighScoring, $SAHitList, $SAScore, $SAReport );
}

# Look up the passed MD5 in the cache database and return true/false
sub CheckCache {
    my $md5 = shift;

    my ( $sql, $sth );
    $sql = "SELECT md5, count, last, first, sasaysspam, sahighscoring, sascore, saheader, salongreport FROM cache WHERE md5=?";
    my $hash = $Baruwa::Scanner::SA::cachedbh->selectrow_hashref( $sql, undef, $md5 );

    if ( defined($hash) ) {
        # Cache hit!
        #print STDERR "Cache hit $hash!\n";
        # Update the counter and timestamp
        $sql = "UPDATE cache SET count=count+1, last=strftime('%s','now') WHERE md5=?";
        $sth = $Baruwa::Scanner::SA::cachedbh->prepare($sql);
        $sth->execute($md5);
        return $hash;
    }
    else {
       # Cache miss... we'll create the cache record after SpamAssassin has run.
       #print STDERR "Cache miss!\n";
        return undef;
    }
}

# Check to see if the cache should have an expiry run done, do it if so.
sub CheckForCacheExpire {
    # Check to see if a cache expiry run is needed
    CacheExpire() if $NextCacheExpire <= time;
    # NextCacheExpire is updated by CacheExpire() so not needed here.
}

sub CacheResult {
    my ( $md5, $SAResult, $HighScoring, $SAHitList, $SAScore, $SAReport ) = @_;
    my $dbh = $Baruwa::Scanner::SA::cachedbh;

    #print STDERR "dbh is $dbh and cachedbh is $Baruwa::Scanner::SA::cachedbh\n";

    my $sql = "INSERT INTO cache (md5, count, last, first, sasaysspam, sahighscoring, sascore, saheader, salongreport) VALUES (?,?,?,?,?,?,?,?,?)";
    my $sth = $dbh->prepare($sql);

    #print STDERR "$sth, $@\n";
    my $now = time;
    $sth->execute(
        $md5, 1, $now, $now, $SAResult,
        $HighScoring, $SAScore, $SAHitList, $SAReport
    );
}

# Expire records from the cache database
sub CacheExpire {
    my $expire1 = shift || $HamCacheLife;       # non-spam
    my $expire2 = shift || $SpamCacheLife;      # low-scoring spam
    my $expire3 = shift || $HighSpamCacheLife;  # everything else except viruses
    my $expire4 = shift || $VirusesCacheLife;   # viruses

    return unless $SQLiteInstalled;

    my $sth = $Baruwa::Scanner::SA::cachedbh->prepare("
    DELETE FROM cache WHERE (
    (sasaysspam=0 AND virusinfected<1 AND first<=(strftime('%s','now')-?)) OR
    (sasaysspam>0 AND sahighscoring=0 AND virusinfected<1 AND first<=(strftime('%s','now')-?)) OR
    (sasaysspam>0 AND sahighscoring>0 AND virusinfected<1 AND last<=(strftime('%s','now')-?)) OR
    (virusinfected>=1 AND last<=(strftime('%s','now')-?))
    )" );
    Baruwa::Scanner::Log::DieLog("Database complained about this: %s. I suggest you delete your %s file and let me re-create it for you",
        $DBI::errstr, Baruwa::Scanner::Config::Value("sacache")
    ) unless $sth;
    my $rows = $sth->execute( $expire1, $expire2, $expire3, $expire4 );
    $sth->finish;

    Baruwa::Scanner::Log::InfoLog( "Expired %s records from the SpamAssassin cache", $rows )
      if $rows > 0;

    # This is when we should do our next cache expiry (20 minutes from now)
    $NextCacheExpire = time + $ExpireFrequency;
}

# Add the virus information to the cache entry so we can keep infected
# attachment details a lot longer than normal spam.
sub AddVirusStats {
    my ($message) = @_;

    #my $virus;
    return unless $message;

    return
      unless $SQLiteInstalled
      && Baruwa::Scanner::Config::Value( "usesacache", $message ) =~ /1/;

    my $sth = $Baruwa::Scanner::SA::cachedbh->prepare(
        'UPDATE cache SET virusinfected=? WHERE md5=?');

    $sth->execute( $message->{virusinfected}, $message->{md5} )
      or Baruwa::Scanner::Log::WarnLog($DBI::errstr);
}

# Fork and test with SpamAssassin. This implements a timeout on the execution
# of the SpamAssassin checks, which occasionally take a *very* long time to
# terminate due to regular expression backtracking and other nasties.
sub SAForkAndTest {
    my ( $GSHits, $Test, $Mail, $Message ) = @_;
    my ($pipe);
    my ( $SAHitList, $SAHits, $SAReqHits, $IsItSpam, $IsItHighScore, $AutoLearn );
    my ( $HighScoreVal, $pid2delete, $IncludeScores, $SAReport, $queuelength );
    my $PipeReturn = 0;

    #print STDERR "Check 2, is \"" . $Test->{conf}->{report_template} . "\"\n";

    $IncludeScores = Baruwa::Scanner::Config::Value( 'listsascores', $Message );
    $queuelength   = Baruwa::Scanner::Config::Value( 'satimeoutlen', $Message );

    $pipe = new IO::Pipe
      or Baruwa::Scanner::Log::DieLog(
        'Failed to create pipe, %s, try reducing '
          . 'the maximum number of unscanned messages per batch',
        $!
      );

    my $pid = fork();
    die "Can't fork: $!" unless defined($pid);

    if ( $pid == 0 ) {
        # In the child
        my ( $spamness, $SAResult, $HitList, @HitNames, $Hit );
        $pipe->writer();
        $pipe->autoflush();

        # Do the actual tests and work out the integer result
        my $mail = $Test->parse( $Mail, 1 );
        $spamness = $Test->check($mail);
        print $pipe $spamness->get_score() . "\n";
        $HitList = $spamness->get_names_of_tests_hit();
        if ($IncludeScores) {
            @HitNames = split( /\s*,\s*/, $HitList );
            $HitList = "";
            foreach $Hit (@HitNames) {
                $HitList .= ( $HitList ? ', ' : '' )
                  . $Hit . ' '
                  . sprintf( "%1.2f", $spamness->{conf}->{scores}->{$Hit} );
            }
        }

        $spamness->learn();
        $AutoLearn = $spamness->{auto_learn_status};
        $AutoLearn = 'no' if $AutoLearn eq 'failed' || $AutoLearn eq "";
        $AutoLearn = 'not spam' if $AutoLearn eq 'ham';

        print $pipe $AutoLearn . "\n";

        print $pipe $HitList . "\n";

        # JKF New code here to print out the full spam report
        $HitList = $spamness->get_report();
        $HitList =~ tr/\n/\0/;
        print $pipe $HitList . "\n";
        $spamness->finish();
        $pipe->close();
        $pipe = undef;
        exit 0;    # $SAResult;
    }

    eval {
        $pipe->reader();
        local $SIG{ALRM} = sub { die "Command Timed Out" };
        alarm Baruwa::Scanner::Config::Value('spamassassintimeout');
        $SAHits = <$pipe>;

        #print STDERR "Read SAHits = $SAHits " . scalar(localtime) . "\n";
        $AutoLearn = <$pipe>;
        $SAHitList = <$pipe>;
        $SAReport  = <$pipe>;

        #print STDERR "Read SAHitList = $SAHitList " . scalar(localtime) . "\n";
        # Not sure if next 2 lines should be this way round...
        $pipe->close();
        waitpid $pid, 0;
        $PipeReturn = $?;
        alarm 0;
        $pid = 0;
        chomp $SAHits;
        chomp $AutoLearn;
        chomp $SAHitList;
        $SAHits = $SAHits + 0.0;

        #$safailures = 0; # This was successful so zero counter
        # We got a result so store a success
        push @SAsuccessqueue, 0;

        # Roll the queue along one
        $SAsuccessqsum += ( shift @SAsuccessqueue ) ? 1 : -1
          if @SAsuccessqueue > $queuelength;

        #print STDERR "Success: sum = $SAsuccessqsum\n";
        $SAsuccessqsum = 0 if $SAsuccessqsum < 0;
    };
    alarm 0;

    # Workaround for bug in perl shipped with Solaris 9,
    # it doesn't unblock the SIGALRM after handling it.
    eval {
        my $unblockset = POSIX::SigSet->new(SIGALRM);
        sigprocmask( SIG_UNBLOCK, $unblockset )
          or die "Could not unblock alarm: $!\n";
    };

    # Construct the hit-list including the score we got.
    my ($longHitList);
    $SAReqHits = Baruwa::Scanner::Config::Value( 'reqspamassassinscore', $Message ) + 0.0;
    $longHitList = Baruwa::Scanner::Config::LanguageValue( $Message, 'score' ) . '='
      . ( $SAHits + 0.0 ) . ', '
      . Baruwa::Scanner::Config::LanguageValue( $Message, 'required' ) . ' '
      . $SAReqHits;
    $longHitList .= ", autolearn=$AutoLearn" unless $AutoLearn eq 'no';
    $longHitList .= ", $SAHitList" if $SAHitList;
    $SAHitList = $longHitList;

    # Note to self: I only close the KID in the parent, not in the child.

    # Catch failures other than the alarm
    Baruwa::Scanner::Log::DieLog("SpamAssassin failed with real error: $@")
      if $@ and $@ !~ /Command Timed Out/;

    # In which case any failures must be the alarm
    if ( $pid > 0 ) {
        $pid2delete = $pid;
        my $maxfailures = Baruwa::Scanner::Config::Value('maxspamassassintimeouts');
        # Increment the "consecutive" counter
        #$safailures++;
        if ( $maxfailures > 0 ) {
            # We got a failure
            push @SAsuccessqueue, 1;
            $SAsuccessqsum++;

            # Roll the queue along one
            $SAsuccessqsum += ( shift @SAsuccessqueue ) ? 1 : -1
              if @SAsuccessqueue > $queuelength;

            #print STDERR "Failure: sum = $SAsuccessqsum\n";
            $SAsuccessqsum = 1 if $SAsuccessqsum < 1;

            if (   $SAsuccessqsum > $maxfailures
                && @SAsuccessqueue >= $queuelength )
            {
                Baruwa::Scanner::Log::WarnLog(
                    "SpamAssassin timed out (with no network"
                      . " checks) and was killed, failure %d of %d",
                    $SAsuccessqsum,
                    $maxfailures * 2
                );
            }
            else {
                Baruwa::Scanner::Log::WarnLog(
                    "SpamAssassin timed out and was killed, "
                      . "failure %d of %d",
                    $SAsuccessqsum, $maxfailures
                );
            }
        }
        else {
            Baruwa::Scanner::Log::WarnLog("SpamAssassin timed out and was killed");
        }

        # Make the report say SA was killed
        $SAHitList = Baruwa::Scanner::Config::LanguageValue( $Message, 'satimedout' );
        $SAHits = 0;

        # Kill the running child process
        my ($i);
        kill 15, $pid;    # Was -15
                          # Wait for up to 10 seconds for it to die
        for ( $i = 0 ; $i < 5 ; $i++ ) {
            sleep 1;
            waitpid( $pid, &POSIX::WNOHANG );
            ( $pid = 0 ), last unless kill( 0, $pid );
            kill 15, $pid;    # Was -15
        }

        # And if it didn't respond to 11 nice kills, we kill -9 it
        if ($pid) {
            kill 9, $pid;     # Was -9
            waitpid $pid, 0;  # 2.53
        }

        # As the child process must now be dead, remove the Bayes database
        # lock file if it exists. Only delete the lock file if it mentions
        # $pid2delete in its contents.
        if ( $pid2delete && $Baruwa::Scanner::SA::SABayesLock ) {
            my $lockfh = new FileHandle;
            if ( $lockfh->open($Baruwa::Scanner::SA::SABayesLock) ) {
                my $line = $lockfh->getline();
                chomp $line;
                $line =~ /(\d+)$/;
                my $pidinlock = $1;
                if ( $pidinlock =~ /$pid2delete/ ) {
                    unlink $Baruwa::Scanner::SA::SABayesLock;
                    Baruwa::Scanner::Log::InfoLog( "Delete bayes lockfile for %s",
                        $pid2delete );
                }
                $lockfh->close();
            }
        }
        #unlink $Baruwa::Scanner::SA::SABayesLock if $Baruwa::Scanner::SA::SABayesLock;
    }

    #Baruwa::Scanner::Log::WarnLog("8 PID is $pid");

    # SpamAssassin is known to play with the umask
    umask 0077;    # Safety net

    # The return from the pipe is a measure of how spammy it was
    Baruwa::Scanner::Log::DebugLog("SpamAssassin returned $PipeReturn");

    #print STDERR "Check 3, is \"" . $Test->{conf}->{report_template} . "\"\n";
    ( $IsItSpam, $IsItHighScore ) = SATest_spam( $Message, $GSHits, $SAHits );

    return ( $IsItSpam, $IsItHighScore, $SAHitList, $SAHits, $SAReport );
}

#
# Subroutine to calculate whether the mail is SPAM or not
#
sub SATest_spam {
    my ( $Message, $GSHits, $SAHits ) = @_;
    my ( $IsItSpam, $IsItHighScore ) = ( 0, 0 );

    my $SAReqHits = 0.0 + Baruwa::Scanner::Config::Value( 'reqspamassassinscore', $Message );
    if ( $SAHits && ( $SAHits + $GSHits >= $SAReqHits ) ) {
        $IsItSpam = 1;
    }

    my $HighScoreVal = 0.0 + Baruwa::Scanner::Config::Value( 'highspamassassinscore', $Message );
    if (   $SAHits
        && $HighScoreVal > 0
        && ( $SAHits + $GSHits >= $HighScoreVal ) )
    {
        $IsItHighScore = 1;
    }

    return ( $IsItSpam, $IsItHighScore );
}

sub SATest {
    my ( $GSHits, $Test, $Mail, $Message ) = @_;
    my ( $SAHitList, $SAHits, $SAReqHits, $IsItSpam, $IsItHighScore, $AutoLearn );
    my ( $HighScoreVal, $pid2delete, $IncludeScores, $SAReport, $queuelength );
    my $PipeReturn = 0;

    $IncludeScores = Baruwa::Scanner::Config::Value( 'listsascores', $Message );
    $queuelength   = Baruwa::Scanner::Config::Value( 'satimeoutlen', $Message );

    my ( $spamness, $SAResult, $HitList, @HitNames, $Hit );

    my $mail = $Test->parse( $Mail, 1 );
    $spamness = $Test->check($mail);

    # 1st output is get_hits or get_score \n
    $SAHits = $spamness->get_score() + 0.0;
    $HitList = $spamness->get_names_of_tests_hit();
    if ($IncludeScores) {
        @HitNames = split( /\s*,\s*/, $HitList );
        $HitList = "";
        foreach $Hit (@HitNames) {
            $HitList .=
                ( $HitList ? ', ' : '' )
              . $Hit . ' '
              . sprintf( "%1.2f", $spamness->{conf}->{scores}->{$Hit} );
        }
    }

    $spamness->learn();
    $AutoLearn = $spamness->{auto_learn_status};
    $AutoLearn = 'no' if $AutoLearn eq 'failed' || $AutoLearn eq "";
    $AutoLearn = 'not spam' if $AutoLearn eq 'ham';

    # 3rd output is $HitList \n
    $SAHitList = $HitList;

    # JKF New code here to print out the full spam report
    $HitList = $spamness->get_report();
    $HitList =~ tr/\n/\0/;

    # 4th output is $HitList \n which is now full spam report
    $SAReport = $HitList . "\n";
    $spamness->finish();

    #print STDERR "Read SAHits = $SAHits " . scalar(localtime) . "\n";

    # Construct the hit-list including the score we got.
    my ($longHitList);
    $SAReqHits = Baruwa::Scanner::Config::Value( 'reqspamassassinscore', $Message ) + 0.0;
    $longHitList = Baruwa::Scanner::Config::LanguageValue( $Message, 'score' ) . '='
      . ( $SAHits + 0.0 ) . ', '
      . Baruwa::Scanner::Config::LanguageValue( $Message, 'required' ) . ' '
      . $SAReqHits;
    $longHitList .= ", autolearn=$AutoLearn" unless $AutoLearn eq 'no';
    $longHitList .= ", $SAHitList" if $SAHitList;
    $SAHitList = $longHitList;

    # SpamAssassin is known to play with the umask
    umask 0077;    # Safety net

    if ( $SAHits && ( $SAHits + $GSHits >= $SAReqHits ) ) {
        $IsItSpam = 1;
    }
    else {
        $IsItSpam = 0;
    }
    $HighScoreVal = Baruwa::Scanner::Config::Value( 'highspamassassinscore', $Message );
    if (   $SAHits
        && $HighScoreVal > 0
        && ( $SAHits + $GSHits >= $HighScoreVal ) )
    {
        $IsItHighScore = 1;
    }
    else {
        $IsItHighScore = 0;
    }
    return ( $IsItSpam, $IsItHighScore, $SAHitList, $SAHits, $SAReport );
}

1;
