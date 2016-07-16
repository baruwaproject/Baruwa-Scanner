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

package Baruwa::Scanner::MCP;

use strict 'vars';
use strict 'refs';
no strict 'subs';    # Allow bare words for parameter %'s

use POSIX qw(:signal_h);    # For Solaris 9 SIG bug workaround
use IO qw(Pipe);

our $VERSION = '4.086000';
our ($SAspamtest $SABayesLock);

# Attributes are
#
#

my $SAversion;
my ($safailures) = 0;

sub initialise {
    my ( %settings, $val, $val2, $prefs );

    # Can't just do this when sendmail.pl loads, as we are still running as
    # root then & spamassassin will get confused when we are later running
    # as something else.

    # If they don't want MCP Checks at all, or they don't want MCP SA Checks
    # then do nothing, else...
    unless (
        (
            Baruwa::Scanner::Config::IsSimpleValue('mcpchecks')
            && !Baruwa::Scanner::Config::Value('mcpchecks')
        )
        || ( Baruwa::Scanner::Config::IsSimpleValue('mcpusespamassassin')
            && !Baruwa::Scanner::Config::Value('mcpusespamassassin') )
      )
    {
        $settings{dont_copy_prefs} = 1;    # Removes need for home directory
        $prefs = Baruwa::Scanner::Config::Value('mcpspamassassinprefsfile');
        $settings{userprefs_filename} = $prefs if defined $prefs;
        $val = Baruwa::Scanner::Config::Value('debugspamassassin');
        $settings{debug} = $val;

        # for unusual bayes and auto whitelist database locations
        $val = Baruwa::Scanner::Config::Value('mcpspamassassinuserstatedir');
        $settings{userstate_dir} = $val if $val ne "";
        $val = Baruwa::Scanner::Config::Value('mcpspamassassinlocalrulesdir');
        $settings{LOCAL_RULES_DIR} = $val if $val ne "";

        # Set the local state directory to a bogus value so it is not used
        $settings{LOCAL_STATE_DIR} = '/BogusSAStateDir';
        $val = Baruwa::Scanner::Config::Value('mcpspamassassindefaultrulesdir');
        $settings{DEF_RULES_DIR} = $val if $val ne "";
        $val = Baruwa::Scanner::Config::Value('mcpspamassassininstallprefix');

        # For version 3 onwards, shouldn't cause problems with earlier code
        $val2 = Baruwa::Scanner::Config::Value('spamassassinautowhitelist');
        $settings{use_auto_whitelist} = $val2 ? 1 : 0;
        $settings{save_pattern_hits} = 1;

        if ( $val ne "" ) {
            # for finding rules in the absence of the above settings
            $settings{PREFIX} = $val;
            my $perl_vers = $] < 5.006 ? $] : sprintf( "%vd", $^V );
            unshift @INC, "$val/lib/perl5/site_perl/$perl_vers";
        }

        # Now we have the path built, try to find the SpamAssassin modules
        Baruwa::Scanner::Log::DieLog(
            "Message Content Protection SpamAssassin installation could not be found"
        ) unless eval "require Mail::SpamAssassin";
        $SAversion = $Mail::SpamAssassin::VERSION + 0.0;

        $Baruwa::Scanner::MCP::SAspamtest = new Mail::SpamAssassin( \%settings );

        # If the Bayes database lock file is still present due to the process
        # being killed, we must delete it. The difficult bit is finding it.
        # Wrap this in an eval for those using old versions of SA which don't
        # have the Bayes engine at all.
        eval {
            my $t = $Baruwa::Scanner::MCP::SAspamtest;
            $Baruwa::Scanner::MCP::SABayesLock =
              $t->sed_path( $t->{conf}->{bayes_path} ) . '.lock';
        };

        # Need to delete lock file now or compile_now may never return
        unlink $Baruwa::Scanner::MCP::SABayesLock;

        $Baruwa::Scanner::MCP::SAspamtest->read_scoreonly_config($prefs);
    }
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

    my ($dfhandle);
    my ( $dfilename, $dfile, @WholeMessage, $SAResult, $SAHitList );
    my ( $HighScoring, $SAScore, $maxsize );

    # Bail out and fake a miss if too many consecutive SA checks failed
    my $maxfailures = Baruwa::Scanner::Config::Value('mcpmaxspamassassintimeouts');

    # If we get maxfailures consecutive timeouts, then disable the
    # SpamAssassin RBL checks in an attempt to get it working again.
    # If it continues to time out for another maxfailures consecutive
    # attempts, then disable it completely.
    if ( $maxfailures > 0 ) {
        if ( $safailures >= 2 * $maxfailures ) {
            return (
                0, 0,
                sprintf(
                    Baruwa::Scanner::Config::LanguageValue(
                        $message, 'mcpsadisabled'
                    ),
                    2 * $maxfailures
                ),
                0
            );
        }
        elsif ( $safailures > $maxfailures ) {
            $Baruwa::Scanner::MCP::SAspamtest->{conf}->{skip_rbl_checks} = 1;
        }
        elsif ( $safailures == $maxfailures ) {
            $Baruwa::Scanner::MCP::SAspamtest->{conf}->{skip_rbl_checks} = 1;
            Baruwa::Scanner::Log::WarnLog(
                "Disabling Message Content Protection SpamAssassin RBL checks");
        }
    }

    $maxsize = Baruwa::Scanner::Config::Value('mcpmaxspamassassinsize');

    # Construct the array of lines of the header and body of the message
    # JKF 30/1/2002 Don't chop off the line endings. Thanks to Andreas Piper
    #               for this.
    #my $h;
    #foreach $h (@{$message->{headers}}) {
    #  push @WholeMessage, $h . "\n";
    #}
    my $fromheader = Baruwa::Scanner::Config::Value( 'envfromheader', $message );
    $fromheader =~ s/:$//;
    push( @WholeMessage, $fromheader . ': ' . $message->{from} . "\n" )
      if $fromheader;

    @WholeMessage = $global::MS->{mta}->OriginalMsgHeaders( $message, "\n" );

    #print STDERR "Headers are : " . join(', ', @WholeMessage) . "\n";
    return ( 0, 0,
        Baruwa::Scanner::Config::LanguageValue( $message, 'mcpsanoheaders' ), 0 )
      unless @WholeMessage;

    push( @WholeMessage, "\n" );
    $message->{store}->ReadBody( \@WholeMessage, $maxsize );

    # Now construct the SpamAssassin object for version < 3
    my $spammail;
    $spammail = Mail::SpamAssassin::NoMailAudit->new( 'data' => \@WholeMessage )
      if $SAversion < 3;

    # Test it for spam-ness
    #print STDERR "About to try MCP\n";
    if ( $SAversion < 3 ) {
        ( $SAResult, $HighScoring, $SAHitList, $SAScore ) =
          SAForkAndTest( $Baruwa::Scanner::MCP::SAspamtest, $spammail, $message );
    }
    else {
        ( $SAResult, $HighScoring, $SAHitList, $SAScore ) =
          SAForkAndTest( $Baruwa::Scanner::MCP::SAspamtest, \@WholeMessage,
            $message );
    }

    return ( $SAResult, $HighScoring, $SAHitList, $SAScore );
}

# Fork and test with SpamAssassin. This implements a timeout on the execution
# of the SpamAssassin checks, which occasionally take a *very* long time to
# terminate due to regular expression backtracking and other nasties.
sub SAForkAndTest {
    my ( $Test, $Mail, $Message ) = @_;

    my ($pipe);
    my ( $SAHitList, $SAHits, $SAReqHits, $IsItSpam, $IsItHighScore );
    my ( $HighScoreVal, $pid2delete, $IncludeScores );
    my $PipeReturn = 0;
    my $Error      = 0;

    $IncludeScores = Baruwa::Scanner::Config::Value( 'mcplistsascores', $Message );

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
        if ( $SAversion < 3 ) {
            $spamness = $Test->check($Mail);
        }
        else {
            my $mail = $Test->parse( $Mail, 1 );
            $spamness = $Test->check($mail);
        }
        print $pipe (
            $SAversion < 3 ? $spamness->get_hits() : $spamness->get_score() )
          . "\n";
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
        print $pipe $HitList . "\n";
        $spamness->finish();
        $pipe->close();
        $pipe = undef;
        exit 0;    # $SAResult;
    }

    eval {
        $pipe->reader();
        local $SIG{ALRM} = sub { die "Command Timed Out" };
        alarm Baruwa::Scanner::Config::Value('mcpspamassassintimeout');
        $SAHits = <$pipe>;

        #print STDERR "Read SAHits = $SAHits " . scalar(localtime) . "\n";
        $SAHitList = <$pipe>;

        #print STDERR "Read SAHitList = $SAHitList " . scalar(localtime) . "\n";
        # Not sure if next 2 lines should be this way round...
        waitpid $pid, 0;
        $pipe->close();
        $PipeReturn = $?;
        alarm 0;
        $pid = 0;
        chomp $SAHits;
        chomp $SAHitList;
        $SAHits     = $SAHits + 0.0;
        $safailures = 0;               # This was successful so zero counter
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
    $SAReqHits =
      Baruwa::Scanner::Config::Value( 'mcpreqspamassassinscore', $Message ) + 0.0;
    $SAHitList =
        Baruwa::Scanner::Config::LanguageValue( $Message, 'score' ) . '='
      . ( $SAHits + 0.0 ) . ', '
      . Baruwa::Scanner::Config::LanguageValue( $Message, 'required' ) . ' '
      . $SAReqHits
      . ( $SAHitList ? ", $SAHitList" : '' );

    # Note to self: I only close the KID in the parent, not in the child.

    # Catch failures other than the alarm
    if ( $@ and $@ !~ /Command Timed Out/ ) {
        Baruwa::Scanner::Log::DieLog(
            "Message Content Protection SpamAssassin failed with real error: $@"
        );
        $Error = 1;
    }

    # In which case any failures must be the alarm
    #if ($@ or $pid>0) {
    if ( $pid > 0 ) {
        $pid2delete = $pid;
        my $maxfailures =
          Baruwa::Scanner::Config::Value('mcpmaxspamassassintimeouts');

        # Increment the "consecutive" counter
        $safailures++;
        if ( $maxfailures > 0 ) {
            if ( $safailures > $maxfailures ) {
                Baruwa::Scanner::Log::WarnLog(
"Message Content Protection SpamAssassin timed out (with no RBL"
                      . " checks) and was killed, consecutive failure "
                      . $safailures . " of "
                      . $maxfailures * 2 );
            }
            else {
                Baruwa::Scanner::Log::WarnLog(
"Message Content Protection SpamAssassin timed out and was killed, "
                      . "consecutive failure "
                      . $safailures . " of "
                      . $maxfailures );
            }
        }
        else {
            Baruwa::Scanner::Log::WarnLog(
"Message Content Protection SpamAssassin timed out and was killed"
            );
        }

        # Make the report say SA was killed
        $SAHitList =
          Baruwa::Scanner::Config::LanguageValue( $Message, 'mcpsatimedout' );
        $SAHits = 0;
        $Error  = 1;

        # Kill the running child process
        my ($i);
        kill -15, $pid;

        # Wait for up to 10 seconds for it to die
        for ( $i = 0 ; $i < 5 ; $i++ ) {
            sleep 1;
            waitpid( $pid, &POSIX::WNOHANG );
            ( $pid = 0 ), last unless kill( 0, $pid );
            kill -15, $pid;
        }

        # And if it didn't respond to 11 nice kills, we kill -9 it
        if ($pid) {
            kill -9, $pid;
            waitpid $pid, 0;    # 2.53
        }

        # As the child process must now be dead, remove the Bayes database
        # lock file if it exists. Only delete the lock file if it mentions
        # $pid2delete in its contents.
        if ( $pid2delete && $Baruwa::Scanner::MCP::SABayesLock ) {
            my $lockfh = new FileHandle;
            if ( $lockfh->open($Baruwa::Scanner::MCP::SABayesLock) ) {
                my $line = $lockfh->getline();
                chomp $line;
                $line =~ /(\d+)$/;
                my $pidinlock = $1;
                if ( $pidinlock =~ /$pid2delete/ ) {
                    unlink $Baruwa::Scanner::MCP::SABayesLock;
                    Baruwa::Scanner::Log::InfoLog( "Delete bayes lockfile for %s",
                        $pid2delete );
                }
                $lockfh->close();
            }
        }

       #unlink $Baruwa::Scanner::MCP::SABayesLock if $Baruwa::Scanner::MCP::SABayesLock;
    }

    #Baruwa::Scanner::Log::WarnLog("8 PID is $pid");

    # The return from the pipe is a measure of how spammy it was
    Baruwa::Scanner::Log::DebugLog(
        "Message Content Protection SpamAssassin returned $PipeReturn");

    # SpamAssassin is known to play with the umask
    umask 0077;    # Safety net

    # Handle the case when there was an error
    if ($Error) {
        Baruwa::Scanner::Log::DebugLog(
            "Message Content Protection SpamAssassin check failed");
        $SAHits = Baruwa::Scanner::Config::Value( 'mcperrorscore', $Message );
    }

    #$PipeReturn = $PipeReturn>>8;
    $IsItSpam = ( $SAHits && $SAHits >= $SAReqHits ) ? 1 : 0;
    $HighScoreVal =
      Baruwa::Scanner::Config::Value( 'mcphighspamassassinscore', $Message );
    $IsItHighScore =
      ( $SAHits && $HighScoreVal > 0 && $SAHits >= $HighScoreVal ) ? 1 : 0;
    return ( $IsItSpam, $IsItHighScore, $SAHitList, $SAHits );
}

1;
