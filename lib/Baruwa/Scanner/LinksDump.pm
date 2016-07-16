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

package Baruwa::Scanner::LinksDump;

use strict 'vars';
use strict 'refs';
no strict 'subs';    # Allow bare words for parameter %'s

use DirHandle;
use POSIX qw(:signal_h setsid);    # For Solaris 9 SIG bug workaround

our $VERSION = '4.086000';

# Attributes are
#

# Constructor.
sub new {
    my $type = shift;
    my $this = {};

    #$this->{dir} = shift;

    bless $this, $type;
    return $this;
}

# Look through an entity to find Doc files. Recursive.
sub FindHTMLFiles {
    my ( $entity, $parent, $already ) = @_;

    #print STDERR "Called with entity=$entity, parent=$parent\n";
    my ( @parts, $body, $part, $path, $headfile, $doc, $k, $v );
    my %empty = ();

    # CASE: Null leaf, fallen off the tree.
    return $already unless $entity;

    # CASE: Leaf node is attachment. Add just this node to what we were given.
    $body = $entity->bodyhandle;
    if ( defined($body) && defined( $body->path ) ) {

        # data is on disk:
        $path = $body->path;
        $path = $1 if $path =~ /([^\/]+)$/;

        #print STDERR "Found an attachment, Path is $path\n";
        if ( $path =~ /\.html?$|\.aspx?$/i ) {
            $already->{$path} = $parent;

            #print STDERR "Added $path --> $parent\n";
            return $already;
        }

        #return ($path,@already) if $path =~ /\.doc$/i;
    }

    # CASE: Non-leaf node, branch node, has children. Add each child.
    @parts = $entity->parts;
    foreach $part (@parts) {

        #print STDERR "Calling FindDocFiles $part\n";
        my $newones = FindDocFiles( $part, $entity, \%empty );
        while ( ( $k, $v ) = each %$newones ) {

            #print STDERR "Adding children $k --> $v\n";
            $already->{$k} = $v;
        }
    }

    #print STDERR "Returning " . join(',',@already) . "\n";
    return $already;
}

# Convert the doc file stored at $1/$2.
# Also passed in the parent entity, so we know what subtree to expand, and
# the message as it comes in handy.
# Use antiword.
# Return 1 on success, 0 on failure.
sub RunLinks {
    my ( $dir, $docname, $parententity, $message ) = @_;

    # Create the subdir to unpack it into
    my $unpackfile = $docname;
    $unpackfile =~ s/\.html?$|\.aspx?$/.txt$1/i;
    my $attachfile = substr( $unpackfile, 1 );

    # Normal attachment so starts with an 'n'.
    $unpackfile = $message->MakeNameSafe( $unpackfile, $dir );

    my $antiword =
      Baruwa::Scanner::Config::Value( 'links', $message );    #-m UTF-8.txt";
    return 0 unless $antiword;

    my $cmd =
      "$antiword -dump '$dir/$docname' > '$dir/$unpackfile' 2>/dev/null";

    my ($kid);
    my ( $TimedOut, $PipeReturn, $pid );
    $kid = new FileHandle;

    $TimedOut = 0;
    my $OldHome = $ENV{'HOME'};
    $ENV{'HOME'} = '/';

    eval {
        die "Can't fork: $!" unless defined( $pid = open( $kid, "-|" ) );
        if ($pid) {

            # In the parent
            local $SIG{ALRM} =
              sub { $TimedOut = 1; die "Command Timed Out" };    # 2.53
            alarm Baruwa::Scanner::Config::Value('linkstimeout');
            close $kid;    # This will wait for completion
            $PipeReturn = $?;
            $pid        = 0;
            alarm 0;

            # Workaround for bug in perl shipped with Solaris 9,
            # it doesn't unblock the SIGALRM after handling it.
            eval {
                my $unblockset = POSIX::SigSet->new(SIGALRM);
                sigprocmask( SIG_UNBLOCK, $unblockset )
                  or die "Could not unblock alarm: $!\n";
            };
        }
        else {
            POSIX::setsid();    # 2.53
            exec $cmd or die "Can't run Links at $antiword: $!";
        }
    };
    alarm 0;                    # 2.53

    # Note to self: I only close the $kid in the parent, not in the child.

    # Catch failures other than the alarm
    Baruwa::Scanner::Log::DieLog("Links HTML converter failed with real error: $@")
      if $@ and $@ !~ /Command Timed Out/;

    # In which case any failures must be the alarm
    if ( $@ or $pid > 0 ) {

        # Kill the running child process
        my ($i);
        kill 'TERM', $pid;

        # Wait for up to 5 seconds for it to die
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
    }

    # Now the child is dead, look at all the return values
    if ( defined $OldHome ) {
        $ENV{'HOME'} = $OldHome;
    }
    else {
        delete $ENV{'HOME'};
    }

    # we want to deliver unparsable DOC files anyway
    return 0 if $TimedOut || $PipeReturn;    # Command failed to exit w'success

    # It all worked, so now add everything back into the message.
    #print STDERR "Dir is \"$dir\" and docname is \"$docname\"\n";

    $parententity->make_multipart;
    my ( $safename, @replacements, $unpacked );
    return 0 unless -f "$dir/$unpackfile" && -s "$dir/$unpackfile";

    # The only file that ever existed in the message structure is the safename.
    # Trim off the leading type indicator, as we're storing unsafe filename.
    my $f = substr( $unpackfile, 1 );
    $message->{file2parent}{$f} = $docname;
    $parententity->attach(
        Type        => "text/plain",
        Charset     => "utf-8",
        Encoding    => "8bit",
        Disposition => "attachment",
        Filename    => $attachfile,
        Path        => "$dir/$unpackfile"
    );
    $message->{bodymodified} = 1;

    $unpackfile = substr( $unpackfile, 1 );    # Trim off before output logging.
    $docname    = substr( $docname,    1 );    # Trim off before output logging.
    Baruwa::Scanner::Log::InfoLog( "Message %s added HTML doc '%s' text as %s",
        $message->{id}, $docname, $unpackfile );

    return 1;                                  # Command succeded and terminated
}

1;

