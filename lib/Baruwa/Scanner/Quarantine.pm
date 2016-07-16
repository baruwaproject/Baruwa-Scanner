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

package Baruwa::Scanner::Quarantine;

use strict 'vars';
use strict 'refs';
no strict 'subs';    # Allow bare words for parameter %'s

use File::Copy;
use File::Temp qw ( tempfile tempdir );

our $VERSION = '4.086000';

# Attributes are
#
# $dir			set by new The root of the quarantine tree
# $uid			set by new The UID to change files to
# $gid			set by new The GID to change files to
# $changeowner		set by new Should I try to chown the files at all?
# $fileumask		set by new Umask to use before creating files
# $dirumask		set by new Umask to use before mkdir 0777;
#

# Constructor.
# Takes dir => directory queue resides in
sub new {
    my $type = shift;
    my $this = {};

    # Work out the uid and gid they want to use for the quarantine dir
    my ( $currentuid, $currentgid ) = ( $<, $( );
    my ( $destuid, $destuname, $destgid, $destgname );
    $destuname = Baruwa::Scanner::Config::Value('quarantineuser')
      || Baruwa::Scanner::Config::Value('runasuser');
    $destgname = Baruwa::Scanner::Config::Value('quarantinegroup')
      || Baruwa::Scanner::Config::Value('runasgroup');
    $this->{changeowner} = 0;
    if ( $destuname ne "" || $destgname ne "" ) {
        $destuid = $destuname ? getpwnam($destuname) : 0;
        $destgid = $destgname ? getgrnam($destgname) : 0;
        $this->{gid} = $destgid if $destgid != $currentgid;
        $this->{uid} = $destuid if $destuid != $currentuid;
    }
    else {
        $destuid     = 0;
        $destgid     = 0;
        $this->{gid} = 0;
        $this->{uid} = 0;
    }

    # Create a test file to try with chown
    my ( $testfn, $testfh, $worked );

    ( $testfh, $testfn ) = tempfile( 'MS.ownertest.XXXXXX', DIR => '/tmp' )
      or Baruwa::Scanner::Log::WarnLog(
        'Could not test file ownership abilities on %s, please delete the file',
        $testfn
      );
    print $testfh "Testing file owner and group permissions for Baruwa\n";
    $testfh->close;

    # Now test the changes to see if we can do them
    my ( $changeuid, $changegid );
    if ( $destgid != $currentgid ) {
        $worked = chown $currentuid, $destgid, $testfn;
        if ($worked) {
            #print STDERR "Can change the GID of the quarantine\n";
            $changegid = 1;
        }
    }
    else {
        $changegid = 0;
    }
    if ( $destuid != $currentuid ) {
        $worked = chown $destuid, $destgid, $testfn;
        if ($worked) {
            #print STDERR "Can change the UID of the quarantine\n";
            $changeuid = 1;
        }
    }
    else {
        $changeuid = 0;
    }
    unlink $testfn;

    # Finally store the results
    $this->{uid} = $currentuid unless $changeuid;
    $this->{gid} = $currentgid unless $changegid;
    $this->{changeowner} = 1 if $changeuid || $changegid;

    # Now to work out the new umask
    # Default is 0600 for files, which gives 0700 for directories
    my ( $perms, $dirumask, $fileumask );
    $perms = Baruwa::Scanner::Config::Value('quarantineperms') || '0600';
    $perms = sprintf "0%lo", $perms unless $perms =~ /^0/;    # Make it octal
    $dirumask = $perms;
    $dirumask =~ s/[1-7]/$&|1/ge;    # If they want r or w give them x too
    $this->{dirumask}  = oct($dirumask) ^ 0777;
    $fileumask         = $perms;
    $this->{fileumask} = oct($fileumask) ^ 0777;

    #print STDERR sprintf("File Umask = 0%lo\n", $this->{fileumask});
    #print STDERR sprintf("Dir  Umask = 0%lo\n", $this->{dirumask});

    my ($dir);
    $dir = Baruwa::Scanner::Config::Value('quarantinedir');

    #print STDERR "Creating quarantine at dir $dir\n";

    umask $this->{dirumask};
    mkdir( $dir, 0777 ) unless -d $dir;
    chown $this->{uid}, $this->{gid}, $dir if $this->{changeowner};
    umask 0077;  # As this is in startup code, assume something daft will happen

    # Cannot make today's directory here as the date will change while the
    # program is running.

    $this->{dir} = $dir;
    bless $this, $type;
    return $this;
}

# Work out the name of today's directory segment
sub TodayDir {
    my ( $day, $month, $year );

    # Create today's directory if necessary
    ( $day, $month, $year ) = (localtime)[ 3, 4, 5 ];
    $month++;
    $year += 1900;
    return sprintf( "%04d%02d%02d", $year, $month, $day );
}

# Store infected files in the quarantine
sub StoreInfections {
    my $this = shift;
    my ($message) = @_;

    my ( $qdir, $todaydir, $msgdir, $uid, $gid, $changeowner, @chownlist );

    #print STDERR "In StoreInfections\n";

    # Create today's directory if necessary
    #$todaydir = $this->{dir} . '/' . TodayDir();
    $qdir = Baruwa::Scanner::Config::Value( 'quarantinedir', $message );
    $todaydir    = $qdir . '/' . $message->{datenumber};    # TodayDir();
    $uid         = $this->{uid};
    $gid         = $this->{gid};
    $changeowner = $this->{changeowner};
    umask $this->{dirumask};
    unless ( -d $qdir ) {
        mkdir( $qdir, 0777 );
        chown $uid, $gid, $qdir if $changeowner;
    }
    unless ( -d $todaydir ) {
        mkdir( $todaydir, 0777 );
        chown $uid, $gid, $todaydir if $changeowner;
    }

    # Create directory for this message
    $msgdir = "$todaydir/" . $message->{id};
    $msgdir =~ /^(.*)$/;
    $msgdir = $1;
    unless ( -d $msgdir ) {
        mkdir( $msgdir, 0777 );
        chown $uid, $gid, $msgdir if $changeowner;
    }

    # Is there a report for the whole message? If so, save the whole thing.
    # Also save the whole thing if they have asked us to quarantine entire
    # messages, not just infections.
    umask $this->{fileumask};
    if ( $message->{allreports}{""}
        || Baruwa::Scanner::Config::Value( 'quarantinewholemessage', $message ) =~
        /1/ )
    {
        #print STDERR "Saving entire message to $msgdir\n";
        Baruwa::Scanner::Log::NoticeLog("Saved entire message to $msgdir");
        $message->{store}->CopyEntireMessage( $message, $msgdir, 'message',
            $uid, $gid, $changeowner );
        push @chownlist, "$msgdir/message" if -f "$msgdir/message";
        # Remember where we archived it, so we can put it in postmaster notice
        push @{ $message->{quarantineplaces} }, $msgdir;

        #print STDERR "1 Added $msgdir to quarantine\n";
    }

    # Now just quarantine the infected attachment files.
    my ( $indir, $attachment, $notype, $report );
    $indir = $global::MS->{work}->{dir} . '/' . $message->{id};
    while ( ( $attachment, $report ) = each %{ $message->{allreports} } ) {
        # Skip reports pertaining to entire message, we've done those.
        # These $attachments contain type indicators
        next unless $attachment;

        # Get the attachment name without the type indicator, won't store it!
        $notype = substr( $attachment, 1 );

        if ( $message->{deleteattach}{$attachment} ) {
            Baruwa::Scanner::Log::NoticeLog( "Deleted infected \"%s\"", $notype );
        }
        else {
            #print STDERR "Quarantining $attachment to $msgdir\n";
            Baruwa::Scanner::Log::NoticeLog( "Saved infected \"%s\" to %s",
                $notype, $msgdir );

            copy( "$indir/$attachment", "$msgdir/$notype" );
            push @chownlist, "$msgdir/$notype";

          # Remember where we archived it, so we can put it in postmaster notice
            push @{ $message->{quarantineplaces} }, $msgdir;

            #print STDERR "2 Added $msgdir to quarantine\n";
        }
    }
    chown $uid, $gid, @chownlist if @chownlist && $changeowner;

    # Reset the umask to safe value
    umask 0077;
}

