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

# Provide functions to deal with opening + locking spool files

package Baruwa::Scanner::Lock;

use strict;
use Fcntl qw(:DEFAULT :flock);
use POSIX qw(:unistd_h :errno_h);
use vars qw($FLOCK_STRUCT);

my $have_module;
my $LockType;

sub ReportLockType {
    return $LockType;
}

# Run-time initialisation

sub initialise {

    eval {
        require Baruwa::Scanner::Fcntl;
        import Baruwa::Scanner::Fcntl( @Baruwa::Scanner::Fcntl::EXPORT,
            @Baruwa::Scanner::Fcntl::EXPORT_OK );
        1;
    };

    $have_module = ( $@ eq "" ? 1 : 0 );

    # Determine locktype to use
    $LockType =
      ( Baruwa::Scanner::Config::Value('locktype') )
      ? Baruwa::Scanner::Config::Value('locktype')
      : $global::MS->{mta}->{LockType};

    Baruwa::Scanner::Log::DebugLog(
        "lock.pl sees Config  LockType =  " . $LockType );

    Baruwa::Scanner::Log::DebugLog( "lock.pl sees have_module =  " . $have_module );

    # module has bugs
    $LockType =~ /posix/ and $have_module and $LockType = "module";

    Baruwa::Scanner::Log::InfoLog( "Using locktype = " . $LockType );

    # Note that in IEEE Std 1003.1-2001,
    # "The interaction between fcntl() and lockf() locks is unspecified."
    #
    # (bother)
    #
    # And we shouldn't really call these "posix" locks, as although they are
    # specified in POSIX, there are two possible types, which may or may not
    # be the same. DOH!

    # Determine correct struct_flock to use at include time

    # HORRIBLY HARDWIRED
    # would like to "use File::lockf" but that would make
    # installation harder. And lockf isn't guaranteed to
    # do the same thing as fcntl :(
    #
    # CPAN File::Lock also appears to be broken (doesn't build, then when
    # built, doesn't pass it's own tests - including segfaulting)
    #
    # So I'll do it myself.

    if ( $LockType =~ /posix/i ) {
        for ($^O) {
            if ( $_ eq 'linux' ) {
                eval <<'__EOD';

                $FLOCK_STRUCT = 's s LL LL I';

                sub struct_flock {
                my ($start, $len, $pid, $type, $whence);
                if (wantarray) {
                # Interpreting a returned struct
                ($type, $whence, $start, $len, $pid) =
                unpack($FLOCK_STRUCT, $_[0]);
                return ($type, $whence, $start, $len, $pid);
                } else {
                # Building a struct
                ($type, $whence, $start, $len, $pid) = @_;
                return pack($FLOCK_STRUCT, $type, $whence, $start, $len, $pid);
                }
                }
__EOD
                if ( $@ ne "" ) {
                    Baruwa::Scanner::Log::DieLog("Unable to create struct_flock subroutine: $@");
                }
                next;
            }
            Baruwa::Scanner::Log::DieLog("1\n2\n3\n4\n5\nDon't know how to do fcntl locking on '$^O'\nPlease file a bug report.5\n4\n3\n2\n1");
        }
    }
}

# Open and lock a file.
#
# Pass in a filehandle, a filespec (including ">", "<", or
# whatever on the front), and (optionally) the type of lock
# you want - "r" or "s" for shared/read lock, or pretty much
# anything else (but "w" or "x" really) for exclusive/write
# lock.
#
# Lock type used (flock or fcntl/lockf/posix) depends on
# config. If you're using posix locks, then don't try asking
# for a write-lock on a file opened for reading - it'll fail
# with EBADF (Bad file descriptor).
#
# If $quiet is true, then don't print any warning.
#
sub openlock {
    my ( $fh, $fn, $rw, $quiet ) = @_;

    my ($struct_flock);

    defined $rw or $rw = ( ( substr( $fn, 0, 1 ) eq '>' ) ? "w" : "r" );
    $rw =~ /^[rs]/i or $rw = 'w';

    # Set umask every time as SpamAssassin might have reset it
    #umask 0077; # Now cleared up after SpamAssassin runs

    $fn =~ /^(.*)$/;
    $fn = $1;
    unless ( open( $fh, $fn ) ) {    # TAINT
        Baruwa::Scanner::Log::NoticeLog( "Could not open file $fn: %s", $! )
          unless $quiet;
        return 0;
    }

    if ( $LockType =~ /module/i ) {

        #Baruwa::Scanner::Log::DebugLog("Using module to lock $fn");
        Baruwa::Scanner::Fcntl::setlk( $fh, ( $rw eq 'w' ? F_WRLCK : F_RDLCK ) ) ==
          0
          and return 1;
    }
    elsif ( $LockType =~ /posix/i ) {

        # Added 3 zeroes for 'start, length, + pid',
        # otherwise pack was being called with undefined values -- nwp
        #Baruwa::Scanner::Log::DebugLog("Using fcntl() to lock $fn");
        $struct_flock =
          struct_flock( ( $rw eq 'w' ? F_WRLCK : F_RDLCK ), 0, 0, 0, 0 );
        fcntl( $fh, F_SETLK, $struct_flock ) and return 1;
    }
    elsif ( $LockType =~ /flock/i ) {
        #Baruwa::Scanner::Log::DebugLog("Using flock() to lock $fn");
        flock( $fh, ( $rw eq 'w' ? LOCK_EX : LOCK_SH ) + LOCK_NB ) and return 1;
    }
    else {
        Baruwa::Scanner::Log::DebugLog("Not locking spool file $fn");
        return 1;
    }

    close($fh);

    if ( ( $! == POSIX::EAGAIN ) || ( $! == POSIX::EACCES ) ) {
        Baruwa::Scanner::Log::DebugLog( "Failed to lock $fn: %s", $! )
          unless $quiet;
    }
    else {
        Baruwa::Scanner::Log::NoticeLog(
            "Failed to lock $fn with unexpected error: %s", $! );
    }

    return 0;
}

sub unlockclose {
    my ($fh) = @_;

    if ( $LockType =~ /module/i ) {
        Baruwa::Scanner::Fcntl::setlk( $fh, F_UNLCK );
    }
    elsif ( $LockType =~ /posix/i ) {
        fcntl( $fh, F_SETLK, struct_flock( F_UNLCK, 0, 0, 0, 0 ) );
    }
    elsif ( $LockType =~ /flock/i ) {
        flock( $fh, LOCK_UN );
    }

    close($fh);
    return 1;
}

1;
