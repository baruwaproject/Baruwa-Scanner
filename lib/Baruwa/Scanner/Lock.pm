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
use File::FcntlLock::XS;
use Fcntl qw(:DEFAULT :flock);
use POSIX qw(:unistd_h :errno_h);

our $VERSION = '4.086000';

# Open and lock a file.
#
# Pass in a filehandle, a filespec (including ">", "<", or
# whatever on the front), and (optionally) the type of lock
# you want - "r" or "s" for shared/read lock, or pretty much
# anything else (but "w" or "x" really) for exclusive/write
# lock.
#
# If $quiet is true, then don't print any warning.
#
sub openlock {
    my ( $fh, $fn, $rw, $quiet ) = @_;

    my ($lh);

    defined $rw or $rw = ( ( substr( $fn, 0, 1 ) eq '>' ) ? "w" : "r" );
    $rw =~ /^[rs]/i or $rw = 'w';

    $fn =~ /^(.*)$/;
    $fn = $1;
    unless ( open( $fh, $fn ) ) {
        Baruwa::Scanner::Log::NoticeLog( "Could not open file $fn: %s", $! ) unless $quiet;
        return 0;
    }

    $lh = new File::FcntlLock::XS(l_type => ($rw eq 'w' ? F_WRLCK : F_RDLCK),
        l_whence => SEEK_SET,
        l_start => 0,
        l_len => 0
    );
    $lh->lock($fh, F_SETLK) and flock($fh, ($rw eq 'w' ? LOCK_EX : LOCK_SH) + LOCK_NB) and return 1;
    close($fh);

    if (($lh->lock_errno() == POSIX::EAGAIN) || ($lh->lock_errno() == POSIX::EACCES)
        || ($! == POSIX::EAGAIN) || ($! == POSIX::EACCES))
    {
        MailScanner::Log::DebugLog( "Failed to lock $fn: %s", $lh->error() )
          unless $quiet;
    }
    else {
        Baruwa::Scanner::Log::NoticeLog("Failed to lock $fn with unexpected error: %s", $lh->error() );
    }

    return 0;
}

sub unlockclose {
    my ($fh) = @_;

    my ($lh);

    $lh = new File::FcntlLock::XS(l_type => F_UNLCK,
        l_whence => SEEK_SET,
        l_start => 0,
        l_len => 0
    );
    $lh->lock($fh, F_SETLK);
    flock($fh, LOCK_UN);
    close($fh);
    return 1;
}

1;
