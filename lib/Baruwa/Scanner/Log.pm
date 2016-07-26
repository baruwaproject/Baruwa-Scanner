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

###########################################################
# Syslog library calls
###########################################################

package Baruwa::Scanner::Log;

use strict;
use Sys::Syslog();
use Carp;

our $VERSION = '4.086000';
our ($LogType, $Banner, $WarningsOnly);

# Used to say 'syslog' but for the baruwa.conf syntax checking code I
# need the default log output to be stderr, as I don't know enough to start
# the logging properly.
$LogType |= 'syslog';    #'stderr';
$WarningsOnly = 0;

sub Configure {
    my ( $banner, $type ) = @_;

    $Banner  = $banner ? $banner : undef;
    $LogType = $type   ? $type   : 'syslog';
}

sub WarningsOnly {
    $WarningsOnly = 1;
}

sub Start {
    my ( $name, $facility, $logsock ) = @_;

    $logsock =~ s/\W//g;    # Take out all the junk

    # These are needed later if we need to restart the logging connection
    # due to a SIGPIPE.
    $Baruwa::Scanner::Log::name     = $name;
    $Baruwa::Scanner::Log::facility = $facility;
    $Baruwa::Scanner::Log::logsock  = $logsock;

    if ( $LogType eq 'syslog' ) {
        if ( $logsock eq '' ) {
            $logsock = 'unix';
        }
        $Baruwa::Scanner::Log::logsock = $logsock;
        print STDERR "Trying to setlogsock($logsock)\n" unless $WarningsOnly;
        eval { Sys::Syslog::setlogsock($logsock); };
        eval { Sys::Syslog::openlog( $name, 'pid, nowait', $facility ); };
    }

    if ( defined $Banner ) {
        InfoLog($Banner);
    }
}

# Re-open the logging, used after SA::initialise has nobbled it due to
# nasty Razor code.
sub Reset {
    if ( $LogType eq 'syslog' ) {
        eval { Sys::Syslog::setlogsock($Baruwa::Scanner::Log::logsock); };
        eval {
            Sys::Syslog::openlog( $Baruwa::Scanner::Log::name, 'pid, nowait',
                $Baruwa::Scanner::Log::facility );
        };
    }
}

sub Stop {
    Sys::Syslog::closelog() if $LogType eq 'syslog';
}

sub DieLog {

    # closelog changes $! in @_
    my (@x) = @_;

    my $logmessage = sprintf shift @x, @x;

    LogText( $logmessage, 'err' );

    Sys::Syslog::closelog() if $LogType eq 'syslog';

    croak "$logmessage";
}

sub WarnLog {
    my (@x) = @_;
    my $logmessage = sprintf shift @x, @x;

    LogText( $logmessage, 'warning' );

    carp $logmessage if $LogType eq 'stderr';
}

sub NoticeLog {
    my (@x) = @_;
    my $logmessage = sprintf shift @x, @x;

    unless ($WarningsOnly) {
        LogText( $logmessage, 'notice' );

        print STDERR "$logmessage\n" if $LogType eq 'stderr';
    }
}

sub InfoLog {
    my (@x) = @_;
    my $logmessage = sprintf shift @x, @x;

    unless ($WarningsOnly) {
        LogText( $logmessage, 'info' );

        print STDERR "$logmessage\n" if $LogType eq 'stderr';
    }
}

sub DebugLog {
    my (@x) = @_;
    if ( Baruwa::Scanner::Config::Value('debug') ) {
        my $logmessage = sprintf shift @x, @x;

        LogText( $logmessage, 'debug' );

        print STDERR "$logmessage\n" if $LogType eq 'stderr';
    }
}

sub LogText {
    my ( $logmessage, $level ) = @_;

    return unless $LogType eq 'syslog';

    # Force use of 8-bit characters, UTF16 breaks syslog badly.
    use bytes;

    foreach ( split /\n/, $logmessage ) {
        s/%/%%/g;
        eval { Sys::Syslog::syslog( $level, $_ ) if $_ ne "" };
    }

    no bytes;
}

1;
