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

#
# Functions which are to do with the MTA, but are slightly higher-level
# than that in that they are the same whichever MTA we are using.
#

package Baruwa::Scanner::Mail;

use strict 'vars';
use strict 'refs';
no strict 'subs';    # Allow bare words for parameter %'s

use vars qw($VERSION);

### The package version, both in 1.23 style *and* usable by MakeMaker:
$VERSION = substr q$Revision: 877 $, 10;

# Attributes are
#

# Kick the MTA into doing a delivery attempt on these messages.
# Take a list of message objects as its input.
# Only kick it for messages that aren't set to just "queue".
sub TellAbout {
    my (@messages) = @_;

    my ( @idlist, @ThisBatch, $message, %OutQueues, %Sendmail2 );

    return unless @messages;

    Baruwa::Scanner::Log::DebugLog("About to deliver " . scalar(@messages) . " messages" )
      if @messages;

    # Build a list of the messages we actually have to tell sendmail about
    foreach $message (@messages) {
        my $outq = Baruwa::Scanner::Config::Value( 'outqueuedir', $message );
        $OutQueues{$outq} .= " " . $message->{id}
          #push @idlist, $message->{id}
          unless Baruwa::Scanner::Config::Value( 'deliverymethod', $message ) eq
          'queue';
        $Sendmail2{$outq} = Baruwa::Scanner::Config::Value( 'sendmail2', $message );
    }

    # If there are no "kicking" messages in the list, just get out
    #return unless @idlist;
    return unless %OutQueues;
    # Now takes a hash of queues-->space-separated string of message ids
    Baruwa::Scanner::Sendmail::KickMessage( \%OutQueues, \%Sendmail2 );
}

# Constructor.
# Takes dir => directory queue resides in
sub new {
    my $type = shift;
    my $this = {};

    #$this->{dir} = shift;

    bless $this, $type;
    return $this;
}

