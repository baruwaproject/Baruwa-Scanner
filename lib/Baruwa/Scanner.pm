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

package Baruwa::Scanner;

use strict 'vars';
use strict 'refs';
no strict 'subs';
require 5.006_001;

our $VERSION = '4.086000';
our $AUTHORITY = 'cpan:DATOPDOG';

# Attributes are
#
# @inq          set by new = list of directory names
# $work         set by new
# $mta          set by new
# $quar                 set by new
# $batch        set by WorkForHours
#

# Constructor.
# Takes dir => directory queue resides in
sub new {
    my $type   = shift;
    my %params = @_;
    my $this   = {};

    $this->{inq}  = $params{InQueue};
    $this->{work} = $params{WorkArea};
    $this->{mta}  = $params{MTA};
    $this->{quar} = $params{Quarantine};

    bless $this, $type;
    return $this;
}

1; # End of Baruwa::Scanner
