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

package Baruwa::Scanner::ConfigSQL;

use strict;
use Baruwa::Scanner::Config;
use DBI;
use Sys::Hostname;
use Sys::SigAction qw( set_sig_handler );

our $VERSION = '4.086000';

# Package globals
our (%PercentVars);
my ($disabled) = 0;
our ($child) = 0;
my ($ConfFile);
my ($hostname) = hostname;

# Debug
our ($debug);

# Database variables
my ($dsn);
my ($db_user);
my ($db_pass);

# SQL statements
my ($sql_sn);
my ($sql_qp);
my ($sql_cf);
my ($sql_rs);
my ($sql_sa);

# Serial number
my ($serial);

# Next update
my ($serial_next);

# Update interval
my ($serial_min) = 60 * 15;    # 15 minutes

sub db_connect {
    my ($file) = shift;
    return undef if not -e $file;
    return undef if $disabled;

    # Set the $ConfFile package global
    $ConfFile = $file if not(defined($ConfFile));

    $dsn = Baruwa::Scanner::Config::QuickPeek($file, 'LocalDBDSN')
      if (!defined($dsn));
    $db_user = Baruwa::Scanner::Config::QuickPeek($file, 'DBUsername')
      if (!defined($db_user));
    $db_pass = Baruwa::Scanner::Config::QuickPeek($file, 'DBPassword')
      if (!defined($db_pass));
    if (!defined($debug)) {
        $debug = Baruwa::Scanner::Config::QuickPeek($file, 'SQLDebug');
        $debug = (lc($debug) eq 'yes') ? 1 : 0;
    }

    # Disable database functions if required data not present
    if (!$dsn || !$db_user || !$db_pass) {
        $disabled = 1;
        print STDERR "Database functions disabled\n" if $debug;
        return undef;
    }

    my ($dbh);

    eval {
        my $h = set_sig_handler('ALRM', sub {die "timeout";},
            {flags => 0, safe => 0});
        alarm(30);
        if ($child) {
            $dbh = DBI->connect_cached(
                $dsn, $db_user, $db_pass,
                {   RaiseError                 => 1,
                    InactiveDestroy            => 1,
                    AutoCommit                 => 1,
                    ShowErrorStatement         => 1,
                    private_configsql_cachekey => 'child'
                }
            );
        } else {

            # PARENT
            $dbh = DBI->connect_cached(
                $dsn, $db_user, $db_pass,
                {   RaiseError                 => 1,
                    InactiveDestroy            => 0,
                    AutoCommit                 => 1,
                    ShowErrorStatement         => 1,
                    private_configsql_cachekey => 'parent'
                }
            );
        }
        alarm(0);
    };
    alarm(0);
    if ($@) {

        # Error; abort and cause child to exit
        my ($err) = $@;
        eval {
            Baruwa::Scanner::Log::DieLog('Database connection error: %s', $err);
        };
        if ($@) {
            die "Database connection error: $err\n";
        }
    }

    # Otherwise return handle
    return $dbh;
}

sub QuickPeek {
    my ($file, $option) = @_;
    return undef if not($file && $option);
    return undef if $disabled;

    # Prevent loops
    return undef if $option =~ /^(db|sql|localdb)/;

    $sql_qp = Baruwa::Scanner::Config::QuickPeek($file, 'SQLQuickPeek')
      if not(defined($sql_qp));
    if (!$sql_qp) {
        $disabled = 1;
        return undef;
    }

    my ($dbh) = db_connect($file) || return undef;
    my ($sth) = $dbh->prepare_cached($sql_qp);
    $sth->execute($option, $hostname);
    if ($sth->err) {
        eval {
            Baruwa::Scanner::Log::WarnLog("ConfigSQL QuickPeek error: %s",
                $sth->errstr);
        };
        printf STDERR ("ConfigSQL QuickPeek error: %s\n", $sth->errstr) if ($@);
    } else {
        my (@row) = $sth->fetchrow_array;
        if (@row) {
            my ($value) = $row[0];
            printf STDERR "ConfigSQL QuickPeek for %s found %s\n", $option,
              $value
              if $debug;
            $sth->finish;
            return $value;
        } else {
            printf STDERR "ConfigSQL QuickPeek for %s NOT FOUND\n", $option
              if $debug;
            $sth->finish;
            return undef;
        }
    }
    return undef;
}

sub ReadConfBasic {
    my ($conf, $File, $CustomVars) = @_;
    return undef if not defined($conf);
    return undef if not ref($File);
    return undef if $disabled;

    $sql_cf = Baruwa::Scanner::Config::QuickPeek($conf, 'SQLConfig')
      if not defined($sql_cf);
    if (!$sql_cf) {
        $disabled = 1;
        return undef;
    }

    my ($dbh) = db_connect($conf) || return undef;
    my ($sth) = $dbh->prepare_cached($sql_cf);
    $sth->execute($hostname);
    if ($sth->err) {
        Baruwa::Scanner::Log::WarnLog("ConfigSQL statement error %s",
            $sth->errstr);
        return undef;
    } else {
        my ($opt, $val, $host, %baruwavars);
        $sth->bind_columns(undef, \$opt, \$val, \$host);
        while ($sth->fetch()) {
            $opt = lc($opt);
            if ($opt eq 'confserialnumber') {
                $serial      = $val;
                $serial_next = time() + $serial_min;
                eval {
                    Baruwa::Scanner::Log::InfoLog(
                        "ConfigSQL configuration loaded with serial %d, next check in %d seconds",
                        $serial,
                        ($serial_next - time())
                    );
                };
                if ($@) {
                    printf STDERR
                      "ConfigSQL configuration loaded with serial %d, next check in %d seconds\n",
                      $serial, ($serial_next - time());
                }
                next;
            }

            # next if $opt =~ /^%.*?%$/;
            next
              if defined $baruwavars{$opt} and $baruwavars{$opt} == $hostname;
            $baruwavars{$opt} = $host;

            # Store percent variables
            if ($opt =~ /^\%([^%]+)\%$/) {

                # Always use the first definition of the %variable%
                $PercentVars{lc($1)} = $val
                  unless exists $PercentVars{lc($1)};
                next;
            }

            # print STDOUT "$opt: $val\n";
            # Expand percent variables
            $val =~ s/\%([^%]+)\%/$PercentVars{lc($1)}/g;

            # Translate \n
            $val =~ s/\\n/\n/g;

            # Expand variables
            $val =~ s/\$\{?(\w+)\}?/$ENV{$1}/g;
            if ($debug) {
                printf STDERR "ConfigSQL ReadConfBasic: %s => %s\n", $opt, $val
                  if ($debug);
                if ($File->{$opt} ne $val) {
                    print STDERR "SQL Override: $opt => "
                      . $File->{$opt}
                      . " => $val\n";
                }
            }
            $File->{$opt} = $val;
        }
        undef(%baruwavars);
        my ($key);
        my %h = %$CustomVars;
        foreach my $k (keys %h) {
            $val = $h{$k};
            ($key) = ($val =~ /\%([^%]+)\%/);
            if (exists $PercentVars{lc($key)}) {
                $val =~ s/\%([^%]+)\%/$PercentVars{lc($1)}/g;
                $val =~ s/\\n/\n/g;
                $val =~ s/\$\{?(\w+)\}?/$ENV{$1}/g;
                if ($debug) {
                    if ($File->{$k} ne $val) {
                        print STDERR "SQL Overide: $k => "
                          . $File->{$k}
                          . " =>  $val\n";
                    }
                }
                $File->{$k} = $val;
            }
        }
    }
    return undef;
}

sub ReadRuleset {
    my ($keyword) = @_;
    return undef if not $keyword;
    return undef if $disabled;

    $sql_rs = Baruwa::Scanner::Config::QuickPeek($ConfFile, 'SQLRuleset')
      if not(defined($sql_rs));
    return undef if not $sql_rs;

    my ($dbh) = db_connect($ConfFile) || return undef;
    my ($sth) = $dbh->prepare_cached($sql_rs);
    $sth->execute($keyword);
    if ($sth->err) {
        Baruwa::Scanner::Log::WarnLog(
            "ConfigSQL ruleset statement error: %s (ruleset %s)",
            $sth->errstr, $keyword);
        return undef;
    } else {
        printf STDERR "ConfigSQL ReadRuleset: %s\n", $keyword if $debug;
        return $sth->fetchall_arrayref({});
    }
    return undef;
}

sub ReturnSpamAssassinConfig {
    return undef if $disabled;
    my (@text) = ();

    return undef if not(defined($ConfFile));
    $sql_sa =
      Baruwa::Scanner::Config::QuickPeek($ConfFile, 'SQLSpamAssassinConfig')
      if not(defined($sql_sa));
    return undef if (!$sql_sa);

    my ($dbh) = db_connect($ConfFile) || return undef;
    my ($sth) = $dbh->prepare_cached($sql_sa);
    $sth->execute();
    if ($sth->err) {
        eval {
            Baruwa::Scanner::Log::WarnLog(
                "ConfigSQL SpamAssassin statement error %s",
                $sth->errstr);
        };
        if ($@) {
            printf STDERR ("ConfigSQL SpamAssassin statement error %s\n",
                $sth->errstr);
        }
    } else {
        while ((my @row = $sth->fetchrow_array)) {
            chomp($row[0]);
            push(@text, $row[0]);
            printf STDERR "ConfigSQL SpamAssassin: %s\n", $row[0] if ($debug);
        }
        return join("\n", @text);
    }
    return undef;
}

sub CheckForUpdate {
    return undef if $disabled;

    $sql_sn = Baruwa::Scanner::Config::QuickPeek($ConfFile, 'SQLSerialNumber')
      if not(defined($sql_sn));
    if (!$sql_sn) {
        $disabled = 1;
        return undef;
    }

    if (time() > $serial_next) {
        my ($dbh) = db_connect($ConfFile) || return undef;
        my ($sth) = $dbh->prepare_cached($sql_sn);
        $sth->execute();
        if ($sth->err) {
            Baruwa::Scanner::Log::WarnLog(
                "ConfigSQL Serial statement returned error: %s",
                $sth->errstr);

            # Abort this update
            $serial_next = time() + $serial_min;
            return 0;
        } else {
            my ($new_serial) = $sth->fetchrow_array;
            if ($new_serial > $serial) {

                # Update detected
                Baruwa::Scanner::Log::InfoLog(
                    "ConfigSQL configuration update detected; restarting this child"
                );
                return 1;
            } else {

                # No update; calculate new retry time
                $serial_next = time() + $serial_min;
                Baruwa::Scanner::Log::InfoLog(
                    "ConfigSQL configuration update check; next time %d seconds",
                    ($serial_next - time())
                ) if $debug;
                return 0;
            }
        }
    } else {
        Baruwa::Scanner::Log::InfoLog(
            "ConfigSQL configuration update check time not reached; next check in %d seconds",
            ($serial_next - time())
        ) if $debug;
        return 0;
    }
    return 0;
}

1;
