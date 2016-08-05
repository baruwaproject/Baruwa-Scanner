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

package Baruwa::Scanner::Message;

use strict 'vars';
use strict 'refs';
no strict 'subs';    # Allow bare words for parameter %'s

use DirHandle;
use Time::localtime qw/ctime/;
use Time::HiRes qw/time/;
use MIME::Parser;
use MIME::Decoder::UU;
use MIME::Decoder::BinHex;
use MIME::WordDecoder;
use MIME::Base64 qw/decode_base64/;
use POSIX qw(:signal_h setsid);
use HTML::TokeParser;
use HTML::Parser;
use Archive::Zip qw( :ERROR_CODES );
use Filesys::Df;
use Digest::MD5;
use OLE::Storage_Lite;
use Fcntl;
use File::Path;
use File::Temp;
use File::Copy qw/move/;
use Baruwa::Scanner::TNEF();
use Baruwa::Scanner::FileInto();
use Baruwa::Scanner::EximDiskStore();

# Install an extra MIME decoder for badly-header uue messages.
install MIME::Decoder::UU 'uuencode';

# Install an extra MIME decoder for binhex-encoded attachments.
install MIME::Decoder::BinHex 'binhex', 'binhex40', 'mac-binhex40',
  'mac-binhex';

our $VERSION = '4.086000';

# Attributes are
#
# $id     set by new
# $store    set by new (is a EximDiskStore for now)
# #$hpath   set by new
# #$dpath   set by new
# $size     set by new (copy of $store->{size})
# $maxmessagesize set in SweepContent.pm, copied out of configuration
# #$inhhandle   set by new
# #$indhandle   set by new
# $from     set by ReadQf
# $fromdomain   set by new
# $fromuser   set by new
# @to     set by new
# @todomain   set by new
# @touser   set by new
# $subject    set by ReadQf
# @headers    set by ReadQf # just the headers, with /^H/ removed
#                       Note @headers is read-only!
# @metadata             set by ReadQf # the entire qf file excluding final "."
# $returnpathflags  set by ReadQf # Only used for sendmail at the moment
# $clientip   set by ReadQf
# $scanme   set by NeedsScanning (from MsgBatch constructor)
# $workarea   set by new
# @archiveplaces  set by new (addresses and dirs)
# @quarantineplaces set by Quarantine.pm
# $spamwhitelisted      set by IsSpam
# $spamblacklisted      set by IsSpam
# $isspam               set by IsSpam
# $issaspam             set by IsSpam
# $isrblspam            set by IsSpam
# $ishigh               set by IsSpam
# $sascore    set by IsSpam
# $spamreport           set by IsSpam
# $sarules    set by IsSpam (ref to hash of rulenames hit)
# $deleted    set by delivery functions
# $headerspath          set by WriterHeaderFile # file is read-only
# $cantparse    set by Explode
# $toomanyattach  set by Explode
# $cantdisinfect  set by ExplodeArchive
# $entity   set by Explode
# $tnefentity   set by Explode (only set if it's a TNEF message)
# $tnefname   set by Explode (contains the type indicator)
# $badtnef    set by Explode
# $entity   set by Explode
# %name2entity    set by Explode
# %file2parent    set by Explode (parent will have type indicator)
# $virusinfected  set by new and ScanBatch
# $nameinfected   set by new and ScanBatch
# JKF 19/12/2007 $passwordinfected  set by new and ScanBatch
# $otherinfected  set by new and ScanBatch
# $sizeinfected   set by new and ScanBatch
# %virusreports         set by TryCommercial (key is filename)
# %virustypes           set by TryCommercial (key is filename)
# %namereports    set by filename trap checker
# %nametypes    set by filename trap checker
# %otherreports   set by TryOther (key is filename)
# %othertypes   set by TryOther (key is filename)
# %entityreports        set by TryOther (key is entity)
# %oldviruses   set by DisinfectAndDeliver
# $infected             set by CombineReports
# %allreports   set by CombineReports
# %alltypes   set by CombineReports
# %entity2parent  set by CreateEntitiesHelpers
# %entity2file    set by CreateEntitiesHelpers
# %entity2safefile  set by CreateEntitiesHelpers
# %file2entity    set by CreateEntitiesHelpers (maps original evil names)
# %file2safefile  set by CreateEntitiesHelpers (evil==>safe)
# %safefile2file  set by CreateEntitiesHelpers (safe==>evil)
# $numberparts    set by CreateEntitiesHelpers
# $signed               set by Clean
# $bodymodified         set by Clean and SignUninfected
# $silent   set by FindSilentAndNoisyInfections
#       if infected with a silent virus
# $noisy    set by FindSilentAndNoisyInfections
#       if infected with a noisy virus
# $needsstripping       set by HandleSpam
# $stillwarn    set by new # Still send warnings even if deleted
# $needsencapsulating set by HandleSpam
# %postfixrecips  set by ReadQf in Postfix support only. Hash of all the
#       'R' addresses in the message to aid rebuilding.
# %originalrecips set by ReadQf in Postfix support only. Hash of all the
#       'O' addresses in the message to aid rebuilding.
# %deleteattach   set by ScanBatch and CheckFiletypeRules. True if
#                              attachment is to be deleted rather than stored.
# $tagstoconvert  set by ??? is list of HTML tags to dis-arm
# $gonefromdisk   set by calls to DeleteUnlock
# $subjectwasunsafe set by SweepContent.pm
# $safesubject    set by SweepContent.pm
# $salongreport   set by SA::Checks (longest version of SA report)
# @spamarchive          set by HandleHamAndSpam, list of places we have
#                              quarantined spam message. Used later to
#                              delete infected spam from spam quarantine.
# $dontdeliver          set by HandleHamAndSpam, true if the message was put
#                              in the spam archive, but still needs to be
#                              virus-scanned so we can remove it again if
#                              necessary. But it doesn't need repairing, as we
#                              won't be delivering it anyway.
# $datenumber   set by new
# $hournumber   set by new
# $datestring   set by new
# $messagedisarmed  set by DisarmHTMLTree
# @disarmedtags                All the HTML tags (incl. phishing) that we found
#                              and disarmed or highlighted.
# $quarantinedinfectionsset by QuarantineInfections, has this message already
#                              been quarantined, so doesn't need quarantining
#                              in QuarantineModifiedBodies.
# $actions    set by HandleHamAndSpam, saves action list.
# $ret                  set by new, true if BarricadeMX RET hash is valid
# $utf8subject    set by ReadQf, UTF8 rep'n of 'unsafe' subject, used by
#            MailWatch v2
# $mtime                set by ReadQf, mtime from stat of the message qfile
# $sigimagepresent  set by DisarmHTML, did we find a Baruwa signature image?
# $isreply        set by SignCleanMessage, did we find signs this is a reply
# $dkimfriendly   set by new if we are running DKIM-friendly.
# $newheadersattop  set by new if 'New Headers At Top' = yes at all.
# $archivesare    set by new, regexp showing what types are Archived.
# $spamvirusreport  set by virus checking, is comma-separated list of
#                   spam-virus names.
#

# Constructor.
# Takes id.
# Takes options $fake which is just used for making an object for
# the command-line testing.
# This isn't specific to the MTA at all, so is all done here.
sub new {
    my $type = shift;
    my ($id, $queuedirname, $getipfromheader, $fake) = @_;
    my $this = {};
    my ($mta, $addr, $user, $domain);
    my ($archiveplaces);

    # print STDERR "Creating message $id\n";

    $this->{id} = $id;
    @{$this->{archiveplaces}}    = ();
    @{$this->{spamarchive}}      = ();
    @{$this->{quarantineplaces}} = ();

    if ($fake) {
        bless $this, $type;
        $this->{store} = new Baruwa::Scanner::EximDiskStore($id, $queuedirname);
        return $this;
    }

    # Create somewhere to store the message
    $this->{store} = new Baruwa::Scanner::EximDiskStore($id, $queuedirname);

    # Try to open and exclusive-lock this message. Return undef if failed.
    # print STDERR "Trying to lock message " . $this->{id} . "\n";
    $this->{store}->Lock() or return undef;

    # print STDERR "Locked message\n";
    Baruwa::Scanner::Log::InfoLog("Locked message: %s", $this->{id});

    # getipfromheader used to be a yes or no option
    # It is now a number. yes = 1, no = 0.
    $getipfromheader = 1 if $getipfromheader =~ /y/i;
    $getipfromheader = 0 if $getipfromheader =~ /n/i || $getipfromheader eq "";
    Baruwa::Scanner::Log::WarnLog(
        "Illegal value for Read IP Address From Received Header, should be a number"
    ) unless $getipfromheader =~ /^\d+$/;

    # Now try to fill as much of the structure as possible
    $this->{size} = $this->{store}->size();
    if ($global::MS->{mta}->ReadQf($this, $getipfromheader) != 1) {
        bless $this, $type;
        $this->{INVALID} = 1;
        return $this;
    }

    #  or return 'INVALID'; # Return empty if fails

    # Work out the user @ domain components
    ($user, $domain) = address2userdomain($this->{from});
    $this->{fromuser}   = $user;
    $this->{fromdomain} = $domain;
    foreach $addr (@{$this->{to}}) {
        ($user, $domain) = address2userdomain($addr);
        push @{$this->{touser}},   $user;
        push @{$this->{todomain}}, $domain;
    }

    $this->{ret} = 0;

    #  my($header_line, $last_rcvd, $last_rcvd_ip);
    if ($this->{clientip} eq '127.0.0.1') {
        my ($header_line, $last_rcvd, $last_rcvd_ip);
        my ($rcvd_count) = 0;
        foreach $header_line (@{$this->{headers}}) {

            # print STDERR "DEBUG: Header line: $header_line\n";
            if ($header_line =~ /ret-id/ && $rcvd_count == 2) {
                $this->{clientip} = $last_rcvd_ip if ($last_rcvd_ip);

                # print STDERR "DEBUG: Using received header $rcvd_count - IP: $last_rcvd_ip\n";
                $this->{ret} = 1 if ($header_line =~ /ret-id pass/i);
                last;
            }
            if ($header_line =~ /Received:/) {
                $rcvd_count++;
                $last_rcvd = $header_line;

                #my($rcvd_ip) = $last_rcvd =~ /\(.*\[(.+)\]\)/;
                my ($rcvd_ip) = $last_rcvd =~ /\(.*\[(.+)\].*\)|\[(.+)\]/;

                # print STDERR "DEBUG: $last_rcvd - IP: $rcvd_ip\n";
                $rcvd_ip = $2 unless $rcvd_ip;
                $last_rcvd_ip = $rcvd_ip;
                last if $rcvd_count > 2;
            }
        }
    }

    $this->{mshmacnullvalid} = 1;
    $this->{mshmacskipvalid} = 0;
    my $usewatermark =
      (Baruwa::Scanner::Config::Value('usewatermarking', $this) =~ /1/) ? 1 : 0;
    my $mshmackey = Baruwa::Scanner::Config::Value('mshmac', $this);
    if (($usewatermark) && (length $mshmackey)) {

        #print STDERR "You are using the Watermark blocking\n";
        my ($subject, $date, $from, $to, $useragent, $hash, $msgid);
        my ($chkmshmacnull, $addmshmac, $chkmshmacskip, $mshamcexp,
            $header_line,   $skiphmac,  @WholeBody
        );
        $this->{addmshmac} = 0;
        $this->{mshmac}    = "";
        $chkmshmacnull = Baruwa::Scanner::Config::Value('checkmshmac', $this);
        $chkmshmacskip =
          Baruwa::Scanner::Config::Value('checkmshmacskip', $this);
        $addmshmac = Baruwa::Scanner::Config::Value('addmshmac',   $this);
        $mshamcexp = Baruwa::Scanner::Config::Value('mshmacvalid', $this);
        $chkmshmacnull = ($chkmshmacnull =~ /1/) ? 1 : 0;
        $chkmshmacskip = ($chkmshmacskip =~ /1/) ? 1 : 0;
        $addmshmac     = ($addmshmac =~ /1/)     ? 1 : 0;
        my $mshmacheader =
          Baruwa::Scanner::Config::Value('mshmacheader', $this);
        $mshmacheader .= ':' unless $mshmacheader =~ /:$/;

       # So do we need to look for a header in the message body?
       # Don't check if there was no client IP address, as we must have made it.
        if (   $chkmshmacnull
            && $this->{fromuser} eq ""
            && $this->{clientip} ne '0.0.0.0') {

            #print STDERR "\tI am checking for a valid Watermark\n";
            $this->{store}->ReadBody(\@WholeBody, 6000);
            foreach (@WholeBody) {
                $date  = Date::Parse::str2time($1) if /^Date: (.*)/i;
                $msgid = $1                        if /^Message-ID: (.*)/i;
                $hash  = $1                        if /^$mshmacheader (.*)/i;

                # If we have our headers then end
                last if defined($date) && defined($hash) && defined($msgid);

                # If we have some our headers and a blank line then end
                last
                  if $_ eq ''
                  && (defined($date) || defined($hash) || defined($msgid));
            }
            undef(@WholeBody);
            if (!defined($hash)) {

                #print STDERR "\tNo hash found\n";
                $this->{mshmacnullvalid}   = 0;
                $this->{mshmacnullpresent} = 1;
            } else {
                $this->{mshmacnullpresent} = 1;
                $this->{mshmacnullvalid} =
                  checkHMAC($hash,
                    $this->{touser}[0] . "\@" . $this->{todomain}[0],
                    $date, $mshmackey, $msgid);
            }
        }

        # Now check to see if we need to add a header
        if ($chkmshmacskip) {
            my @hashes;
            foreach (@{$this->{headers}}) {
                $date = Date::Parse::str2time($1) if /^Date: (.*)/i;
                $msgid = $1 if /^Message-ID: (.*)/i;
                push(@hashes, $1) if /^$mshmacheader (.*)/i;
            }

            #print STDERR "I got $hash\n";
            if ($chkmshmacskip) {
                foreach (@hashes) {
                    if (checkHMAC(
                            $_, $this->{fromuser} . "\@" . $this->{fromdomain},
                            $date, $mshmackey, $msgid
                        )
                      ) {
                        $this->{mshmacskipvalid} = 1;
                        last;
                    }
                }
            }
        }
        if ($addmshmac) {
            my $expiry = time() + $mshamcexp;
            $hash =
              createHMAC($expiry,
                $this->{fromuser} . "\@" . $this->{fromdomain},
                $date, $mshmackey, $msgid);

      #$global::MS->{mta}->AppendHeader($this, $mshmacheader, "$expiry\@$hash");
            $this->{addmshmac} = 1;
            $this->{mshmac}    = "$expiry\@$hash";
        }
    }

    # Reset the infection counters to 0
    $this->{virusinfected} = 0;
    $this->{nameinfected}  = 0;
    $this->{otherinfected} = 0;
    $this->{sizeinfected}  = 0;

    # JKF 19/12/2007 $this->{passwordinfected} = 0;
    $this->{stillwarn} = 0;

    # Set the date string and number
    $this->{datestring} = scalar localtime;
    my ($hour, $day, $month, $year, $date);
    ($hour, $day, $month, $year) = (localtime)[2, 3, 4, 5];
    $date = sprintf("%04d%02d%02d", $year + 1900, $month + 1, $day);
    $this->{datenumber} = $date;
    $this->{hournumber} = sprintf("%02d", $hour);

    # Work out where to archive/copy this message.
    # Could do all the archiving in a different separate place.
    $archiveplaces = Baruwa::Scanner::Config::Value('archivemail', $this);
    if ($archiveplaces =~ /_DATE_/) {

        # Only do the work for the date substitution if we really have to
        $archiveplaces =~ s/_DATE_/$date/g;

        #print STDERR "Archive location is $archiveplaces\n";
    }
    $archiveplaces =~ s/_HOUR_/$hour/g;
    @{$this->{archiveplaces}} =
      ((defined $archiveplaces) ? split(" ", $archiveplaces) : ());

    # Decide if we want to scan this message at all
    $this->{scanmail} = Baruwa::Scanner::Config::Value('scanmail', $this);
    if ($this->{scanmail} =~ /[12]/) {
        $this->{scanmail} = 1;
    } else {

        # Make sure it is set to something, and not left as undef.
        $this->{scanmail} = 0;
    }
    if ($this->{scanmail} !~ /1/) {
        $this->{scanvirusonly} = 1;
    } else {
        $this->{scanvirusonly} = 0;
    }

    # Are we running in DKIM-friendly mode?
    # Require Multiple Headers = add
    # and Add New Headers At Top = yes
    my $multhead = Baruwa::Scanner::Config::Value('multipleheaders', $this);
    my $attop    = Baruwa::Scanner::Config::Value('newheadersattop', $this);
    $this->{dkimfriendly} = ($multhead =~ /add/ && $attop =~ /1/) ? 1 : 0;
    $this->{newheadersattop} = 1 if $attop =~ /1/;

    # Work out what types of file are archives
    my $ArchivesAre = Baruwa::Scanner::Config::Value('archivesare', $this);
    my @ArchivesAre = split " ", $ArchivesAre;

    # Reduce each word to the first letter
    @ArchivesAre = map {substr($_, 0, 1)} @ArchivesAre;
    $ArchivesAre = join '', @ArchivesAre;

    # And turn the first letters into a regexp
    $ArchivesAre = '[' . $ArchivesAre . ']' if $ArchivesAre;
    $this->{archivesare} = $ArchivesAre;

    bless $this, $type;
    return $this;
}

sub checkHMAC {

    my ($hash, $email, $date, $secret, $msgid) = @_;

    my ($expiry, $newhash) = split(/\@/, $hash);
    return 0 if ($expiry < time());

#print STDERR "I am checking $hash using input of: $email, $date, $secret, $msgid\n";

    $hash = createHMAC($expiry, $email, $date, $secret, $msgid);
    return 0 unless ($hash eq $newhash);

    return 1;
}

sub createHMAC {
    my ($expiry, $email, $date, $secret, $msgid) = @_;
    return Digest::MD5::md5_base64(
        join("\$\%", $expiry, $date, $secret, $msgid));
}

# Delete a named attachment (filename supplied) from this message
sub DeleteFile {
    my $this     = shift;
    my $safefile = shift;

    #print STDERR "Been asked to delete $safefile\n";
    $global::MS->{work}->DeleteFile($this, $safefile);
}

# Take an email address. Return (user, domain).
sub address2userdomain {
    my ($addr) = @_;

    my ($user, $domain);

    $addr = lc($addr);
    $addr =~ s/^<\s*//;    # Delete leading and
    $addr =~ s/\s*>$//;    # trailing <>

    $user   = $addr;
    $domain = $addr;

    if ($addr =~ /@/) {
        $user =~ s/@[^@]*$//;
        $domain =~ s/^[^@]*@//;
    }

    return ($user, $domain);
}

# Print a message
sub print {
    my $this = shift;

    print STDERR "Message " . $this->{id} . "\n";
    print STDERR "  Size = " . $this->{size} . "\n";
    print STDERR "  From = " . $this->{from} . "\n";
    print STDERR "  To   = " . join(',', @{$this->{to}}) . "\n";
    print STDERR "  Subj = " . $this->{subject} . "\n";
}

# Get/Set "scanme" flag
sub NeedsScanning {
    my ($this, $value) = @_;

    $this->{scanme} = $value if @_ > 1;
    return $this->{scanme};
}

# Write the file containing all the message headers.
# Called by the MessageBatch constructor.
# Notes: assumes the directories required already exist.
sub WriteHeaderFile {
    my $this = shift;

    #my @headers;
    my $header   = new FileHandle;
    my $filename = $global::MS->{work}->{dir} . '/' . $this->{id} . '.header';
    $this->{headerspath} = $filename;

    Baruwa::Scanner::Lock::openlock($header, ">$filename", "w")
      or
      Baruwa::Scanner::Log::DieLog("Cannot create + lock headers file %s, %s",
        $filename, $!);

    #@headers = $global::MS->{mta}->OriginalMsgHeaders($this);
    #print STDERR "Headers are " . join(', ', @headers) . "\n";
    #foreach (@headers) {
    foreach ($global::MS->{mta}->OriginalMsgHeaders($this)) {
        tr/\r/\n/
          ;    # Work around Outlook [Express] bug allowing viruses in headers
        print $header "$_\n";
    }
    print $header "\n";
    Baruwa::Scanner::Lock::unlockclose($header);

    # Set the owner of the header file
    $filename =~ /^(.*)$/;
    $filename = $1;
    chown $global::MS->{work}->{uid}, $global::MS->{work}->{gid}, $filename
      if $global::MS->{work}->{changeowner};
}

# Is this message spam? Try to build the spam report and store it in
# the message.
sub IsSpam {
    my $this = shift;
    my ($includesaheader, $iswhitelisted, $usegsscanner, $mshmacreport);

    my $spamheader    = "";
    my $rblspamheader = "";
    my $gsreport      = "";
    my $saspamheader  = "";
    my $RBLsaysspam   = 0;
    my $rblcounter    = 0;
    my $LogSpam       = Baruwa::Scanner::Config::Value('logspam');
    my $LogNonSpam    = Baruwa::Scanner::Config::Value('lognonspam');
    my $LocalSpamText = Baruwa::Scanner::Config::LanguageValue($this, 'spam');
    my $LocalNotSpamText =
      Baruwa::Scanner::Config::LanguageValue($this, 'notspam');

    #print STDERR "MTime{" . $this->{id} . "} = " . $this->{mtime} . "\n";

    # Construct a pretty list of all the unique domain names for logging
    my (%todomain, $todomain);
    foreach $todomain (@{$this->{todomain}}) {
        $todomain{$todomain} = 1;
    }
    $todomain = join(',', keys %todomain);
    my $recipientcount = @{$this->{to}};

    # $spamwhitelisted      set by IsSpam
    # $spamblacklisted      set by IsSpam
    # $isspam               set by IsSpam
    # $ishigh               set by IsSpam
    # $spamreport           set by IsSpam

    $this->{spamwhitelisted} = 0;
    $this->{spamblacklisted} = 0;
    $this->{isspam}          = 0;
    $this->{ishigh}          = 0;
    $this->{spamreport}      = "";
    $this->{sascore}         = 0;

    # Work out if they always want the SA header
    $includesaheader =
      Baruwa::Scanner::Config::Value('includespamheader', $this);

    # If they want the GS scanner then we must carry on too
    $usegsscanner = Baruwa::Scanner::Config::Value('gsscanner', $this);

    # Do the whitelist check before the blacklist check.
    # If anyone whitelists it, then everyone gets the message.
    # If no-one has whitelisted it, then consider the blacklist.
    $iswhitelisted = 0;
    my $maxrecips = Baruwa::Scanner::Config::Value('whitelistmaxrecips');
    $maxrecips = 999999 unless $maxrecips;

    # BarricadeMX mods
    # Skip SpamAssassin if a valid RET hash is found ($this->{ret} == true)
    if ($this->{ret}) {
        Baruwa::Scanner::Log::InfoLog(
            "Valid RET hash found in Message %s, skipping Spam Checks",
            $this->{id});
        return 0;
    }

    # Skip Spam Checks if Watermark is valid
    if ($this->{mshmacskipvalid}) {
        Baruwa::Scanner::Log::InfoLog(
            "Valid Watermark HASH found in Message %s Header, skipping Spam Checks",
            $this->{id}
        );
        return 0;
    }

    if ($this->{mshmacnullpresent} && $this->{mshmacnullvalid}) {
        Baruwa::Scanner::Log::InfoLog("Message %s from %s has valid watermark",
            $this->{id}, $this->{clientip});
    } elsif ($this->{mshmacnullpresent} && $this->{mshmacnullvalid} == 0) {

        # If the sender is empty then treat unmarked messages as spam perhaps?
        my $mshmacnull =
          lc(Baruwa::Scanner::Config::Value('mshmacnull', $this));

        #print STDERR "mshmacnull = $mshmacnull\n";
        # This can be "none", "spam" or "high-scoring spam"
        #$mshmacnull =~ s/[^a-z]//g;
        if ($mshmacnull =~ /delete/) {
            $this->{deleted}     = 1;
            $this->{dontdeliver} = 1;
            Baruwa::Scanner::Log::InfoLog(
                "Message %s from %s has no (or invalid) watermark or sender address, deleted",
                $this->{id}, $this->{clientip}
            ) if $LogSpam;
        } elsif ($mshmacnull =~ /high/) {
            my $highscore =
              Baruwa::Scanner::Config::Value('highspamassassinscore', $this);
            $this->{isspam}  = 1;
            $this->{ishigh}  = 1;
            $this->{sascore} = $highscore if $this->{sascore} < $highscore;
            $this->{spamreport} =
              $LocalSpamText . "(no watermark or sender address)";
            Baruwa::Scanner::Log::InfoLog(
                "Message %s from %s has no (or invalid) watermark or sender address, marked as high-scoring spam",
                $this->{id}, $this->{clientip}
            ) if $LogSpam;
            return 1;
        } elsif ($mshmacnull =~ /spam/) {
            my $reqscore =
              Baruwa::Scanner::Config::Value('reqspamassassinscore', $this);
            $this->{isspam} = 1;
            $this->{sascore} = $reqscore if $this->{sascore} < $reqscore;
            $this->{spamreport} =
              $LocalSpamText . "(no watermark or sender address)";
            Baruwa::Scanner::Log::InfoLog(
                "Message %s from %s has no (or invalid) watermark or sender address, marked as spam",
                $this->{id}, $this->{clientip}
            ) if $LogSpam;
            return 1;
        }

       # spam/high/normal can also be a number, which is added to the Spam Score
        elsif (($mshmacnull + 0.0) > 0.01) {
            $this->{sascore} += $mshmacnull + 0.0;
            Baruwa::Scanner::Log::InfoLog(
                "Message %s had bad watermark, added %s to spam score",
                $this->{id}, $mshmacnull + 0.0)
              if $LogSpam;
            my ($mshspam, $mshhigh) =
              Baruwa::Scanner::SA::SATest_spam($this, 0.0,
                $this->{sascore} + 0.0);
            $this->{isspam} = 1 if $mshspam;
            $this->{ishigh} = 1 if $mshhigh;
            $this->{spamreport} =
              ($mshspam ? $LocalSpamText : $LocalNotSpamText)
              . " (no watermark or sender address)";
            $mshmacreport = " (no watermark or sender address)";
        } elsif ($this->{mshmacnullpresent}) {
            Baruwa::Scanner::Log::InfoLog(
                "Message %s from %s has no (or invalid) watermark or sender address",
                $this->{id}, $this->{clientip}
            );
        }
    }

    # Only allow whitelisting if there are few enough recipients.
    if ($recipientcount <= $maxrecips) {
        if (Baruwa::Scanner::Config::Value('spamwhitelist', $this)) {

            # Whitelisted, so get out unless they want SA header
            #print STDERR "Message is whitelisted\n";
            Baruwa::Scanner::Log::InfoLog(
                "Message %s from %s (%s) is whitelisted",
                $this->{id}, $this->{clientip}, $this->{from})
              if $LogSpam || $LogNonSpam;
            $iswhitelisted = 1;
            $this->{spamwhitelisted} = 1;

            # whitelisted and doesn't want SA header so get out
            return 0 unless $includesaheader || $usegsscanner;
        }
    } else {

        # Had too many recipients, ignoring the whitelist
        Baruwa::Scanner::Log::InfoLog(
            "Message %s from %s (%s) ignored whitelist, "
              . "had %d recipients (>%d)",
            $this->{id},     $this->{clientip}, $this->{from},
            $recipientcount, $maxrecips
        ) if $LogSpam || $LogNonSpam;
    }

    # If it's a blacklisted address, don't bother doing any checks at all
    if (!$iswhitelisted
        && Baruwa::Scanner::Config::Value('spamblacklist', $this)) {
        $this->{spamblacklisted} = 1;
        $this->{isspam}          = 1;
        $this->{ishigh}          = 1
          if Baruwa::Scanner::Config::Value('blacklistedishigh', $this);
        $this->{spamreport} = $LocalSpamText . ' ('
          . Baruwa::Scanner::Config::LanguageValue($this, 'blacklisted') . ')';
        Baruwa::Scanner::Log::InfoLog(
            "Message %s from %s (%s) to %s" . " is spam (blacklisted)",
            $this->{id}, $this->{clientip}, $this->{from}, $todomain)
          if $LogSpam;
        return 1;
    }

    my $whitelistreport = '';
    if ($iswhitelisted) {
        $whitelistreport = ' ('
          . Baruwa::Scanner::Config::LanguageValue($this, 'whitelisted') . ')';
    }

    #
    # Check to see if message is too large to be likely to be spam.
    #
    my $maxtestsize = Baruwa::Scanner::Config::Value('maxspamchecksize', $this);
    if ($this->{size} > $maxtestsize) {
        $this->{spamreport} =
          Baruwa::Scanner::Config::LanguageValue($this, 'skippedastoobig');
        $this->{spamreport} = $this->ReflowHeader(
            Baruwa::Scanner::Config::Value('spamheader', $this),
            $this->{spamreport});
        Baruwa::Scanner::Log::InfoLog(
            "Message %s from %s (%s) to %s is too big for spam checks (%d > %d bytes)",
            $this->{id}, $this->{clientip}, $this->{from},
            $todomain,   $this->{size},     $maxtestsize
        );
        return 0;
    }

    if (!$iswhitelisted) {

        # Not whitelisted, so do the RBL checks
        $0 = 'Baruwa: checking with Spam Lists';
        ($rblcounter, $rblspamheader) = Baruwa::Scanner::RBLs::Checks($this);
        my $rblthreshold = Baruwa::Scanner::Config::Value('normalrbls', $this);
        my $highrblthreshold =
          Baruwa::Scanner::Config::Value('highrbls', $this);
        $rblthreshold     = 1 if $rblthreshold <= 1;
        $highrblthreshold = 1 if $highrblthreshold <= 1;
        $RBLsaysspam      = 1 if $rblcounter >= $rblthreshold;

        # Add leading "spam, " if RBL says it is spam. This will be at the
        # front of the spam report.
        $this->{isspam}    = 1 if $RBLsaysspam;
        $this->{isrblspam} = 1 if $RBLsaysspam;
        $this->{ishigh}    = 1 if $rblcounter >= $highrblthreshold;
    }

    # rblspamheader is useful start to spamreport if RBLsaysspam.

    # Do the Custom Spam Checker
    my ($gsscore);

    #print STDERR "In Message.pm about to look at gsscanner\n";
    if ($usegsscanner) {

        #print STDERR "In Message.pm about to run gsscanner\n";
        ($gsscore, $gsreport) = Baruwa::Scanner::GenericSpam::Checks($this);

        #print STDERR "In Message.pm we got $gsscore, $gsreport\n";
        $this->{gshits}   = $gsscore;
        $this->{gsreport} = $gsreport;
        $this->{sascore} += $gsscore;    # Add the score
        Baruwa::Scanner::Log::InfoLog(
            "Custom Spam Scanner for message %s from %s "
              . "(%s) to %s report is %s %s",
            $this->{id}, $this->{clientip},
            $this->{from}, $todomain, $gsscore, $gsreport)
          if $LogSpam && ($gsscore != 0 || $gsreport ne "");
    }

    # Don't do the SA checks if they have said no.
    unless (Baruwa::Scanner::Config::Value('usespamassassin', $this)) {
        $this->{spamwhitelisted} = $iswhitelisted;
        $this->{isspam}          = 1
          if $this->{sascore} + 0.0 >=
          Baruwa::Scanner::Config::Value('reqspamassassinscore', $this) + 0.0;
        $this->{ishigh} = 1
          if $this->{sascore} + 0.0 >=
          Baruwa::Scanner::Config::Value('highspamassassinscore', $this) + 0.0;
        Baruwa::Scanner::Log::InfoLog("Message %s from %s (%s) to %s is %s",
            $this->{id}, $this->{clientip},
            $this->{from}, $todomain, $rblspamheader)
          if $RBLsaysspam && $LogSpam;

        # Replace start of report if it wasn't spam from rbl but now is.
        $this->{spamreport} =
          ($this->{isspam}) ? $LocalSpamText : $LocalNotSpamText;
        $this->{spamreport} .= $mshmacreport;
        $this->{spamreport} .= $whitelistreport;
        $this->{spamreport} .= ', ' if $this->{spamreport};
        $this->{spamreport} .= $rblspamheader if $rblspamheader;
        $this->{spamreport} .= ', ' if $this->{spamreport} && $rblspamheader;
        $this->{spamreport} .= $gsscore + 0.0 if $gsscore != 0;
        $this->{spamreport} .= ', ' if $this->{spamreport} && $gsscore != 0;
        $this->{spamreport} .= $gsreport if $gsreport ne "";
        $this->{spamreport} = $this->ReflowHeader(
            Baruwa::Scanner::Config::Value('spamheader', $this),
            $this->{spamreport});
        return $this->{isspam};
    }

    # If it's spam and they dont want to check SA as well
    if ($this->{isspam}
        && !Baruwa::Scanner::Config::Value('checksaifonspamlist', $this)) {
        $this->{spamwhitelisted} = $iswhitelisted;
        Baruwa::Scanner::Log::InfoLog("Message %s from %s (%s) to %s is %s",
            $this->{id}, $this->{clientip},
            $this->{from}, $todomain, $rblspamheader)
          if $RBLsaysspam && $LogSpam;

        # Replace start of report if it wasn't spam from rbl but now is.
        $this->{spamreport} =
          ($this->{isspam}) ? $LocalSpamText : $LocalNotSpamText;
        $this->{spamreport} .= $mshmacreport;
        $this->{spamreport} .= $whitelistreport;
        $this->{spamreport} .= ', ' if $this->{spamreport};
        $this->{spamreport} .= $rblspamheader if $rblspamheader;
        $this->{spamreport} .= ', ' if $this->{spamreport} && $rblspamheader;
        $this->{spamreport} .= $gsscore + 0.0 if $gsscore != 0;
        $this->{spamreport} .= ', ' if $this->{spamreport} && $gsscore != 0;
        $this->{spamreport} .= $gsreport if $gsreport ne "";
        $this->{spamreport} = $this->ReflowHeader(
            Baruwa::Scanner::Config::Value('spamheader', $this),
            $this->{spamreport});
        return $RBLsaysspam;
    }

    # They must want the SA checks doing.

    my $SAsaysspam    = 0;
    my $SAHighScoring = 0;
    my $saheader      = "";
    my $sascore       = 0;
    my $salongreport  = "";
    $0 = 'Baruwa: checking with SpamAssassin';
    ($SAsaysspam, $SAHighScoring, $saheader, $sascore, $salongreport) =
      Baruwa::Scanner::SA::Checks($this);

    # Cannot trust the SAsaysspam and SAHighScoring from the previous test as
    # they depend solely on what SpamAssassin finds, and not what the Watermark
    # and GS scanner found previously, the scores for which are already in
    # $this->{sascore}. So recalculate the SAsaysspam and SAHighScoring based
    # on *all* the evidence we have so far.
    ($SAsaysspam, $SAHighScoring) = Baruwa::Scanner::SA::SATest_spam(
        $this,
        $this->{sascore} + 0.0,
        $sascore + 0.0
    );
    $this->{sascore} += $sascore;    # Save the actual figure for use later...
         # Trim all the leading rubbish off the long SA report and turn it back
         # into a multi-line string, then store it in the message properties.
    $salongreport =~ s/^.* pts rule name/ pts rule name/;
    $salongreport =~ tr/\0/\n/;
    $this->{salongreport} = $salongreport;

    #print STDERR $salongreport . "\n";

    # Fix the return values
    $SAsaysspam = 0 unless $saheader;    # Solve bug with empty SAreports
    $saheader =~ s/\s+$//g if $saheader; # Solve bug with trailing space

    # Build the hash containing all the rules hit as keys, values are 1
    # $saheader looks like this: score=11.12, required 6, DATE_IN_PAST_12_24 1.77, INVALID_DATE 1.65, INVALID_MSGID 2.60, RCVD_IN_NJABL_SPAM 3.10, SPF_HELO_NEUTRAL 2.00
    my (@hitslist, %names);
    @hitslist = split(/\s*,\s*/, $saheader);
    shift @hitslist;    # Remove total score
    shift @hitslist;    # Remove required score
    foreach (@hitslist) {
        $names{lc($1)} = 1 if /^\s*(\S+)\s+/;
    }
    $this->{sarules} = \%names;

    #print STDERR "SA report is \"$saheader\"\n";
    #print STDERR "SAsaysspam = $SAsaysspam\n";
    $saheader =
      Baruwa::Scanner::Config::LanguageValue($this, 'spamassassin')
      . " ($saheader)"
      if $saheader;

    # The message really is spam if SA says so (unless it's been whitelisted)
    unless ($iswhitelisted) {
        $this->{isspam} |= $SAsaysspam;
        $this->{issaspam} = $SAsaysspam;
    }

    # If it's spam...
    if ($this->{isspam}) {
        $this->{ishigh} = 1 if $SAHighScoring;
        $this->{spamreport} =
          ($this->{isspam}) ? $LocalSpamText : $LocalNotSpamText;
        $this->{spamreport} .= $mshmacreport;
        $this->{spamreport} .= $whitelistreport;
        $this->{spamreport} .= ', ' if $this->{spamreport};
        $this->{spamreport} .= $rblspamheader if $rblspamheader;
        $this->{spamreport} .= ', ' if $this->{spamreport} && $rblspamheader;
        $this->{spamreport} .= $gsscore + 0.0 if $gsscore != 0;
        $this->{spamreport} .= ', ' if $this->{spamreport} && $gsscore != 0;
        $this->{spamreport} .= $gsreport if $gsreport ne "";

        if ($SAsaysspam || $includesaheader) {
            $this->{spamreport} .= ', ' if $this->{spamreport} && $gsreport;
            $this->{spamreport} .= $saheader if $saheader ne "";
        }
    } else {

        # It's not spam...
        #print STDERR "It's not spam\n";
        #print STDERR "SAHeader = $saheader\n";
        $this->{spamreport} =
          ($this->{isspam}) ? $LocalSpamText : $LocalNotSpamText;
        $this->{spamreport} .= $mshmacreport;
        $this->{spamreport} .= $whitelistreport;
        $this->{spamreport} .= ', ' if $this->{spamreport};
        $this->{spamreport} .= $rblspamheader if $rblspamheader;
        $this->{spamreport} .= ', ' if $this->{spamreport} && $rblspamheader;
        $this->{spamreport} .= $gsscore + 0.0 if $gsscore != 0;
        $this->{spamreport} .= ', ' if $this->{spamreport} && $gsscore != 0;
        $this->{spamreport} .= $gsreport if $gsreport ne "";
        $this->{spamreport} .= ', ' if $this->{spamreport} && $gsreport;
        $this->{spamreport} .= $saheader if $saheader ne "";
    }

    # Do the spam logging here so we can log high-scoring spam too
    if (($LogSpam && $this->{isspam}) || ($LogNonSpam && !$this->{isspam})) {
        my $ReportText = $this->{spamreport};
        $ReportText =~ s/\s+/ /sg;
        Baruwa::Scanner::Log::InfoLog("Message %s from %s (%s) to %s is %s",
            $this->{id}, $this->{clientip},
            $this->{from}, $todomain, $ReportText);
    }

    # Now just reflow and log the results
    if ($this->{spamreport} ne "") {
        $this->{spamreport} = $this->ReflowHeader(
            Baruwa::Scanner::Config::Value('spamheader', $this),
            $this->{spamreport});
    }

    return $this->{isspam};
}

# Do whatever is necessary with this message to deal with spam.
# We can assume the message passed is indeed spam (isspam==true).
# Call it with either 'spam' or 'nonspam'. Don't use 'ham'!
sub HandleHamAndSpam {
    my ($this, $HamSpam) = @_;

    my ($actions, $action, @actions, %actions);
    my (@extraheaders, $actionscopy, $actionkey);

    # Set default action for DMX/MailWatch reporting
    $this->{actions} = 'deliver';

    # Get a space-separated list of all the actions
    if ($HamSpam eq 'nonspam') {

        #print STDERR "Looking up hamactions\n";
        $actions = Baruwa::Scanner::Config::Value('hamactions', $this);

        # Fast bail-out if it's just the simple "deliver" case that 99% of
        # people will use
        # Can't do this with SA rule actions: return if $actions eq 'deliver';
    } else {

        # It must be spam as it's not ham
        if ($this->{ishigh}) {

            #print STDERR "Looking up highscorespamactions\n";
            $actions =
              Baruwa::Scanner::Config::Value('highscorespamactions', $this);
        } else {

            #print STDERR "Looking up spamactions\n";
            $actions = Baruwa::Scanner::Config::Value('spamactions', $this);
        }
    }

    # Find all the bits in quotes, with their spaces
    $actionscopy = $actions;

    #print STDERR "Actions = \'$actions\'\n";
    while ($actions =~ s/\"([^\"]+)\"//) {
        $actionkey = $1;

        #print STDERR "ActionKey = $actionkey and $1\n";
        push @extraheaders, $actionkey;
        Baruwa::Scanner::Log::WarnLog(
            "Syntax error in \"header\" action in spam "
              . "actions, missing \":\" in %s",
            $actionkey
        ) unless $actionkey =~ /:/;
    }
    @{$this->{extraspamheaders}} = @extraheaders;

    #$actions = lc($actions);
    $actions =~ s/^\s*//;
    $actions =~ s/\s*$//;
    $actions =~ s/\s+/ /g;

    #print STDERR "Actions after = \'$actions\'\n";
    #print STDERR "Extra headers are \"" . join(',',@extraheaders) . "\"\n";

    Baruwa::Scanner::Log::WarnLog('Syntax error: missing " in spam actions %s',
        $actionscopy)
      if $actions =~ /\"/;

    $actions =~ tr/,//d;    # Remove all commas in case they put any in
    @actions = split(" ", $actions);

    #print STDERR "Actions are $actions\n";

    # The default action if they haven't specified anything is to
    # deliver spam like normal mail.
    # Can't do this with SA rule actions: return unless @actions;

    # If they have just specified a filename, then something is wrong
    if ($#actions == 0 && $actions[0] =~ /\// && $actions[0] !~ /^store-\//) {
        Baruwa::Scanner::Log::WarnLog(
            'Your spam actions "%s" looks like a filename.'
              . ' If this is a ruleset filename, it must end in .rule or .rules',
            $actions[0]
        );
        $actions[0] = 'deliver';
    }

    # Save actions for DMX/MailWatch reporting
    $this->{actions} = join(',', @actions);

    my (%lintoptions, $custom);
    foreach $action (@actions) {

        # Allow for store-nonspam, etc.
        #$action =~ s/^store\W(\w+).*$/store-$1/;
        if ($action =~ /^custom\((.*)\)/) {
            Baruwa::Scanner::Config::CallCustomAction($this, 'yes', $1);
            $action = 'custom';
        }

        $lintoptions{$action} = 1 unless $action =~ /-\//;

        $actions{$action} = 1;

        #print STDERR "Message: HandleSpam action is $action\n";
        if ($action =~ /\@/) {

            #print STDERR "Message " . $this->{id} . " : HandleSpam() adding " .
            #             "$action to archiveplaces\n";
            push @{$this->{archiveplaces}}, $action;
            $actions{'forward'} = 1;
            delete $lintoptions{$action};   # Can't syntax-check email addresses
        }
        if ($action =~ /-\//) {
            delete $lintoptions{$action};    # Can't syntax-check dir paths
        }
    }

    #############################################
    ### SpamAssassin Rule Actions starts here ###
    #############################################
    my $sarule       = Baruwa::Scanner::Config::Value('saactions',    $this);
    my $logsaactions = Baruwa::Scanner::Config::Value('logsaactions', $this);
    if ($sarule) {

        #print STDERR "SArule = $sarule\n";
        $logsaactions = 1 if $logsaactions =~ /1/;
        my @sarule = split /\s*,\s*/, $sarule;
        my %sarule = ();
        my @sascorerules;    # List of extra rules of the spamscore>10 variety
        my $lastrule = "";   # Allows multiple actions per rule name
        my $thisaction;      # Just for debug output
            # Loop through each x=>y in the saactions config setting
        foreach my $rule (@sarule) {

            if ($rule =~ /^(\S+)\s*=\>\s*(.*)$/) {

                # It's a new RULE=>action
                $sarule{lc($1)} .= "\0$2";
                $lastrule   = $1;
                $thisaction = $2;

                #print STDERR "Added rule $1 ==> action $2\n";
            } else {

                # No '=>', it's just an action,
                # so make the RULE a copy of the previous one.
                $sarule{lc($lastrule)} .= "\0$rule";
                $thisaction = $rule;

                #print STDERR "(Added rule $lastrule ==> action $rule)\n";
            }

            #print STDERR "Breaking up sarule into $lastrule => $thisaction\n";

            # Look for SpamScore>n and other tests
            my $rulename = lc($1);    # This will look like spamscore>10
            if ($rulename =~ /^spamscore\s*(\>|\>=|==|\<=|\<)\s*([0-9.]+)/) {
                my ($test, $threshold) = ($1, $2);
                my $spamscore = $this->{sascore} + 0.0;    # Be wary of Perl bug
                my $result    = 0;

                #print STDERR 'Evaling $result=1 if ' . $spamscore . $test .
                #             $threshold . ';' . "\n";
                eval '$result=1 if ' . $spamscore . $test . $threshold . ';';

                #print STDERR "  Result was $result\n";
                push @sascorerules, $rulename
                  if $result;    # These rules are all hits
            }
        }

        # Loop through each SA rule we hit with this message
        foreach my $looprule ((keys %{$this->{sarules}}), @sascorerules) {

            # Bail out if we're not interested in this rule
            #print STDERR "*Looking for sarule $looprule\n";
            foreach $action (split(/\0+/, $sarule{$looprule})) {

                #my $action = $sarule{$looprule};
                $action =~ s/^\s+//;
                $action =~ s/\s+$//;
                next unless $action;

                #print STDERR "*sarule $looprule gave action $action\n";
                Baruwa::Scanner::Log::InfoLog(
                    "SpamAssassin Rule Actions: rule %s caused action %s in message %s",
                    $looprule, $action, $this->{id})
                  if $logsaactions;
                if ($action !~ /^notify/ && $action =~ s/^no\w?\W*//)
                {    # Anything started no, not not, etc.
                        #
                        # It's a NOT action so remove the action
                        #
                        #print STDERR "It's a NOT action $action\n";
                    $action =~ s/forward\s*|header\s*//g;
                    if ($action =~ /\@/) {

                 # Remove the address from the list of @{$this->{archiveplaces}}
                        my @places;
                        foreach (@{$this->{archiveplaces}}) {
                            push @places, $_ unless /^$action$/i;
                        }
                        $this->{archiveplaces} = \@places;

#print STDERR "Removed $action from archiveplaces to give " . join(',',@places) . "\n";
                    } elsif ($action =~ /\"([^\"]+)\"/) {

               # Remove the header from the list of @{$this->{extraspamheaders}}
                        my @headers;
                        foreach (@{$this->{extraspamheaders}}) {
                            push @headers, $_ unless /^$action$/i;
                        }
                        $this->{extraspamheaders} = \@headers;

#print STDERR "Removed $action from extraspamheaders to give " . join(',',@headers) . "\n";
                    } elsif ($action =~ /^custom\((.*)\)/) {

                        # Call the "no" custom action
                        Baruwa::Scanner::Config::CallCustomAction($this, 'no',
                            $1);
                    } else {

                        #print STDERR "Removed $action from actions list\n";
                        # Support store-nonspam etc.
                        #$action =~ s/^store\W(\w+).*$/store-$1/;
                        delete $actions{$action};
                        $lintoptions{$action} = 1 unless $action =~ /-\//;
                    }
                } else {
                    #
                    # It's a normal action so add the action
                    #
                    #print STDERR "SArule normal action $action\n";
                    # Need to handle 'forward' and 'header' specially
                    $action =~ s/forward\s*|header\s*//g;
                    if ($action =~ /\@/) {

                        # It's a forward
                        #print STDERR "Adding $action to archiveplaces\n";
                        push @{$this->{archiveplaces}}, $action;
                        $actions{'forward'} = 1;

                        #delete $lintoptions{$action};
                    } elsif ($action =~ /\"([^\"]+)\"/) {

                        # It's a header
                        $actionkey = $1;

                        #print STDERR "Adding $actionkey to extraspamheaders\n";
                        push @{$this->{extraspamheaders}}, $actionkey;
                        Baruwa::Scanner::Log::WarnLog(
                            "Syntax error in \"header\" action in "
                              . "SpamAssassin rule actions, missing "
                              . "\":\" in %s",
                            $actionkey
                        ) unless $action =~ /:/;

                        #delete $lintoptions{$action};
                    } elsif ($action =~ /^custom\((.*)\)/) {

                        # Call the "no" custom action
                        Baruwa::Scanner::Config::CallCustomAction($this, 'yes',
                            $1);
                    } else {

               # It's some other action
               #print STDERR "Adding action $action\n";
               # Support store-nonspam etc.
               #$action =~ s/^store\W(\w+).*$/store-$1/;
               #print STDERR "Adding action $action after cleaning up stores\n";
                        $actions{$action} = 1;
                        $lintoptions{$action} = 1 unless $action =~ /-\//;
                    }
                }
            }

            # "delete" ==> "no-deliver"
            delete $actions{'deliver'} if $actions{'delete'};
        }
    }
    ###########################################
    ### SpamAssassin Rule Actions ends here ###
    ###########################################

    delete $actions{''};    # Delete any null records that crept in
        #print STDERR "Actions are: " . join(',',keys %actions) . "\n";

    # Do the syntax check
    delete $lintoptions{'deliver'};
    delete $lintoptions{'delete'};
    delete $lintoptions{'store'};
    delete $lintoptions{'store-nonspam'};
    delete $lintoptions{'store-spam'};
    delete $lintoptions{'bounce'};
    delete $lintoptions{'forward'};
    delete $lintoptions{'striphtml'};
    delete $lintoptions{'attachment'};
    delete $lintoptions{'notify'};
    delete $lintoptions{'header'};
    delete $lintoptions{'custom'};
    my $lintstring = join(' ', keys %lintoptions);

    if ($lintstring ne '') {
        my $lints = ($lintstring =~ /\s/) ? 's' : '';
        my $linttype;
        if ($HamSpam eq 'nonspam') {
            $linttype = 'Non-Spam';
        } else {
            if ($this->{ishigh}) {
                $linttype = 'High-Scoring Spam';
            } else {
                $linttype = 'Spam';
            }
        }
        Baruwa::Scanner::Log::WarnLog("Message %s produced illegal %s Action%s "
              . "\"%s\", so message is being delivered",
            $this->{id}, $linttype, $lints, $lintstring);

        # We found an error so fail-safe by delivering the message
        $actions{'deliver'} = 1;
    }

    # Now we are left with deliver, bounce, delete, store and striphtml.
    #print STDERR "Archive places are " . join(',', keys %actions) . "\n";

    # Log every message not being delivered
    if (Baruwa::Scanner::Config::Value('logdelivery')) {
        if (!$actions{'deliver'}) {
            Baruwa::Scanner::Log::NoticeLog(
                "Non-delivery of \u%s: message %s from %s to %s with subject %s",
                $HamSpam,
                $this->{id},
                lc($this->{from}),
                lc(join(',', @{$this->{to}})),
                $this->{subject}
            );
        }

        # Log every message being delivered
        if ($actions{'deliver'}) {
            Baruwa::Scanner::Log::NoticeLog(
                "Delivery of \u%s: message %s from %s to %s with subject %s",
                $HamSpam,
                $this->{id},
                lc($this->{from}),
                lc(join(',', @{$this->{to}})),
                $this->{subject}
            );
        }
    }

    # Split this job into 2.
    # 1) The message is being delivered to at least 1 address,
    # 2) The message is not being delivered to anyone.
    # The extra addresses for forward it to have already been added.
    if ($actions{'deliver'} || $actions{'forward'}) {
        #
        # Message is going to original recipient and/or extra recipients
        #

        Baruwa::Scanner::Log::NoticeLog(
            "Spam Actions: message %s actions are %s",
            $this->{id}, join(',', keys %actions))
          if $HamSpam eq 'spam' && Baruwa::Scanner::Config::Value('logspam');

        # Delete the original recipient if they are only forwarding it
        $global::MS->{mta}->DeleteRecipients($this) if !$actions{'deliver'};

        # Delete action is over-ridden as we are sending it somewhere
        delete $actions{'delete'};

        # Message still exists, so it will be delivered to its new recipients
    } else {
        #
        # Message is not going to be delivered anywhere
        #

        Baruwa::Scanner::Log::NoticeLog(
            "Spam Actions: message %s actions are %s",
            $this->{id}, join(',', keys %actions))
          if $HamSpam eq 'spam' && Baruwa::Scanner::Config::Value('logspam');

    # Mark the message so it won't get cleaned up or delivered, but just dropped
    #print STDERR "Setting DontDeliver for " . $this->{id} . "\n";
        $this->{dontdeliver} = 1;

        # Optimisation courtesy of Yavor.Trapkov@wipo.int
        $this->{deleted} = 1 if (keys %actions) == 1 && $actions{'delete'};
        ## Mark the message as deleted, so it won't get delivered
        #$this->{deleted} = 1;
    }

    # All delivery will now happen correctly.

    # Bounce a message back to the sender if they want that
    if ($actions{'bounce'}) {
        if ($HamSpam eq 'nonspam') {
            Baruwa::Scanner::Log::WarnLog(
                "Does not make sense to bounce non-spam");
        } else {

    #Baruwa::Scanner::Log::WarnLog('The "bounce" Spam Action no longer exists');
            if ($this->{ishigh}) {
                Baruwa::Scanner::Log::NoticeLog(
                    "Will not bounce high-scoring spam");
            } else {
                $this->HandleSpamBounce()
                  if Baruwa::Scanner::Config::Value('enablespambounce', $this);
            }
        }
    }

    # Notify the recipient if they want that
    if ($actions{'notify'}) {
        if ($HamSpam eq 'nonspam') {
            Baruwa::Scanner::Log::WarnLog(
                "Does not make sense to notify recipient about non-spam");
        } else {
            $this->HandleSpamNotify();
        }
    }

    # Store it if they want that
    my ($store, @stores);
    push @stores, $HamSpam  if $actions{'store'};
    push @stores, 'nonspam' if $actions{'store-nonspam'};
    push @stores, 'spam'    if $actions{'store-spam'};

    # Find all the absolute dir path stores
    foreach $store (keys %actions) {
        next unless $store =~ s/^store-//;
        push @stores, $store if $store =~ /^\//;
    }

    my %storealready;
    foreach $store (@stores) {
        my ($dir, $dir2, $spamdir, $uid, $gid, $changeowner);
        $uid         = $global::MS->{quar}->{uid};
        $gid         = $global::MS->{quar}->{gid};
        $changeowner = $global::MS->{quar}->{changeowner};

        #print STDERR "Store is $store\n";
        if ($store =~ /^\//) {

            #print STDERR "Absolute store $store\n";
            # It's an absolute store, so just store it in there
            $store =~ s/_HOUR_/$this->{hournumber}/;
            $store =~ s/_DATE_/$this->{datenumber}/;
            $store =~ s/_FROMUSER_/$this->{fromuser}/;
            $store =~ s/_FROMDOMAIN_/$this->{fromdomain}/;
            if ($store =~ /_TOUSER_|_TODOMAIN_/) {

          # It contains a substitution so we need to loop through all the recips
                my $numrecips = scalar(@{$this->{to}});
                foreach my $recip (0 .. $numrecips - 1) {
                    my $storecopy = $store;
                    my $u         = $this->{touser}[$recip];
                    my $d         = $this->{todomain}[$recip];
                    $storecopy =~ s/_TOUSER_/$u/g;
                    $storecopy =~ s/_TODOMAIN_/$d/g;
                    umask $global::MS->{quar}->{dirumask};
                    mkpath $storecopy unless -d $storecopy;
                    chown $uid, $gid, $storecopy if $changeowner;
                    umask $global::MS->{quar}->{fileumask};
                    push @{$this->{spamarchive}},
                      $this->{store}
                      ->CopyEntireMessage($this, $storecopy, $this->{id},
                        $uid, $gid, $changeowner)
                      unless $storealready{$storecopy};
                    $storealready{$storecopy} = 1;
                    chown $uid, $gid, "$storecopy/" . $this->{id};
                }
            } else {

                # It doesn't contian _TOUSER_ or _TODOMAIN_ so is a simple one
                umask $global::MS->{quar}->{dirumask};
                mkpath $store unless -d $store;
                chown $uid, $gid, $store if $changeowner;
                umask $global::MS->{quar}->{fileumask};
                push @{$this->{spamarchive}},
                  $this->{store}->CopyEntireMessage($this, $store, $this->{id},
                    $uid, $gid, $changeowner)
                  unless $storealready{$store};
                $storealready{$store} = 1;
                chown $uid, $gid, "$store/" . $this->{id};
            }
        } else {
            $dir = Baruwa::Scanner::Config::Value('quarantinedir', $this);

            #$dir2 = $dir . '/' .  Baruwa::Scanner::Quarantine::TodayDir();
            $dir2    = $dir . '/' . $this->{datenumber};
            $spamdir = $dir2 . '/' . $store;

            #print STDERR "dir = $dir\ndir2 = $dir2\nspamdir = $spamdir\n";
            umask $global::MS->{quar}->{dirumask};
            unless (-d $dir) {
                mkdir $dir, 0777;
                chown $uid, $gid, $dir if $changeowner;
            }
            unless (-d $dir2) {
                mkdir $dir2, 0777;
                chown $uid, $gid, $dir2 if $changeowner;
            }
            unless (-d $spamdir) {
                mkdir $spamdir, 0777;
                chown $uid, $gid, $spamdir if $changeowner;
            }

            #print STDERR "Storing spam to $spamdir/" . $this->{id} . "\n";
            #print STDERR "uid=$uid gid=$gid changeowner=$changeowner\n";
            umask $global::MS->{quar}->{fileumask};
            my @paths;
            @paths =
              $this->{store}->CopyEntireMessage($this, $spamdir, $this->{id},
                $uid, $gid, $changeowner)
              unless $storealready{$spamdir};

            # Remember where we have stored the spam in an archive, so we never
            # archive infected messages
            #print STDERR "Added " . join(',', @paths) . " to spamarchive\n";
            push @{$this->{spamarchive}}, @paths unless $storealready{$spamdir};
            $spamdir =~ /^(.*)$/;
            $spamdir = $1;
            my $tempid = $this->{id};
            $tempid =~ /^(.*)$/;
            $tempid = $1;
            chown $uid, $gid,
              "$spamdir/" . $tempid;    # Harmless if this fails # TAINT
        }
    }
    umask 0077;                         # Safety net

    # If they want to strip the HTML tags out of it,
    # then just tag it as we can only do this later.
    $this->{needsstripping} = 1 if $actions{'striphtml'};

    # If they want to encapsulate the message in an RFC822 part,
    # then tag it so we can do this later.
    $this->{needsencapsulating} = 1 if $actions{'attachment'};
}

# We want to send a message back to the sender saying that their junk
# email has been rejected by our site.
# Send a message back to the sender which has the local postmaster as
# the header sender, but <> as the envelope sender. This means it
# cannot bounce.
# Now have 3 different message file settings:
# 1. Is spam according to RBL's
# 2. Is spam according to SpamAssassin
# 3. Is spam according to both
sub HandleSpamBounce {
    my $this = shift;

    my ($from, $to, $subject, $date, $spamreport, $longspamreport, $hostname);
    my ($emailmsg, $line, $messagefh, $filename, $localpostmaster, $id);
    my ($postmastername);

    $from = $this->{from};

    # Don't ever send a message to "" or "<>"
    return if $from eq "" || $from eq "<>";

    # Do we want to send the sender a warning at all?
    # If nosenderprecedence is set to non-blank and contains this
    # message precedence header, then just return.
    my (@preclist, $prec, $precedence, $header);
    @preclist =
      split(" ",
        lc(Baruwa::Scanner::Config::Value('nosenderprecedence', $this)));
    $precedence = "";
    foreach $header (@{$this->{headers}}) {
        $precedence = lc($1) if $header =~ /^precedence:\s+(\S+)/i;
    }
    if (@preclist && $precedence ne "") {
        foreach $prec (@preclist) {
            if ($precedence eq $prec) {
                Baruwa::Scanner::Log::InfoLog(
                    "Skipping sender of precedence %s", $precedence);
                return;
            }
        }
    }

    # Setup other variables they can use in the message template
    $id = $this->{id};

    #$to = join(', ', @{$this->{to}});
    $localpostmaster = Baruwa::Scanner::Config::Value('localpostmaster', $this);
    $postmastername = Baruwa::Scanner::Config::LanguageValue($this, 'baruwa');
    $hostname = Baruwa::Scanner::Config::Value('hostname', $this);
    $subject = $this->{subject};
    $date           = $this->{datestring};     # scalar localtime;
    $spamreport     = $this->{spamreport};
    $longspamreport = $this->{salongreport};

    #print STDERR "longspamreport = \"$longspamreport\"\n";
    my (%tolist);
    foreach $to (@{$this->{to}}) {
        $tolist{$to} = 1;
    }
    $to = join(', ', sort keys %tolist);

    # Delete everything in brackets after the SA report, if it exists
    $spamreport =~ s/(spamassassin)[^(]*\([^)]*\)/$1/i;

    # Work out which of the 3 spam reports to send them.
    $filename = "";
    if ($this->{isrblspam} && !$this->{issaspam}) {
        $filename =
          Baruwa::Scanner::Config::Value('senderrblspamreport', $this);
        Baruwa::Scanner::Log::NoticeLog("Spam Actions: (RBL) Bounce to %s",
            $from)
          if Baruwa::Scanner::Config::Value('logspam');
    } elsif ($this->{issaspam} && !$this->{isrblspam}) {
        $filename = Baruwa::Scanner::Config::Value('sendersaspamreport', $this);
        Baruwa::Scanner::Log::NoticeLog(
            "Spam Actions: (SpamAssassin) Bounce to %s", $from)
          if Baruwa::Scanner::Config::Value('logspam');
    }
    if ($filename eq "") {
        $filename =
          Baruwa::Scanner::Config::Value('senderbothspamreport', $this);
        Baruwa::Scanner::Log::NoticeLog(
            "Spam Actions: (RBL,SpamAssassin) Bounce to %s", $from)
          if Baruwa::Scanner::Config::Value('logspam');
    }

    $messagefh = new FileHandle;
    $messagefh->open($filename)
      or Baruwa::Scanner::Log::WarnLog("Cannot open message file %s, %s",
        $filename, $!);
    $emailmsg = "X-Baruwa-Bounce: yes\n";
    while (<$messagefh>) {
        chomp;
        s#"#\\"#g;
        s#@#\\@#g;

        # Boring untainting again...
        /(.*)/;

        # Bug fix by Martin Hepworth
        $line = eval "\"$1\"";
        $emailmsg .= Baruwa::Scanner::Config::DoPercentVars($line) . "\n";
    }
    $messagefh->close();

    if (Baruwa::Scanner::Config::Value('bouncespamasattachment', $this)) {
        $this->HandleSpamBounceAttachment($emailmsg);
    } else {

        # Send the message to the spam sender, but ensure the envelope
        # sender address is "<>" so that it can't be bounced.
        $global::MS->{mta}->SendMessageString($this, $emailmsg, '<>')
          or
          Baruwa::Scanner::Log::WarnLog("Could not send sender spam bounce, %s",
            $!);
    }
}

# Like encapsulating and sending a message to the recipient, take the
# passed text as the text and headers of an email message and attach
# the original message as an rfc/822 attachment.
sub HandleSpamBounceAttachment {
    my ($this, $plaintext) = @_;

    my $parser      = MIME::Parser->new;
    my $explodeinto = $global::MS->{work}->{dir} . '/' . $this->{id};

    #print STDERR "Extracting spam bounce message into $explodeinto\n";
    my $filer = Baruwa::Scanner::FileInto->new($explodeinto);
    $parser->filer($filer);

    my $bounce = eval {$parser->parse_data(\$plaintext)};
    if (!$bounce) {
        Baruwa::Scanner::Log::WarnLog("Cannot parse spam bounce report, %s",
            $!);
        return;
    }

    #print STDERR "Successfully parsed bounce report\n";

    # Now make it multipart and push the report into a child
    $bounce->make_multipart('report');

    # Now turn the original message into a string and attach it
    my (@original);

    #my $original = $this->{entity}->stringify;
    @original = $global::MS->{mta}->OriginalMsgHeaders($this, "\n");
    push(@original, "\n");
    $this->{store}->ReadBody(\@original,
        Baruwa::Scanner::Config::Value('maxspamassassinsize'));

    $bounce->add_part(
        MIME::Entity->build(
            Type        => 'message/rfc822',
            Disposition => 'attachment',
            Top         => 0,
            'X-Mailer'  => undef,
            Data        => \@original
        )
    );

    # Prune all the dead branches off the tree
    PruneEntityTree($bounce);

    # Stringify the message and send it -- this could be VERY large!
    my $bouncetext = $bounce->stringify;

    #print STDERR "Spam bounce message is this:\n$bouncetext";
    if ($bouncetext) {
        $global::MS->{mta}->SendMessageString($this, $bouncetext, '<>')
          or Baruwa::Scanner::Log::WarnLog(
            "Could not send sender spam bounce attachment, %s", $!);
    } else {
        Baruwa::Scanner::Log::WarnLog(
            "Failed to create sender spam bounce attachment, %s", $!);
    }
}

# We want to send a message to the recipient saying that their spam
# mail has not been delivered.
# Send a message to the recipients which has the local postmaster as
# the sender.
sub HandleSpamNotify {
    my $this = shift;

    my ($from, $to, $subject, $date, $spamreport, $hostname, $day, $month,
        $year);
    my ($emailmsg, $line, $messagefh, $filename, $localpostmaster, $id);
    my ($postmastername);

    $from = $this->{from};

    # Don't ever send a message to "" or "<>"
    return if $from eq "" || $from eq "<>";

    # Do we want to send the sender a warning at all?
    # If nosenderprecedence is set to non-blank and contains this
    # message precedence header, then just return.
    my (@preclist, $prec, $precedence, $header);
    @preclist =
      split(" ",
        lc(Baruwa::Scanner::Config::Value('nosenderprecedence', $this)));
    $precedence = "";
    foreach $header (@{$this->{headers}}) {
        $precedence = lc($1) if $header =~ /^precedence:\s+(\S+)/i;
    }
    if (@preclist && $precedence ne "") {
        foreach $prec (@preclist) {
            if ($precedence eq $prec) {
                Baruwa::Scanner::Log::InfoLog(
                    "Skipping sender of precedence %s", $precedence);
                return;
            }
        }
    }

    # Setup other variables they can use in the message template
    $id              = $this->{id};
    $localpostmaster = Baruwa::Scanner::Config::Value('localpostmaster', $this);
    $postmastername  = Baruwa::Scanner::Config::LanguageValue($this, 'baruwa');
    $hostname        = Baruwa::Scanner::Config::Value('hostname', $this);
    $subject         = $this->{subject};
    $date       = $this->{datestring};    # scalar localtime;
    $spamreport = $this->{spamreport};

    # And let them put the date number in there too
    #($day, $month, $year) = (localtime)[3,4,5];
    #$month++;
    #$year += 1900;
    #my $datenumber = sprintf("%04d%02d%02d", $year, $month, $day);
    my $datenumber = $this->{datenumber};

    my (%tolist);
    foreach $to (@{$this->{to}}) {
        $tolist{$to} = 1;
    }
    $to = join(', ', sort keys %tolist);

    # Delete everything in brackets after the SA report, if it exists
    $spamreport =~ s/(spamassassin)[^(]*\([^)]*\)/$1/i;

    # Work out which of the 3 spam reports to send them.
    $filename = Baruwa::Scanner::Config::Value('recipientspamreport', $this);
    Baruwa::Scanner::Log::NoticeLog("Spam Actions: Notify %s", $to)
      if Baruwa::Scanner::Config::Value('logspam');

    $messagefh = new FileHandle;
    $messagefh->open($filename)
      or Baruwa::Scanner::Log::WarnLog("Cannot open message file %s, %s",
        $filename, $!);
    $emailmsg = "";
    while (<$messagefh>) {
        chomp;
        s#"#\\"#g;
        s#@#\\@#g;

        # Boring untainting again...
        /(.*)/;
        $line = eval "\"$1\"";
        $emailmsg .= Baruwa::Scanner::Config::DoPercentVars($line) . "\n";
    }
    $messagefh->close();

    # Send the message to the spam sender, but ensure the envelope
    # sender address is "<>" so that it can't be bounced.
    $global::MS->{mta}->SendMessageString($this, $emailmsg, $localpostmaster)
      or Baruwa::Scanner::Log::WarnLog("Could not send sender spam notify, %s",
        $!);
}

sub RejectMessage {
    my $this = shift;

    my ($from,     $to,   %tolist,    $subject,  $date,            $hostname);
    my ($emailmsg, $line, $messagefh, $filename, $localpostmaster, $id);
    my ($postmastername);

    $from = $this->{from};

    # Don't ever send a message to "" or "<>"
    return if $from eq "" || $from eq "<>";

    # Setup other variables they can use in the message template
    $id              = $this->{id};
    $localpostmaster = Baruwa::Scanner::Config::Value('localpostmaster', $this);
    $postmastername  = Baruwa::Scanner::Config::LanguageValue($this, 'baruwa');
    $hostname        = Baruwa::Scanner::Config::Value('hostname', $this);
    $subject         = $this->{subject};
    $date = $this->{datestring};    # scalar localtime;
    foreach $to (@{$this->{to}}) {
        $tolist{$to} = 1;
    }
    $to = join(', ', sort keys %tolist);

    # Work out which of the 3 spam reports to send them.
    $filename = Baruwa::Scanner::Config::Value('rejectionreport', $this);
    Baruwa::Scanner::Log::NoticeLog("Reject message %s from %s with report %s",
        $id, $from, $filename);
    return if $filename eq "";

    #print STDERR "Rejecting message $id with $filename\n";
    $messagefh = new FileHandle;
    $messagefh->open($filename)
      or Baruwa::Scanner::Log::WarnLog("Cannot open message file %s, %s",
        $filename, $!);
    $emailmsg = "X-Baruwa-Rejected: yes\n";

    while (<$messagefh>) {
        chomp;
        s#"#\\"#g;
        s#@#\\@#g;

        # Boring untainting again...
        /(.*)/;
        $line = eval "\"$1\"";
        $emailmsg .= Baruwa::Scanner::Config::DoPercentVars($line) . "\n";
    }
    $messagefh->close();

    #print STDERR "Rejection is:\n-----SNIP-----\n$emailmsg-----SNIP-----\n";
    # Send the message to the spam sender, but ensure the envelope
    # sender address is "<>" so that it can't be bounced.
    $global::MS->{mta}->SendMessageString($this, $emailmsg, '<>')
      or Baruwa::Scanner::Log::WarnLog(
        "Could not send rejection report for %s, %s",
        $id, $!);
    $this->{deleted}     = 1;
    $this->{dontdeliver} = 1;

}

# Like encapsulating and sending a message to the recipient, take the

# Deliver a message that doesn't want to be touched at all in any way.
# Take an out queue dir.
sub DeliverUntouched {
    my $this = shift;
    my ($OutQ) = @_;

    return if $this->{deleted};

    #my $OutQ = Baruwa::Scanner::Config::Value('outqueuedir', $this);
    my $store = $this->{store};

    # Link the queue data file from in to out
    $store->LinkData($OutQ);

    # Add the headers onto the metadata in the message store
    $global::MS->{mta}->AddHeadersToQf($this);

    # Don't add the same extra recipient twice
    my %alreadydone = ();

    # Add the secret archive recipients
    my ($extra, @extras);
    foreach $extra (@{$this->{archiveplaces}}) {

        # Email archive recipients include a '@'
        next if $extra =~ /^\//;
        next unless $extra =~ /@/;
        $extra =~ s/_HOUR_/$this->{hournumber}/g;
        $extra =~ s/_DATE_/$this->{datenumber}/g;
        $extra =~ s/_FROMUSER_/$this->{fromuser}/g;
        $extra =~ s/_FROMDOMAIN_/$this->{fromdomain}/g;
        if ($extra !~ /_TOUSER_|_TODOMAIN_/) {

            # It's a simple email address
            push @extras, $extra unless $alreadydone{$extra};
            $alreadydone{$extra} = 1;
        } else {

          # It contains a substitution so we need to loop through all the recips
            my $numrecips = scalar(@{$this->{to}});
            foreach my $recip (0 .. $numrecips - 1) {
                my $extracopy = $extra;
                my $u         = $this->{touser}[$recip];
                my $d         = $this->{todomain}[$recip];
                $extracopy =~ s/_TOUSER_/$u/g;
                $extracopy =~ s/_TODOMAIN_/$d/g;
                push @extras, $extracopy unless $alreadydone{$extracopy};
                $alreadydone{$extracopy} = 1;  # Dont add the same address twice
            }
        }
    }
    $global::MS->{mta}->AddRecipients($this, @extras) if @extras;

    # Write the new qf file, delete originals and unlock the message
    $store->WriteHeader($this, $OutQ);
    unless ($this->{gonefromdisk}) {
        $store->DeleteUnlock();
        $this->{gonefromdisk} = 1;
    }

    # Note this does not kick the MTA into life here any more
}

# Deliver a message that doesn't need scanning at all
# Takes an out queue dir.
sub DeliverUnscanned {
    my $this = shift;
    my ($OutQ) = @_;

    return if $this->{deleted};

    #my $OutQ = Baruwa::Scanner::Config::Value('outqueuedir', $this);
    my $store = $this->{store};

    # Link the queue data file from in to out
    $store->LinkData($OutQ);

    # Add the headers onto the metadata in the message store
    $global::MS->{mta}->AddHeadersToQf($this);

    # Remove duplicate subject: lines
    $global::MS->{mta}->UniqHeader($this, 'Subject:');

    # Add the information/help X- header
    my $infoheader = Baruwa::Scanner::Config::Value('infoheader', $this);
    if ($infoheader) {
        my $infovalue = Baruwa::Scanner::Config::Value('infovalue', $this);
        $global::MS->{mta}->ReplaceHeader($this, $infoheader, $infovalue);
    }
    my $idheader = Baruwa::Scanner::Config::Value('idheader', $this);
    if ($idheader) {
        $global::MS->{mta}->ReplaceHeader($this, $idheader, $this->{id});
    }

    # Add the Unscanned X- header
    if (Baruwa::Scanner::Config::Value('signunscannedmessages', $this)) {
        $global::MS->{mta}->AddMultipleHeader($this, 'mailheader',
            Baruwa::Scanner::Config::Value('unscannedheader', $this), ', ');
    }

    # Remove any headers we don't want in the message
    my (@removeme, $remove);
    @removeme =
      split(/[,\s]+/, Baruwa::Scanner::Config::Value('removeheaders', $this));
    foreach $remove (@removeme) {

        # Add a : if there isn't one already, it's needed for DeleteHeader()
        # 20090312 Done in DeleteHeader: $remove .= ':' unless $remove =~ /:$/;
        $global::MS->{mta}->DeleteHeader($this, $remove);
    }

    # Leave old content-length: headers as we aren't changing body.

    # Add IPv6 or IPv4 protocol version header
    my $ipverheader = Baruwa::Scanner::Config::Value('ipverheader', $this);
    $global::MS->{mta}->ReplaceHeader($this, $ipverheader,
        (($this->{clientip} =~ /:/) ? 'IPv6' : 'IPv4'))
      if $ipverheader;

# Add spam header if it's spam or they asked for it
#$global::MS->{mta}->AddHeader($this,
#                              Baruwa::Scanner::Config::Value('spamheader',$this),
#                              $this->{spamreport})
# JKF 3/10/2005
    $global::MS->{mta}
      ->AddMultipleHeader($this, 'spamheader', $this->{spamreport}, ', ')
      if Baruwa::Scanner::Config::Value('includespamheader', $this)
      || ($this->{spamreport} && $this->{isspam});

    # Add the spam stars if they want that. Limit it to 60 characters to avoid
    # a potential denial-of-service attack.
    my ($stars, $starcount, $scoretext, $minstars, $scorefmt);
    $starcount = int($this->{sascore}) + 0;
    $starcount = 0 if $this->{spamwhitelisted};    # 0 stars if white-listed
    $scorefmt  = Baruwa::Scanner::Config::Value('scoreformat', $this);
    $scorefmt  = '%d' if $scorefmt eq '';
    $scoretext = sprintf($scorefmt, $this->{sascore} + 0);
    $minstars  = Baruwa::Scanner::Config::Value('minstars', $this);
    $starcount = $minstars
      if $this->{isrblspam}
      && $minstars
      && $starcount < $minstars;

    if (Baruwa::Scanner::Config::Value('spamscorenotstars', $this)) {
        $stars = $scoretext;    # int($starcount);
    } else {
        $starcount = 60 if $starcount > 60;
        $stars =
          Baruwa::Scanner::Config::Value('spamstarscharacter') x $starcount;
    }
    if (Baruwa::Scanner::Config::Value('spamstars', $this) =~ /1/
        && $starcount > 0) {
        $global::MS->{mta}
          ->AddMultipleHeader($this, 'spamstarsheader', $stars, ', ');
    }

    # Add the Envelope to and from headers
    AddFromAndTo($this);

    # Repair the subject line
    $global::MS->{mta}->ReplaceHeader($this, 'Subject:', $this->{safesubject})
      if $this->{subjectwasunsafe};

# Remove duplicate subject because replaceheader does not delete if in dkimsafe mode
    $global::MS->{mta}->UniqHeader($this, 'Subject:');

    # Modify the subject line for Disarming
    my $disarmtag = Baruwa::Scanner::Config::Value('disarmsubjecttext', $this);
    if ($this->{messagedisarmed}) {

        #print STDERR "Message has been disarmed at 1346.\n";
        my $where =
          Baruwa::Scanner::Config::Value('disarmmodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}
            ->TextEndsHeader($this, 'Subject:', $disarmtag)) {
            $global::MS->{mta}
              ->AppendHeader($this, 'Subject:', $disarmtag, ' ');
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $disarmtag)) {
            $global::MS->{mta}
              ->PrependHeader($this, 'Subject:', $disarmtag, ' ');
        }
    }

    # Modify the subject line for spam
    # if it's spam AND they want to modify the subject line AND it's not
    # already been modified by another of your Baruwas.
    my $spamtag = Baruwa::Scanner::Config::Value('spamsubjecttext', $this);
    $spamtag =~ s/_SCORE_/$scoretext/;
    $spamtag =~ s/_STARS_/$stars/i;

    if ($this->{isspam} && !$this->{ishigh}) {
        my $where = Baruwa::Scanner::Config::Value('spammodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}->TextEndsHeader($this, 'Subject:', $spamtag))
        {   $global::MS->{mta}->AppendHeader($this, 'Subject:', $spamtag, ' ');
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $spamtag)) {
            $global::MS->{mta}->PrependHeader($this, 'Subject:', $spamtag, ' ');
        }
    }

    # If it is high-scoring spam, then add a different bit of text
    $spamtag = Baruwa::Scanner::Config::Value('highspamsubjecttext', $this);
    $spamtag =~ s/_SCORE_/$scoretext/;
    $spamtag =~ s/_STARS_/$stars/i;

    if ($this->{isspam} && $this->{ishigh}) {
        my $where =
          Baruwa::Scanner::Config::Value('highspammodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}->TextEndsHeader($this, 'Subject:', $spamtag))
        {   $global::MS->{mta}->AppendHeader($this, 'Subject:', $spamtag, ' ');
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $spamtag)) {
            $global::MS->{mta}->PrependHeader($this, 'Subject:', $spamtag, ' ');
        }
    }

    # Add the extra headers they want for spam messages
    my (@extraheaders, $extraheader);
    my ($key,          $value);
    push @extraheaders, @{$this->{extraspamheaders}}
      if $this->{extraspamheaders};
    foreach $extraheader (@extraheaders) {
        next unless $extraheader =~ /:/;
        ($key, $value) = split(/:\s*/, $extraheader, 2);
        $key =~ s/\s+/-/g;    # Replace spaces in header name with dashes

        # Replace _TO_ in the header value with a comma-separated list of recips
        if ($value =~ /_TO_/) {

            # Get the actual text for the header value
            my ($recipient, %tolist);
            foreach $recipient (@{$this->{to}}) {
                $tolist{$recipient} = 1;
            }
            $recipient = join(', ', sort keys %tolist);

            # Now reflow the To list in case it is very long
            $recipient = $this->ReflowHeader($key . ':', $recipient);
            $value =~ s/_TO_/$recipient/g;
        }

        $global::MS->{mta}
          ->AddMultipleHeaderName($this, $key . ':', $value, ', ');
    }

    # Add watermark header if chosen to do so.
    if ($this->{addmshmac}) {
        my $mshmacheader =
          Baruwa::Scanner::Config::Value('mshmacheader', $this);
        my $mshmac = $this->{mshmac};

        $global::MS->{mta}->ReplaceHeader($this, $mshmacheader, $mshmac);
    }

    # Add the secret archive recipients
    my ($extra, @extras, %alreadydone);
    foreach $extra (@{$this->{archiveplaces}}) {

        # Email archive recipients include a '@'
        next if $extra =~ /^\//;
        next unless $extra =~ /@/;
        $extra =~ s/_HOUR_/$this->{hournumber}/g;
        $extra =~ s/_DATE_/$this->{datenumber}/g;
        $extra =~ s/_FROMUSER_/$this->{fromuser}/g;
        $extra =~ s/_FROMDOMAIN_/$this->{fromdomain}/g;
        if ($extra !~ /_TOUSER_|_TODOMAIN_/) {

            # It's a simple email address
            push @extras, $extra unless $alreadydone{$extra};
            $alreadydone{$extra} = 1;
        } else {

          # It contains a substitution so we need to loop through all the recips
            my $numrecips = scalar(@{$this->{to}});
            foreach my $recip (0 .. $numrecips - 1) {
                my $extracopy = $extra;
                my $u         = $this->{touser}[$recip];
                my $d         = $this->{todomain}[$recip];
                $extracopy =~ s/_TOUSER_/$u/g;
                $extracopy =~ s/_TODOMAIN_/$d/g;
                push @extras, $extracopy unless $alreadydone{$extracopy};
                $alreadydone{$extracopy} = 1;  # Dont add the same address twice
            }
        }
    }
    $global::MS->{mta}->AddRecipients($this, @extras) if @extras;

    # Write the new qf file, delete originals and unlock the message
    $store->WriteHeader($this, $OutQ);
    unless ($this->{gonefromdisk}) {
        $store->DeleteUnlock();
        $this->{gonefromdisk} = 1;
    }

    # Note this does not kick the MTA into life here any more
}

# Add the X-Envelope-From and X-Envelope-To headers
sub AddFromAndTo {
    my $this = shift;

    my ($to, %tolist, $from, $envtoheader);

    # Do they all want the From header
    if (Baruwa::Scanner::Config::Value('addenvfrom', $this) !~ /0/) {
        $from = $this->{from};
        $global::MS->{mta}->ReplaceHeader($this,
            Baruwa::Scanner::Config::Value('envfromheader', $this), $from);
    }

    # Do they all want the To header
    if (Baruwa::Scanner::Config::Value('addenvto', $this) =~ /^[1\s]+$/) {

        # Get the actual text for the header value
        foreach $to (@{$this->{to}}) {
            $tolist{$to} = 1;
        }
        $to = join(', ', sort keys %tolist);

        $envtoheader = Baruwa::Scanner::Config::Value('envtoheader', $this);

        # Now reflow the To list in case it is very long
        $to = $this->ReflowHeader($envtoheader, $to);

        $global::MS->{mta}->ReplaceHeader($this, $envtoheader, $to);
    }
}

# Replace the attachments of the message with a zip archive
# containing them all.
sub ZipAttachments {
    my $this = shift;

    return if $this->{deleted};

    return
      unless Baruwa::Scanner::Config::Value('zipattachments', $this) =~ /1/;

    my $workarea    = $global::MS->{work};
    my $explodeinto = $workarea->{dir} . "/" . $this->{id};

    #print STDERR "Processing files in $explodeinto\n";
    chdir $explodeinto;
    my $dir = new DirHandle $explodeinto;
    unless ($dir) {
        Baruwa::Scanner::Log::WarnLog("Error: could not open message dir %s",
            $explodeinto);
        return;
    }

    # Build a regexp of the filename suffixes to ignore
    my ($suffix, $suffixes, @suffixes, $regexp, @escaped);
    $suffixes = Baruwa::Scanner::Config::Value('attachzipignore', $this);
    @suffixes = split " ", $suffixes;
    foreach $suffix (@suffixes) {
        push @escaped, quotemeta($suffix) . '$';
    }
    $regexp = join('|', @escaped);

    #print STDERR "Regexp is \"$regexp\"\n";

    # Build a list of attachment entities
    my ($file, @files, $entity, @entitylist, @entitiestodelete, $unsafefile);
    $this->ListLeafEntities($this->{entity}, \@entitylist);

    my $totalsize = 0;    #  Track total size of all attachments added to zip
    foreach $entity (@entitylist) {
        $file = $this->{entity2safefile}{$entity};
        next
          if $file eq '';   # Has this attachment been removed from the message?
                            #print STDERR "Looking for $file\n";
        next unless -f "$explodeinto/$file";
        next unless $entity;

        # Don't add the file if it's the winmail.dat file
        unless ($entity eq $this->{tnefentity} && $this->{tnefentity}) {

            # Add the file if it is an attachment, not an inline file
            if ($entity->head->mime_attr("content-disposition") =~
                /attachment/i) {
                unless ($file =~ /$regexp/i) {
                    push @files,            $file;
                    push @entitiestodelete, $entity;
                    $totalsize += -s "$explodeinto/$file";

                    #print STDERR "Added $file to attachment list\n";
                }
            }
        }
    }

    # If no files in the archive, don't create it.
    return unless @files;

    # If the total file sizes are too small, don't zip them
    return
      if $totalsize < Baruwa::Scanner::Config::Value('attachzipminsize', $this);

    # Find the name of the new zip file, if there is one
    my $newzipname = Baruwa::Scanner::Config::Value('attachzipname', $this);

    #print STDERR "New zip name = $newzipname\n";
    return unless $newzipname;

    # Create a new zip archive
    my $zip = Archive::Zip->new();
    foreach $file (@files) {

        #JKF 20080331 $zip->addFile("$explodeinto/$file", $file);
        $unsafefile = $this->{safefile2file}{$file};

        #print STDERR "Adding $file as $unsafefile\n";
        Baruwa::Scanner::Log::InfoLog("Adding zip member name \"%s\"", $file);
        $zip->addFile("$explodeinto/$file", $unsafefile);
    }

    # The new zip file is a normal attachment.
    my $safezipname = $this->MakeNameSafe('n' . $newzipname, $explodeinto);

    #print STDERR "Writing to zip $safezipname\n";
    my $result = $zip->writeToFileNamed($explodeinto . '/' . $safezipname);
    unless ($result == AZ_OK) {

        #print STDERR "Error: Zip file could not be created!\n";
        Baruwa::Scanner::Log::WarnLog(
            "Zip file %s for message %s could not be created",
            $safezipname, $this->{id});
        return;
    }

    # Add the new zipfile entity
    $entity = $this->{entity};
    $entity->make_multipart;
    my $newentity = MIME::Entity->build(
        Path        => "$explodeinto/$safezipname",
        Top         => 0,
        Type        => "application/zip",
        Encoding    => "base64",
        Filename    => $newzipname,
        Disposition => "attachment"
    );
    $entity->add_part($newentity);
    $this->{bodymodified} = 1;

    # Create all the Helpers for the new attachment
    $this->{entity2file}{$newentity}         = $newzipname;
    $this->{entity2safefile}{$newentity}     = $safezipname;
    $this->{entity2parent}{$newentity}       = 0;
    $this->{file2entity}{$newzipname}        = $newentity;
    $this->{name2entity}{scalar($newentity)} = $newentity;
    $this->{file2safefile}{$newzipname}      = $safezipname;
    $this->{safefile2file}{$safezipname}     = $newzipname;

    # Delete the old attachments' entities
    my ($attachfile, $attachentity);
    foreach $entity (@entitiestodelete) {
        $attachfile = $this->{entity2safefile}{$entity};

        #$attachentity = $this->{file2entity}{$attachfile};
        $this->DeleteEntity($entity, $this->{entity}, $this->{tnefentity});

    # Thought this was right: $this->DeleteEntity($entity, $this->{tnefentity});
    # And the files themselves
        unlink("$explodeinto/$attachfile");

        #print STDERR "Deleted file $attachfile\n";
    }

}

# Explode a message into its MIME structure and attachments.
# Pass in the workarea where it should go.
sub Explode {
    my $this = shift;

    # $handle is Sendmail only
    my ($entity, $pipe, $handle, $pid, $workarea, $baruwaname);

    return if $this->{deleted};

    # Get the translation of Baruwa, we use it a lot
    $baruwaname = Baruwa::Scanner::Config::LanguageValue($this, 'baruwa');

    # Set up something so that the hash exists
    $this->{file2parent}{""} = "";

    # df file is already locked
    $workarea = $global::MS->{work};
    my $explodeinto = $workarea->{dir} . "/" . $this->{id};

    # print STDERR "Going to explode message " . $this->{id} .
    #             " into $explodeinto\n";

    # Setup everything for the MIME parser
    my $parser = MIME::Parser->new;
    my $filer  = Baruwa::Scanner::FileInto->new($explodeinto);

    # Over-ride the default default character set handler so it does it
    # much better than the MIME-tools default handling.
    MIME::WordDecoder->default->handler('*' => \&WordDecoderKeep7Bit);

    # print STDERR "Exploding message " . $this->{id} . " into " .
    #             $explodeinto . "\n";
    $parser->filer($filer);
    $parser->extract_uuencode(1);       # uue is off by default
    $parser->output_to_core(0);    # everything into files

    $handle = IO::File->new_tmpfile
      or die "Your /tmp needs to be set to \"chmod 1777 /tmp\"";
    binmode($handle);
    # $this->{store}->ReadMessageHandle($this, $handle) or return;
    unless ($this->{store}->ReadMessageHandle($this, $handle)) {
        print STDERR "Failed to read message $this->{id}\n";
        return;
    }

    ## Do the actual parsing
    my $maxparts = Baruwa::Scanner::Config::Value('maxparts', $this) || 200;
    MIME::Entity::ResetBaruwaCounter($maxparts);

    # Inform MIME::Parser about our maximum
    $parser->max_parts($maxparts * 3);
    $entity = eval {$parser->parse($handle)};
    print STDERR "ERROR: $@\n" if ($@);
    # close and delete tmpfile
    close($handle);

    if (!$entity && !MIME::Entity::BaruwaCounter() >= $maxparts) {
        unless ($this->{dpath}) {

           # It probably ran out of disk space, drop this message from the batch
            Baruwa::Scanner::Log::WarnLog(
                "Failed to create message structures for %s"
                  . ", dropping it from the batch",
                $this->{id}
            );
            my @toclear = ($this->{id});
            $workarea->ClearIds(\@toclear)
              ;    # Delete attachments we might have made
            $this->DropFromBatch();
            return;
        }

        Baruwa::Scanner::Log::WarnLog("Cannot parse "
              . $this->{headerspath} . " and "
              . $this->{dpath}
              . ", $@");
        $this->{entity} =
          $entity;    # In case it failed due to too many attachments
        $this->{cantparse}     = 1;
        $this->{otherinfected} = 1;
        return;
    }

    # Too many attachments in the message?
    if ($maxparts > 0 && MIME::Entity::BaruwaCounter() >= $maxparts) {

        #print STDERR "Found an error!\n";
        #Not with sendmail: $pipe->close();
        #Not with sendmail: kill 9, $pid; # Make sure we are reaping a dead'un
        #Not with sendmail: waitpid $pid, 0;
        Baruwa::Scanner::Log::WarnLog(
            "Too many attachments (%d) in %s",
            MIME::Entity::BaruwaCounter(),
            $this->{id}
        );
        $this->{entity} =
          $entity;    # In case it failed due to too many attachments
        $this->{toomanyattach} = 1;
        $this->{otherinfected} = 1;
        return;
    }

    # Closing the pipe this way will reap the child, apparently!
    #Not with sendmail: $pipe->close;
    #Not with sendmail: kill 9, $pid; # Make sure we are reaping a dead'un
    $this->{entity} = $entity;

    # Now handle TNEF files. They should be the only attachment to the message.
    ($this->{tnefentity}, $this->{tnefname}) =
      Baruwa::Scanner::TNEF::FindTNEFFile($entity)
      if Baruwa::Scanner::Config::Value('expandtnef');

    # Look for winmail.dat files in each attachment directory $path.
    # When we find one explode it into its files and store the root MIME
    # entity into $IsTNEF{$id} so we can handle it separately later.
    # Pattern to match is actually winmail(digits).dat(digits) as that copes
    # with forwarded or bounced messages from mail packages that download
    # all attachments into 1 directory, adding numbers to their filenames.

    # Only delete original tnef if no-one wants to not replace it nor use it
    my $DeleteTNEF = 0;
    $DeleteTNEF = 1
      if Baruwa::Scanner::Config::Value('replacetnef', $this) !~ /[01]/;

    # print STDERR "ReplaceTNEF = " . Baruwa::Scanner::Config::Value('replacetnef', $this) . "\n";

    if (Baruwa::Scanner::Config::Value('tnefexpander') && $this->{tnefentity}) {
        my ($tneffile, @tneffiles);

        # Find all the TNEF files called winmail.dat
        my $outputdir = new DirHandle;
        $outputdir->open($explodeinto)
          or Baruwa::Scanner::Log::WarnLog(
            "Failed to open dir "
              . $explodeinto
              . " while scanning for TNEF files, %s",
            $!
          );

        # This regexp must *not* be anchored to the start of the filename as
        # there should be a prefix type indicator character in the filename.
        @tneffiles = map {/(.winmail\d*\.dat\d*)/i} $outputdir->read();
        $outputdir->close();

        #print STDERR "TNEF Entity is " . $this->{tnefentity} . "\n";
        #print STDERR "TNEF files are " . join(',',@tneffiles) . "\n";
        #print STDERR "Tree is \n" . $this->{entity}->dump_skeleton;

        foreach $tneffile (@tneffiles) {
            my $result;

            # Remove the type indicator character for logging.
            my $tnefnotype = substr($tneffile, 1);
            Baruwa::Scanner::Log::InfoLog("Expanding TNEF archive at %s/%s",
                $explodeinto, $tnefnotype);
            $result =
              Baruwa::Scanner::TNEF::Decoder($explodeinto, $tneffile, $this);
            if ($result) {
                # If they want to replace the TNEF rather than add to it,
                # then delete the original winmail.dat-style attachment
                # and remove the flag saying it is a TNEF message at all.
                # print STDERR "***** Found TNEF Attachments = " . $this->{foundtnefattachments} . "\n";
                # print STDERR "*** DeleteTNEF = $DeleteTNEF and foundtnefatt = " . $this->{foundtnefattachments} . "\n";
                if ($DeleteTNEF && $this->{foundtnefattachments}) {
                    $this->DeleteEntity($this->{tnefentity}, $this->{entity},
                        $this->{tnefentity});
                    unlink "$explodeinto/$tneffile";

                    #print STDERR "*** Deleted $explodeinto/$tneffile\n";
                    delete $this->{tnefentity};
                    Baruwa::Scanner::Log::InfoLog(
                        "Message %s has had TNEF %s removed",
                        $this->{id}, $tnefnotype);
                }
            } else {
                Baruwa::Scanner::Log::WarnLog(
                    "Corrupt TNEF %s that cannot be "
                      . "analysed in message %s",
                    $tnefnotype, $this->{id}
                );
                $this->{badtnef}       = 1;
                $this->{otherinfected} = 1;
            }
        }
    }

    $explodeinto =~ /^(.*)$/;
    $explodeinto = $1;
    unless (chdir $explodeinto) {    # TAINT
        Baruwa::Scanner::Log::WarnLog(
            "Could not chdir to %s just before unpacking "
              . "extra message parts",
            $explodeinto
        );
        return;
    }

    # -------------------------------
    # If the MIME boundary exists and is "" then remove the entire message.
    # The top level must be multipart/mixed
    if (defined($entity) && $entity->head) {
        if ($entity->is_multipart || $entity->head->mime_type =~ /^multipart/i)
        {   my $boundary = $entity->head->multipart_boundary;

            #print STDERR "Boundary is \"$boundary\"\n";
            if ($boundary eq "" || $boundary eq "\"\"" || $boundary =~ /\s$/) {
                my $cantparse =
                  Baruwa::Scanner::Config::LanguageValue($this, 'cantanalyze');
                $this->{allreports}{""} .= "$baruwaname: $cantparse\n";
                $this->{alltypes}{""}   .= 'c';
                $this->{otherinfected}++;

                #print STDERR "Found error\n";
            }
        }
    }

    # -------------------------------

    # Now try to extract messages from text files as they might be things
    # we didn't manage to extract first time around.
    # And try to expand .tar.gz .tar.z .tgz .zip files.
    # We will then scan everything from inside them.
    my ($allowpasswords, $couldnotreadmesg, $passwordedmesg, $toodeepmesg);
    my ($insistpasswords, $nonpasswordedmesg);
    $allowpasswords = Baruwa::Scanner::Config::Value('allowpasszips', $this);
    $allowpasswords = ($allowpasswords !~ /0/) ? 1 : 0;
    $insistpasswords = Baruwa::Scanner::Config::Value('insistpasszips', $this);
    $insistpasswords = ($insistpasswords !~ /0/) ? 1 : 0;
    $couldnotreadmesg =
      Baruwa::Scanner::Config::LanguageValue($this, 'unreadablearchive');
    $passwordedmesg =
      Baruwa::Scanner::Config::LanguageValue($this, 'passwordedarchive');
    $nonpasswordedmesg =
      Baruwa::Scanner::Config::LanguageValue($this, 'nonpasswordedarchive');
    $toodeepmesg =
      Baruwa::Scanner::Config::LanguageValue($this, 'archivetoodeep');

    #print STDERR "About to unpack parts and archives\n";
    $this->ExplodePartAndArchives(
        $explodeinto,
        Baruwa::Scanner::Config::Value('maxzipdepth', $this),
        $allowpasswords,
        $insistpasswords,
        $couldnotreadmesg,
        $passwordedmesg,
        $nonpasswordedmesg,
        $toodeepmesg,
        $baruwaname
    );

    # Now unpack all the *.doc Word files if they want me to
    if (Baruwa::Scanner::Config::Value('addtextofdoc', $this) =~ /1/) {

        # Find all the *.doc files in the attachments we now have
        my %nullhash = ();
        my $docfiles = Baruwa::Scanner::Antiword::FindDocFiles($this->{entity},
            $this->{entity}, \%nullhash);

        # For each one, create the *.txt file using antiword.
        #foreach my $docfile (@docfiles) {
        my ($docfile, $parent);
        while (($docfile, $parent) = each %$docfiles) {

         #foreach my $docfile (@docfiles) {
         #print STDERR "Antiwording $docfile,$parent into $explodeinto\n";
         #Baruwa::Scanner::Antiword::RunAntiword($explodeinto, $docfile, $this);
            Baruwa::Scanner::Antiword::RunAntiword($explodeinto, $docfile,
                $parent, $this);
        }
    }

    # Check we haven't filled the disk. Remove this message if we have, so
    # that we can continue processing the other messages.
    my $dir = Baruwa::Scanner::Config::Value("incomingworkdir");
    my $df = df($dir, 1024);
    if ($df) {
        my $freek = $df->{bavail};
        if (defined($freek) && $freek < 100 && $freek >= 0) {
            Baruwa::Scanner::Log::WarnLog(
                "Message %s is too big for available disk space in %s, skipping it",
                $this->{id}, $dir
            );
            my @toclear = ($this->{id});
            $workarea->ClearIds(\@toclear)
              ;    # Delete attachments we might have made
            $this->DropFromBatch();
            return;
        }
    }

    # Set the owner and group on all the extracted files
    my ($tmplist1, @tmplist);
    if ($workarea->{changeowner}) {
        foreach $tmplist1 (glob "$explodeinto/* $explodeinto/.*") {
            $tmplist1 =~ /(.*)/;
            $tmplist1 = $1;
            push @tmplist, $tmplist1 unless -d $tmplist1;
        }
        chown $workarea->{uid}, $workarea->{gid}, @tmplist if @tmplist;
    }

    # JKF 20100528 Now set the perms on all the extracted files
    my $workperms = Baruwa::Scanner::Config::Value('workperms') || '0600';

    # Make it octal with a leading zero if necessary
    $workperms = sprintf "0%lo", $workperms unless $workperms =~ /^0/;
    $workperms = oct($workperms);    # and back to decimal for chmod
    chmod $workperms, @tmplist if @tmplist;
}

sub ListLeafEntities {
    my ($message, $entity, $entitylist) = @_;

    my (@parts, $part);

    # Fallen off the tree?
    return unless $entity && defined($entity->head);

    # Found a leaf node
    if ($entity && !$entity->parts) {
        push @$entitylist, $entity;
        return;
    }

    # Walk down each sub-tree
    @parts = $entity->parts;
    foreach $part (@parts) {
        ListLeafEntities($message, $part, $entitylist);
    }
}

# Delete a given entity from the MIME entity tree.
# Have to walk the entire tree to do this.
# Bail out as soon as we've found it.
# Return 0 if DeleteEntity fell off a leaf node.
# Return 1 if DeleteEntity hit the TNEF node.
# Return 2 if DeleteEntity is just walking back up the tree.
sub DeleteEntity {
    my ($message, $entitytodelete, $subtree, $tnef) = @_;

    my (@parts, $part, @keep);

    #print STDERR "In DeleteEntity\n";

    # If we have a no-body message then replace the TNEF entity with an
    # empty attachment. Special case.
    if (scalar($message->{entity}) eq $tnef) {

        #print STDERR "Found message with no body but a TNEF attachment.\n";
        $part = MIME::Entity->build(
            Type     => "text/plain",
            Encoding => "quoted-printable",
            Data     => ["\n"]
        );
        push @keep, $part;
        $message->{entity}->parts(\@keep);
        $message->{bodymodified} = 1;

        #print STDERR "Replaced single part with empty text/plain attachment\n";
        return 2;
    }

    # Fallen off a leaf node?
    #print STDERR "Returning 0\n" unless $subtree && defined($subtree->head);
    #return 0 unless $entity && defined($entity->head);
    return 0 unless $subtree && defined($subtree->head);

    return 1 if $subtree eq $entitytodelete;

    if ($subtree && !$subtree->parts) {  # FIX FIX FIX !$entity->is_multipart) {
                                         # Found the TNEF entity at a leaf node?
        return 1 if scalar($subtree) eq $tnef;

        #print STDERR "Returning 2\n";
        return 2;
    }

    @parts = $subtree->parts;

    #print STDERR "Parts are " . join(',',@parts) . "\n";
    foreach $part (@parts) {
        my $foundit = DeleteEntity($message, $entitytodelete, $part, $tnef);

        #print STDERR "DeleteEntity = $foundit\n";
        push @keep, $part unless $foundit == 1;
    }

    # Make sure there is always at least 1 part.
    #print STDERR "Keep is " . join(',',@keep) . "\n";
    unless (@keep) {

        #print STDERR "Adding an empty text/plain\n";
        $part = MIME::Entity->build(
            Type     => "text/plain",
            Encoding => "quoted-printable",
            Data     => ["\n"]
        );
        push @keep, $part;
    }
    $subtree->parts(\@keep);
    $message->{bodymodified} = 1;

    # If there are no parts left, make this entity a singlepart entity
    $subtree->make_singlepart unless scalar(@keep);

    return 2;
}

# Quietly drop a message from the batch. Used when we run out of disk
# space.
sub DropFromBatch {
    my ($message) = @_;
    $message->{deleted}      = 1;
    $message->{gonefromdisk} = 1;    # Don't try to delete the original
    $message->{store}->Unlock();   # Unlock it so other processes can pick it up
    $message->{abandoned} = 1;   # This message was abandoned, re-try it n times
}

# Try to recursively unpack tar (with or without gzip) files and zip files.
# Extracts to a given maximum unpacking depth.
sub ExplodePartAndArchives {
    my ($this,           $explodeinto,       $maxlevels,
        $allowpasswords, $insistpasswords,   $couldnotreadmesg,
        $passwordedmesg, $nonpasswordedmesg, $toodeepmesg,
        $msname
    ) = @_;

    my ($dir, $file, $part, @parts, $buffer);
    my (%seenbefore, %seenbeforesize, $foundnewfiles);
    my ($size, $level, $ziperror, $tarerror, $silentviruses, $noisyviruses);
    my ($allziperrors, $alltarerrors, $textlevel, $failisokay);
    my ($linenum, $foundheader, $prevline, $line, $position, $prevpos,
        $nextpos);
    my ($cyclecounter, $rarerror, $create0files, $oleerror);

    $dir          = new DirHandle;
    $file         = new FileHandle;
    $level        = 0;                #-1;
    $textlevel    = 0;
    $cyclecounter = 0;
    $ziperror     = 0;
    $tarerror     = 0;

    # Do they only want encryption checking and nothing else?
    my $onlycheckencryption;
    $onlycheckencryption = 0;

    # More robust way of saying maxlevels==0 && allowpasswords==0;
    $onlycheckencryption = 1 if !$maxlevels && !$allowpasswords;
    $onlycheckencryption = 1 if !$maxlevels && $insistpasswords;
    $create0files        = 0;
    $create0files        = 1
      if Baruwa::Scanner::Config::Value('checkppafilenames', $this) =~ /1/;

    $silentviruses =
      ' ' . Baruwa::Scanner::Config::Value('silentviruses', $this) . ' ';
    $noisyviruses =
      ' ' . Baruwa::Scanner::Config::Value('noisyviruses', $this) . ' ';

    $dir->open($explodeinto);

    # $cyclecounter is a sanity check to ensure we don't loop forever
  OUTER: while ($cyclecounter < 30) {
        $cyclecounter++;
        $textlevel++;
        last if $level > $maxlevels;    # && $textlevel>1;
        $foundnewfiles = 0;
        $dir->rewind();
        @parts = $dir->read();

        #print STDERR "Level = $level\n";
        foreach $part (@parts) {
            next if $part eq '.' || $part eq '..';

            # Skip the entire loop if it's not what we are looking for

            $size = -s "$explodeinto/$part";
            next
              if $seenbefore{$part}
              && $seenbeforesize{$part} == $size;
            $seenbefore{$part}     = 1;
            $seenbeforesize{$part} = $size;

            #print STDERR "$level/$maxlevels Found new file $part\n";

            #print STDERR "Reading $part\n";
            # Added a . on the front to handle the type indicator character
            if ($part =~ /^.msg.*txt/ && $textlevel <= 2) {

                # Try and find hidden messages in the text files
                #print STDERR "About to read $explodeinto/$part\n";
                $file->open("$explodeinto/$part") or next;

         # Try reading the first few lines to see if they look like mail headers
                $linenum     = 0;
                $foundheader = 0;
                $prevline    = "";
                $prevpos     = 0;
                $nextpos     = 0;
                $line        = undef;

                for ($linenum = 0; $linenum < 30; $linenum++) {

                    #$position = $file->getpos();
                    $line = <$file>;
                    last unless defined $line;
                    $nextpos += length $line;

                    # Must have 2 lines of header
                    # prevline looks like Header:
                    # line     looks like       setting
                    #          or         Header:
                    if (   $prevline =~ /^[^:\s]+: /
                        && $line =~ /(^\s+\S)|(^[^:\s]+: )/) {   #|(^\s+.*=)/) {
                         #print STDERR "Found header start at \"$prevline\"\n and \"$line\"\n";
                        $foundheader = 1;
                        last;
                    }
                    $prevline = $line;
                    $prevpos  = $position;
                    $position = $nextpos;
                }

                if ($foundheader) {

                    # Check all lines are header lines up to next blank line
                    my ($num, $reallyfoundheader);
                    $reallyfoundheader = 0;

                    # Check for a maximum of 30 lines of headers
                    foreach $num (0 .. 30) {
                        $line = <$file>;
                        last unless defined $line;

                        # Must have a valid header line
                        #print STDERR "Examining: \"$line\"\n";
                        next if $line =~ /(^\s+\S)|(^[^:\s]+: )/;

                        #print STDERR "Not a header line\n";
                        # Or a blank line
                        if ($line =~ /^[\r\n]*$/) {
                            $reallyfoundheader = 1;
                            last;
                        }

                        #print STDERR "Not a blank line\n";
                        # Non-header line, so it isn't a valid message part
                        $reallyfoundheader = 0;
                        last;
                    }

                    #print STDERR "Really found header = $reallyfoundheader\n";
                    if ($reallyfoundheader) {

                        # Rewind to the start of the header
                        #$file->setpos($prevpos);
                        seek $file, $prevpos, 0;

                        #print STDERR "First line is \"" . <$file> . "\"\n";

                        # Setup everything for the MIME parser
                        my $parser = MIME::Parser->new;
                        my $filer =
                          Baruwa::Scanner::FileInto->new($explodeinto);

             # Over-ride the default default character set handler so it does it
             # much better than the MIME-tools default handling.
                        MIME::WordDecoder->default->handler(
                            '*' => \&WordDecoderKeep7Bit);

                   #print STDERR "Exploding message " . $this->{id} . " into " .
                   #             $explodeinto . "\n";
                        $parser->filer($filer);
                        $parser->extract_uuencode(1);    # uue is off by default
                        $parser->output_to_core('NONE'); # everything into files

                        # Do the actual parsing
                        #print STDERR "About to parse\n";
                        my $entity = eval {$parser->parse($file)};

                        #print STDERR "Done the parse\n";

                        # We might have created new files that need parsing
                        $foundnewfiles = 1;
                        next OUTER;
                    }
                }
                $file->close;
            }

            # Not got anything to do?
            next if !$maxlevels && $allowpasswords;

            #$level++;
            next if $level > $maxlevels;

            # Find all the zip files
            #print STDERR "Looking at $explodeinto/$part\n";
            #next if Baruwa::Scanner::Config::Value('filecommand', $this) eq "";
            next unless $file->open("$explodeinto/$part");

            #print STDERR "About to read 4 bytes\n";
            unless (read($file, $buffer, 4) == 4) {

                #print STDERR "Very short file $part\n";
                $file->close;
                next;
            }
            my $uudfilename = "";
            $uudfilename = FindUUEncodedFile($file)
              if Baruwa::Scanner::Config::Value('lookforuu', $this) =~ /1/;

            #$file->close;
            $failisokay = 0;
            if ($buffer =~ /^MZ/) {
                $failisokay = 1;
            }
            $file->close, next
              unless $buffer eq "PK\003\004"
              || $buffer eq "Rar!"
              || $part =~ /\.rar$/
              || defined($uudfilename)
              || $failisokay;

            #print STDERR "Found a zip or rar file\n" ;
            $file->close, next
              unless Baruwa::Scanner::Config::Value('findarchivesbycontent',
                $this)
              || $part =~
              /\.(tar\.g?z|taz|tgz|tz|zip|exe|rar|uu|uue|doc|xls|ppt|dot|xlt|pps)$/i;
            $foundnewfiles = 1;

            #print STDERR "Unpacking $part at level $level\n";

            if ($uudfilename ne "") {

          # It cannot be a zip or a rar, so skip the checks for them.
          # Oh yes it can! Do all the checks.
          # Ignore the return value, don't care if uudecode fails, it was
          # probably just a false positive on the uuencoded-data locator.
          #print STDERR "About to unpackuue $part into $uudfilename\n";
          # uudfilename does not have the type indicator character on the front.
                $this->UnpackUUE($part, $explodeinto, $file, $uudfilename);
            }
            $file->close;

 # if (isB64Encoded("$explodeinto/$part")) {
 #   Baruwa::Scanner::Log::WarnLog("Found Base64 encoded part $part, decoding");
 #   ConvertB64Part($part, $explodeinto);
 # }
 # Is it a zip file, in which case unpack the zip
            $ziperror = "";

            #print STDERR "About to unpackzip $part\n";
            $ziperror =
              $this->UnpackZip($part, $explodeinto, $allowpasswords,
                $insistpasswords, $onlycheckencryption, $create0files);

            #print STDERR "* * * * * * * Unpackzip $part returned $ziperror\n";
            # If unpacking as a zip failed, try it as a rar
            $rarerror = "";
            if ($part =~ /\.rar$/i || $buffer eq "Rar!" or $buffer =~ /^MZ[P]?/)
            {   $rarerror =
                  $this->UnpackRar($part, $explodeinto, $allowpasswords,
                    $insistpasswords, $onlycheckencryption, $create0files);
            }

            # And if that failed, try it as a Microsoft OLE
            $oleerror = "";
            if (Baruwa::Scanner::Config::Value('unpackole', $this)
                && (   $buffer eq "\320\317\021\340"
                    || $buffer eq "\376\067\0\043"
                    || $buffer eq "\x31\xbe\0\0"
                    || $buffer eq "\0\0\xbc\x31"
                    || $buffer eq "PO^Q"
                    || $buffer eq "\333\245-\0")
              ) {
                $oleerror =
                  $this->UnpackOle($part, $explodeinto, $allowpasswords,
                    $insistpasswords, $onlycheckencryption, $create0files);
            }

            $tarerror = "";
            $tarerror =
              0    # $this->UnpackTar($part, $explodeinto, $allowpasswords)
              if $ziperror || $part =~ /(tar\.g?z|tgz)$/i;

            #print STDERR "In inner: \"$part\"\n";
            if ($ziperror eq "nonpassword" || $rarerror eq "nonpassword") {

                # Trim off leading type indicator character for logging.
                my $f = substr($part, 1);
                Baruwa::Scanner::Log::WarnLog(
                    "Non-password-protected archive (%s) in %s",
                    $f, $this->{id});
                $this->{allreports}{$part} .= "$msname: $nonpasswordedmesg\n";
                $this->{alltypes}{$part} .= 'c';    # JKF 19/12/2007 'p'
                $this->{nonpasswordprotected} = 1;
                $this->{otherinfected}        = 1;

         # JKF 19/12/2007 $this->{passwordinfected} = 1;
         # JKF 19/12/2007 and comment out the previous line about otherinfected.
                $this->{cantdisinfect} =
                  1;    # Don't even think about disinfecting this!
                $this->{silent} = 1
                  if $silentviruses =~ /\sZip-NonPassword|All-Viruses\s/i;
                $this->{noisy} = 1 if $noisyviruses =~ /\sZip-NonPassword\s/i;
            } elsif ($ziperror eq "password" || $rarerror eq "password") {

                # Trim off leading type indicator character for logging.
                my $f = substr($part, 1);
                Baruwa::Scanner::Log::WarnLog(
                    "Password-protected archive (%s) in %s",
                    $f, $this->{id});
                $this->{allreports}{$part} .= "$msname: $passwordedmesg\n";
                $this->{alltypes}{$part} .= 'c';    # JKF 19/12/2007 'p'
                $this->{passwordprotected} = 1;
                $this->{otherinfected}     = 1;
                $this->{cantdisinfect} =
                  1;    # Don't even think about disinfecting this!
                $this->{silent} = 1
                  if $silentviruses =~ /\sZip-Password|All-Viruses\s/i;
                $this->{noisy} = 1 if $noisyviruses =~ /\sZip-Password\s/i;
            } elsif ($ziperror && $tarerror && $rarerror && !$failisokay) {

                # Trim off leading type indicator character for logging.
                my $f = substr($part, 1);
                Baruwa::Scanner::Log::WarnLog("Unreadable archive (%s) in %s",
                    $f, $this->{id});
                $this->{allreports}{$part} .= "$msname: $couldnotreadmesg\n";
                $this->{alltypes}{$part}   .= 'c';
                $this->{otherinfected} = 1;
            }
        }

        #print STDERR "In outer: \"$part\"\n";
        last if !$foundnewfiles || $level > $maxlevels;
        $dir->rewind;

#print STDERR "Rewinding, Incrementing level from $level to " . ($level+1) . "\n";
        $level++;
    }

    #print STDERR "Level=$level($maxlevels)\n";
    #print STDERR "Onlycheckencryption=$onlycheckencryption\n";
    if ($level > $maxlevels && !$onlycheckencryption && $maxlevels) {
        Baruwa::Scanner::Log::WarnLog(
            "Files hidden in very deeply nested archive " . "in %s",
            $this->{id});
        $this->{allreports}{""} .= "$msname: $toodeepmesg\n";
        $this->{alltypes}{""}   .= 'c';
        $this->{otherinfected}++;
    }
}

# Search the given filehandle for signs that this could contain uu-encoded data
# Return the filename if found, undef otherwise. Also return the open file
# handle.
sub FindUUEncodedFile {
    my $fh = shift;

    my ($mode, $file);
    my $linecounter = 0;

    seek $fh, 0, 0;    # Rewind the file to the start
    while (<$fh>) {
        if (/^begin(.*)/) {
            my $modefile = $1;
            if ($modefile =~ /^(\s+(\d+))?(\s+(.*?\S))?\s*\Z/) {
                ($mode, $file) = ($2, $4);
            }
            Baruwa::Scanner::Log::InfoLog("Found uu-encoded file %s", $file);
            last;
        }
        $linecounter++;
        seek($fh, 0, 0), return undef if $linecounter > 50;
    }
    return $file;
}

# We now have a uuencoded file to decode. We have a target filename we have
# read from the uuencode header.
# uudecoded does *not* have the type indicator character. Add a 'u' to get
# the output filename.
sub UnpackUUE {
    my $this = shift;
    my ($uuencoded, $explodeinto, $uuehandle, $uudecoded) = @_;

    # Trim off leading type indicator for logging
    my $attachmentname = substr($uuencoded, 1);

    # Set up all the tree structures for cross-referencing
    my $safename = $this->MakeNameSafe('u' . $uudecoded, $explodeinto);
    Baruwa::Scanner::Log::InfoLog(
        "Unpacking UU-encoded file %s to %s in message %s",
        $attachmentname, substr($safename, 1),
        $this->{id}
    );
    $this->{file2parent}{$uudecoded}   = $uuencoded;
    $this->{file2parent}{$safename}    = $uuencoded;
    $this->{file2safefile}{$uudecoded} = $safename;
    $this->{safefile2file}{$safename}  = $uudecoded;

    $safename = "$explodeinto/$safename";

    my $out = new FileHandle;
    unless ($out->open("> $safename")) {
        Baruwa::Scanner::Log::WarnLog(
            "Unpacking UU-encoded file %s, could not create target file %s in message %s",
            $this->MakeNameSafe($uuencoded, $explodeinto),
            $safename,
            $this->{id}
        );
        return;
    }

    while (<$uuehandle>) {
        last if /^end/;
        next if /[a-z]/;
        next unless int((((ord() - 32) & 077) + 2) / 3) == int(length() / 4);
        $out->print(unpack('u', $_));
    }
    $out->close;
}

# Unpack a rar file into the named directory.
# Return 1 if an error occurred, else 0.
# Return 0 on success.
# Return "password" if a member was password-protected.
# Very much like UnpackZip except it uses the external "unrar" command.
sub UnpackRar {
    my ($this, $zipname, $explodeinto, $allowpasswords, $insistpasswords,
        $onlycheckencryption, $touchfiles)
      = @_;

    my ($zip,         @members,     $member,     $name,    $fh,
        $safename,    $memb,        $check,      $junk,    $unrar,
        $IsEncrypted, $PipeTimeOut, $PipeReturn, $NameTwo, $HasErrors,
        $member2,     $Stuff,       $BeginInfo,  $EndInfo, $ParseLine,
        $what,        $nopathname
    );

    # Timeout value for unrar is currently the same as that of the file
    # command + 20. Julian, when you add the filetimeout to the config file
    # perhaps you should think about adding a maxcommandexecutetime setting
    # as well
    $PipeTimeOut = Baruwa::Scanner::Config::Value('unrartimeout');
    $unrar       = Baruwa::Scanner::Config::Value('unrarcommand');
    return 1 unless $unrar && -x $unrar;

    #Baruwa::Scanner::Log::WarnLog("UnPackRar Testing : %s", $zipname);

    # This part lists the archive contents and makes the list of
    # file names within. "This is a list verbose option"
    $memb = SafePipe("$unrar v -p- '$explodeinto/$zipname' 2>&1", $PipeTimeOut);

    $Stuff     = "";
    $BeginInfo = 0;
    $EndInfo   = 0;
    $memb =~ s/\r//gs;
    my @test = split /\n/, $memb;
    $memb = '';

    # Have to parse the output from the 'v' command and parse the information
    # between the ----------------------------- lines
    foreach $what (@test) {

        # If we haven't hit any ------- lines at all, and we are prompted for
        # a password, then the whole archive is password-protected.
        unless ($BeginInfo || $EndInfo) {
            if ($what =~ /^Encrypted file:/i && !$allowpasswords) {
                Baruwa::Scanner::Log::WarnLog("Password Protected RAR Found");
                return "password";
            }
        }

        # Have we already hit the beginng and now find another ------ string?
        # If so then we are at the end
        $EndInfo = 1 if $what =~ /^-/ && $BeginInfo;

        # if we are after the begning but haven't reached the end,
        # then process this line
        if ($BeginInfo && !$EndInfo) {

            # Parse Line
            $Stuff = $what;
            $Stuff =~ s/^\s+|\s+$//g;
            chomp($Stuff);
            my ($RAttrib, $RSize, $RPacked, $RRatio,
                $RDate,   $RTime, $RCrc,    $RName
            ) = split /\s+/, $Stuff;
            $memb .= "$RName\n";
            $Stuff = '';
        }

        # If we have a line full of ---- and $BeginInfo is not set then
        # we are at the first and we need to set $BeginInfo so next pass
        # begins processing file information
        if ($what =~ /^-/ && !$BeginInfo) {
            $BeginInfo = 1;
        }
    }

    # Remove returns from the output string, exit if the archive is empty
    # or the output is empty

    $memb =~ s/\r//gs;
    return 1
      if $memb ne ''
      && $memb =~ /(No files to extract|^COMMAND_TIMED_OUT$)/si;

    return 0
      if $memb eq '';    # JKF If no members it probably wasn't a Rar self-ext
     #Baruwa::Scanner::Log::DebugLog("Unrar : Archive Testing Completed On : %s",
     #                           $memb);

    @members = split /\n/, $memb;

    $fh = new FileHandle;

    foreach $member2 (@members) {
        $IsEncrypted = 0;
        $HasErrors   = 0;

        #Baruwa::Scanner::Log::InfoLog("Checking member %s",$member2);
        # Test the current file name to see if it's password protected
        # and capture the output. If the command times out, then return

        next if $member2 eq "";
        $member = quotemeta $member2;

        #print STDERR "Member is ***$member***\n";
        $check =
          SafePipe("$unrar  t -p- -idp '$explodeinto/$zipname' $member 2>&1",
            $PipeTimeOut);

        #print STDERR "Point 1\n";
        return 1 if $check =~ /^COMMAND_TIMED_OUT$/;

        # Check for any error with this file. Format is FileName - Error string
        if ($check =~ /$member\s+-\s/i) {
            Baruwa::Scanner::Log::WarnLog("Unrar: Error in file: %s -> %s",
                $zipname, $member);
            $HasErrors = 1;
        }

        $check =~ s/\n/:/gsi;

        #Baruwa::Scanner::Log::WarnLog("Got : %s", $check);

        # If we get the string Encrypted then we have found a password
        # protected archive and we handle it the same as zips are handled

        if ($check =~ /\bEncrypted file:\s.+\(password incorrect/si) {
            $IsEncrypted = 1;
            Baruwa::Scanner::Log::WarnLog("Password Protected RAR Found");

            #print STDERR "Checking member " . $member . "\n";
            #print STDERR "******** Encryption = " . $IsEncrypted . "\n";
            return "password" if !$allowpasswords && $IsEncrypted;
        } else {
            if ($insistpasswords) {
                Baruwa::Scanner::Log::WarnLog(
                    "Non-Password Protected RAR Found");
                return "nonpassword";
            }
        }

        # If they don't want to extract, but only check for encryption,
        # then skip the rest of this as we don't actually want the files
        # checked against the file name/type rules
        next if $onlycheckencryption;

        $name = $member2;

        #print STDERR "UnPackRar : Making Safe Name from $name\n";

        # There is no facility to change the output name for a rar file
        # but we can rename rename the files inside the archive
        # prefer to use $NameTwo because there is no path attached
        # $safename is guaranteed not to exist, but NameTwo gives us the
        # filename without any directory information, which we use later.
        $nopathname = $name;
        $nopathname =~ s/^.*\///;
        $safename = $this->MakeNameSafe('r' . $nopathname, $explodeinto);
        $NameTwo  = $safename;
        $NameTwo  = $1 if $NameTwo =~ /([^\/]+)$/;

        #Baruwa::Scanner::Log::InfoLog("UnPackRar: Member : %s", $member);
        #print STDERR "UnPackRar : Safe Name is $safename\n";

        #Baruwa::Scanner::Log::InfoLog("UnPackRar: SafeName : %s", $safename);
        $this->{file2parent}{$name}       = $zipname;
        $this->{file2parent}{$safename}   = $zipname;
        $this->{file2safefile}{$name}     = $safename;
        $this->{safefile2file}{$safename} = $name;

        #print STDERR "Archive member \"$name\" is now \"$safename\"\n";

        $safename = "$explodeinto/$safename";

        $PipeReturn = '';
        $?          = 0;
        if (!$IsEncrypted && !$HasErrors) {

            #print STDERR "Expanding ***$member***\ninto ***$NameTwo***\n";
            $PipeReturn = SafePipe(
                "$unrar p -y -inul -p- -idp '$explodeinto/$zipname' $member > \"$NameTwo\"",
                $PipeTimeOut
            );
            unless ("$?" == 0 && $PipeReturn ne 'COMMAND_TIMED_OUT') {

# The rename operation failed!, so skip the extraction of a
# potentially bad file name.
# JKF Temporary testing code
#Baruwa::Scanner::Log::WarnLog("UnPackRar: RC: %s PipeReturn : ",$?,$PipeReturn);
                Baruwa::Scanner::Log::WarnLog(
                    "UnPackRar: Could not rename or use "
                      . "safe name in Extract, NOT Unpacking file %s",
                    $safename
                );
                next;
            }

#Baruwa::Scanner::Log::InfoLog("UnPackRar: Done...., got %d and %s", $?, $PipeReturn);
        }

      #Baruwa::Scanner::Log::WarnLog("RC = %s : Encrypt = %s : PipeReturn = %s",
      #                          $?,$IsEncrypted,$PipeReturn );
        unless ("$?" == 0
            && !$HasErrors
            && !$IsEncrypted
            && $PipeReturn ne 'COMMAND_TIMED_OUT') {

            # If we got an error, or this file is encrypted create a zero-length
            # file so the filename tests will still work.
            Baruwa::Scanner::Log::WarnLog(
                "Unrar : Encrypted Or Extract Error Creating" . " 0 length %s",
                $NameTwo
            );
            $touchfiles && $fh->open(">$safename") && $fh->close();
        }
    }
    return 0;
}

# Modified Julian's code from SweepOther.pm
# Changed to allow execution of any given command line with a time
# control. This could replace any call to system or use of backticks
#
# $Cmd         = command line to execute
# $timeout     = max time in seconds to allow execution
#
sub SafePipe {
    my ($Cmd, $TimeOut) = @_;

    my ($Kid, $pid, $TimedOut, $Str);
    $Kid      = new FileHandle;
    $TimedOut = 0;

    #print STDERR "SafePipe : Command : $Cmd\n";
    #print STDERR "SafePipe : TimeOut : $TimeOut\n";

    $? = 0;    # Make sure there's no junk left in here

    eval {
        die "Can't fork: $!" unless defined($pid = open($Kid, '-|'));
        if ($pid) {

            # In the parent

            # Set up a signal handler and set the alarm time to the timeout
            # value passed to the function

            local $SIG{ALRM} = sub {$TimedOut = 1; die "Command Timed Out"};
            alarm $TimeOut;

            # while the command is running we will collect it's output
            # in the $Str variable. We don't process it in any way here so
            # whatever called us will get back exactly what they would have
            # gotten with a system() or backtick call

            #Baruwa::Scanner::Log::DebugLog("SafePipe : Processing %s", $Cmd);

            while (<$Kid>) {
                $Str .= $_;

                #print STDERR "SafePipe : Processing line \"$_\"\n";
            }

            #Baruwa::Scanner::Log::DebugLog("SafePipe : Completed $Cmd");
            #print STDERR "SafePipe : Returned $PipeReturnCode\n";

            $pid = 0;    # 2.54
            alarm 0;

            # Workaround for bug in perl shipped with Solaris 9,
            # it doesn't unblock the SIGALRM after handling it.
            eval {
                my $unblockset = POSIX::SigSet->new(SIGALRM);
                sigprocmask(SIG_UNBLOCK, $unblockset)
                  or die "Could not unblock alarm: $!\n";
            };
        } else {

            # In the child
            POSIX::setsid();

          # Execute the command via an exec call, bear in mind this will only
          # capture STDIN so if you need STDERR, or both you have to handle, for
          # example, 2>&1 as part of the command line just as you would with
          # system() or backticks
          #
          #the line following the
          # call should *never* be reached unless the call it's self fails
          #print STDERR "SafePipe in child exec $Cmd\n";

            my @args = ("$Cmd");

            #exec $Cmd or print STDERR "SafePipe :  failed to execute $Cmd\n";

            open STDIN, "< /dev/null";

            exec map {m/(.*)/} @args
              or
              Baruwa::Scanner::Log::WarnLog("SafePipe :  failed to execute %s",
                $Cmd);

       #Baruwa::Scanner::Log::DebugLog("SafePipe in Message.pm : exec failed " .
       #                           "for $Cmd");
            exit 1;
        }
    };
    alarm 0;    # 2.53

    #Baruwa::Scanner::Log::DebugLog("SafePipe in Message.pm : Completed $Cmd");
    #Baruwa::Scanner::Log::WarnLog("Returned Code : %d", $?);
    # Catch failures other than the alarm
    Baruwa::Scanner::Log::WarnLog(
        "SafePipe in Message.pm : $Cmd failed with real error: $@")
      if $@ and $@ !~ /Command Timed Out/;

    #print STDERR "SafePipe : pid = $pid and \@ = $@\n";

    # In which case any failures must be the alarm
    if ($@ or $pid > 0) {

        # Kill the running child process
        my ($i);
        kill -15, $pid;

        # Wait for up to 5 seconds for it to die
        for ($i = 0; $i < 5; $i++) {
            sleep 1;
            waitpid($pid, &POSIX::WNOHANG);
            ($pid = 0), last unless kill(0, $pid);
            kill -15, $pid;
        }

        # And if it didn't respond to 11 nice kills, we kill -9 it
        if ($pid) {
            kill -9, $pid;
            waitpid $pid, 0;    # 2.53
        }
    }

    # If the command timed out return the string below, otherwise
    # return the command output in $Str
    return $Str unless $TimedOut;

    Baruwa::Scanner::Log::WarnLog("Safepipe in Message.pm : %s timed out!",
        $Cmd);
    return "COMMAND_TIMED_OUT";
}

# Unpack a zip file into the named directory.
# Return 1 if an error occurred, else 0.
# Return 0 on success.
# Return "password" if a member was password-protected.
my $zipadd = 0;    #TODO: Figure out a better way to do this

sub UnpackZip {
    my ($this, $zipname, $explodeinto, $allowpasswords, $insistpasswords,
        $onlycheckencryption, $touchfiles)
      = @_;

    my ($zip, @members, $member, $name, $fh, $safename);

    #print STDERR "Unpacking $zipname\n";
    my $tmpname = "$explodeinto/$zipname";
    $tmpname =~ /^(.*)$/;
    $tmpname = $1;
    return 1 if -s $tmpname == 4_237_4;    # zip of death?
    Archive::Zip::setErrorHandler(sub { });    # Stop error messages
    return 1 unless $zip     = Archive::Zip->new("$explodeinto/$zipname");
    return 1 unless @members = $zip->members();

    #print STDERR "Members are " . join(',',@members) . "\n";

    $fh = new FileHandle;

    foreach $member (@members) {

        #print STDERR "Checking member " . $member->fileName() . "\n";
        #print STDERR "******** Encryption = " . $member->isEncrypted() . "\n";
        return "password" if !$allowpasswords && $member->isEncrypted();
        return "nonpassword" if $insistpasswords && !($member->isEncrypted());

        # If they don't want to extract, but only check for encryption,
        # then skip the rest of this as we don't actually want the files.
        next if $onlycheckencryption;

        # Untaint member's attributes.
        # Fix to use workperms in preference by Rick Cooper rcooper@dwford.com
        my $workperms = Baruwa::Scanner::Config::Value('workperms') || '0600';

 # Make it octal with a leading zero if necessary by Curu Wong prinbra@gmail.com
        $workperms = sprintf("0%lo", $workperms) unless $workperms =~ /^0/;
        $workperms = oct($workperms);    # and back to decimal for chmod
        $member->unixFileAttributes($workperms);

        $name = $member->fileName();

        # Trim off any leading directory path
        $name =~ s#^.*/##;
        $zipadd = ($zipadd + 1) % 100;
        $safename = $this->MakeNameSafe('z' . $zipadd . $name, $explodeinto);

        #print STDERR "MakeNameSafe(z + $zipadd + $name) = $safename\n";
        $this->{file2parent}{$name}       = $zipname;
        $this->{file2parent}{$safename}   = $zipname;
        $this->{file2safefile}{$name}     = $safename;
        $this->{safefile2file}{$safename} = $name;

        #print STDERR "Archive member \"$name\" is now \"$safename\"\n";
        # Untaint output filename
        $safename =~ /^(.*)$/;
        $safename = $1;

        #print STDERR "About to extract $member to $safename\n";
        unless ($zip->extractMemberWithoutPaths($member, $safename) == AZ_OK) {

           # Create a zero-length file if extraction failed
           # so the filename tests will still work.
           #print STDERR "Done passworded extraction of $member to $safename\n";
            $touchfiles && $fh->open(">$safename") && $fh->close();
        }

        #print STDERR "Done extraction of $member to $safename\n";
    }
    return 0;
}

# Unpack an ole file into the named directory.
# Return 1 if an error occurred, else 0.
# Return 0 on success.
# Return "password" if a member was password-protected.
# Currently does not support password-encryption, will merely not create
# any members.
sub UnpackOle {
    my ($this, $olename, $explodeinto, $allowpasswords, $insistpasswords,
        $onlycheckencryption, $touchfiles)
      = @_;

    my ($ole, $tree, @NativeFilenames);

    #print STDERR "Unpacking $explodeinto/$olename\n";
    eval {
        #return 1 unless $ole = OLE::Storage_Lite::PPS->new(1,2,3,4,5,6,7,8,
        #                                                   9,10,11,12,13);
        my $tmpnam = "$explodeinto/$olename";
        $tmpnam =~ /^(.*)$/;
        $tmpnam = $1;
        return 1 unless $ole = OLE::Storage_Lite->new($tmpnam);
        return 1 unless $tree = $ole->getPpsTree(1);    # (1) => Get Data too

        my $level = 0;
        @NativeFilenames =
          $this->OleUnpackTree($tree, 0, \$level, $explodeinto, $olename);
    };

    if ($@) {

      #print STDERR "Skipping OLE document unpacking due to analysis failure\n";
        Baruwa::Scanner::Log::WarnLog(
            "Skipping OLE document unpacking due to OLE analysis failure");
    } else {
        $this->OleUnpackPackages($explodeinto, $olename, @NativeFilenames);
    }

    return 0;
}

# Each embedded object in an OLE tree is packages in a special format.
# This converts a list of named filenames into their original data.
sub OleUnpackPackages {
    my ($this, $explodeinto, $parentname, @NativeFilenames) = @_;

    my ($infh, $byte, $number, $buffer, $outname);
    my ($finished, $length, $size);

  OLEFILE: foreach my $inname (@NativeFilenames) {
        $size = -s "$explodeinto/$inname";

     # Start with the simple version of the format which is just 4 bytes of junk
        close $infh if $infh;
        $infh = new FileHandle;
        sysopen $infh, "$explodeinto/$inname", O_RDONLY;
        sysseek $infh, 4, SEEK_SET;    # Skip 1st 4 bytes
        sysread($infh, $buffer, $size);
        my $outfh = new FileHandle;
        $outname = $inname . "_tmp";
        my $outsafe = $this->MakeNameSafe('o' . $outname, $explodeinto);
        sysopen $outfh, "$explodeinto/$outsafe", (O_CREAT | O_WRONLY);
        syswrite $outfh, $buffer, $size if $outfh;
        close $outfh if $outfh;

        # Set up Baruwa data structures
        $this->{file2parent}{$outname} = $parentname;
        $this->{file2parent}{$outsafe} = $parentname;
        $this->{file2parent}{substr($outsafe, 1)} = $parentname;  # Why not? :-)
        $this->{file2safefile}{$outname} = $outsafe;
        $this->{safefile2file}{$outsafe} = $outname;

        # Now do the version which uses and analyses the full header.
        $byte   = "";
        $buffer = "";
        sysseek $infh, 6, SEEK_SET;    # Skip 1st 6 bytes
        $outname  = "";
        $finished = 0;
        $length   = 0;
        until ($byte eq "\0" || $finished || $length > 1000) {

            # Read a C-string into $outname
            sysread($infh, $byte, 1) or $finished = 1;
            $outname .= $byte;
            $length++;
        }
        next OLEFILE if $length > 1000;    # Bail out if it went wrong
        $finished = 0;
        $byte     = 1;
        $length   = 0;
        until ($byte eq "\0" || $finished || $length > 1000)
        {                                  # Throw away a C-string
            sysread($infh, $byte, 1) or $finished = 1;
            $length++;
        }
        next OLEFILE if $length > 1000;    # Bail out if it went wrong
        sysseek $infh, 4, Fcntl::SEEK_CUR or next OLEFILE;   # Skip next 4 bytes
        sysread $infh, $number, 4 or next OLEFILE;
        $number = unpack 'V', $number;

        #print STDERR "Skipping $number bytes of header filename\n";
        if ($number > 0 && $number < 1_000_000) {
            sysseek $infh, $number,
              Fcntl::SEEK_CUR;    # Skip the next bit of header (C-string)
        } else {
            next OLEFILE;
        }
        sysread $infh, $number, 4 or next OLEFILE;
        $number = unpack 'V', $number;

        #print STDERR "Reading $number bytes of file data\n";
        sysread $infh, $buffer, $number
          if $number > 0 && $number < $size;    # Sanity check
        $outfh = new FileHandle;
        $outsafe = $this->MakeNameSafe('o' . $outname, $explodeinto);
        sysopen $outfh, "$explodeinto/$outsafe", (O_CREAT | O_WRONLY)
          or next OLEFILE;
        if ($number > 0 && $number < 1_000_000_000)
        {                                       # Number must be reasonable!
            syswrite $outfh, $buffer, $number or next OLEFILE;
        }
        close $outfh;

        # Set up Baruwa data structures
        $this->{file2parent}{$outname}   = $parentname;
        $this->{file2parent}{$outsafe}   = $parentname;
        $this->{file2safefile}{$outname} = $outsafe;
        $this->{safefile2file}{$outsafe} = $outname;
    }
    close $infh if $infh;
}

# Unpack the tree of OLE objects in this Office Document
my %OleNum2Type = (1 => 'DIR', 2 => 'FILE', 5 => 'ROOT');

sub OleUnpackTree {
    my ($this, $tree, $level, $Ttl, $explodeinto, $parentname) = @_;

    my (@OleNative);

    my $olename = OLE::Storage_Lite::Ucs2Asc($tree->{Name});
    my $safename = $this->MakeNameSafe('o' . $olename, $explodeinto);

    #print STDERR "Unpacking OLE file to $safename\n";

    # Save the data out to a new file. Probably not as fast as possible.
    if ($OleNum2Type{$tree->{Type}} eq 'FILE') {

        # Added leading . to account for type indicator character
        if ($safename =~ /^.Ole.*Native/i) {
            my $fh = new FileHandle;
            sysopen $fh, "$explodeinto/$safename", (O_CREAT | O_WRONLY);
            syswrite $fh, $tree->{Data};
            close $fh;

            # Find all the embedded objects
            push @OleNative, $safename if $safename =~ /^.Ole.*Native/;

            # Set up Baruwa data structures
            $this->{file2parent}{$olename}    = $parentname;
            $this->{file2parent}{$safename}   = $parentname;
            $this->{file2safefile}{$olename}  = $safename;
            $this->{safefile2file}{$safename} = $olename;
        }
    }

    ${$Ttl}++;
    foreach my $child (@{$tree->{Child}}) {
        push @OleNative,
          $this->OleUnpackTree($child, $level + 1, $Ttl, $explodeinto,
            $parentname)
          if $child && $level < 50;    # Simple DoS prevention measure
    }
    return @OleNative;
}

# Is this filename evil?
sub IsNameEvil {
    my ($this, $name, $dir) = @_;

    #print STDERR "Testing \"$name\" to see if it is evil\n";
    return 1 if (!defined($name) or ($name eq ''));    ### empty
       #JKF 20080307 return 1 if ($name =~ m{(^\s)|(\s+\Z)});  ### leading/trailing whitespace
    return 1 if ($name =~ m{\s});        ### whitespace
    return 1 if ($name =~ m{^\.+\Z});    ### dots
      # JKF 20080307 return 1 if ($name =~ tr{ \%\(\)\+\,\-\.0-9\=A-Z_a-z\{\}\x80-\xFF}{}c);
    return 1 if ($name =~ tr{\%\(\)\+\,\-\.0-9\=A-Z_a-z\{\}\x80-\xFF}{}c);
    return 1 if (length($name) > 50);
    return 'exists' if (-e "$dir/$name");
    0;
}

# Make this filename safe and return the safe version
sub MakeNameSafe {
    my ($self, $fname, $dir) = @_;

    ### Isolate to last path element:
    # JKF Drop Vax support my $last = $fname; $last =~ s{^.*[/\\\[\]:]}{};
    my $firstchar = substr($fname, 0, 1);
    $fname = substr($fname, 1);
    my $last = $fname;
    $last =~ s{^.*[/\\:]}{};
    if ($last and !$self->IsNameEvil($last, $dir)) {
        return $firstchar . $last;
    }

    # Try removing leading whitespace, trailing whitespace and all
    # dangerous characters to start with.
    $last =~ s/^\s+//;
    $last =~ s/\s+\Z//;
    $last =~ tr/\%\(\)\+\,\-\.0-9\=A-Z_a-z\{\}\x80-\xFF//cd;

    #print STDERR "MakeNameSafe: 2 $fname,$last\n";
    return $firstchar . $last unless $self->IsNameEvil($last, $dir);

    ### Break last element into root and extension, and truncate:
    my ($root, $ext) = (
          ($last =~ /^(.*)\.([^\.]+)\Z/)
        ? ($1, $2)
        : ($last, '')
    );
    $root =~ s/\s+//g;
    $ext =~ s/\s+//g;
    $root = substr($root, 0, ($self->{MPF_TrimRoot} || 14));
    $ext  = substr($ext,  0, ($self->{MPF_TrimExt}  || 3));
    $ext =~ /^\w+$|^$/ or $ext = "dat";
    my $trunc = $root . ($ext ? ".$ext" : '');

    if (!$self->IsNameEvil($trunc, $dir)) {
        return $firstchar . $trunc;
    }

    # It is still evil, but probably just because it exists
    if ($self->IsNameEvil($trunc, $dir) eq 'exists') {
        my $counter = 0;
        $trunc = $trunc . '0';
        do {
            $counter++;
            $trunc = $root . $counter . ($ext ? ".$ext" : '');
        } while $self->IsNameEvil($trunc, $dir) eq 'exists';
        return $firstchar . $trunc;
    }
    ### Hope that works:
    # Return a new filename that doesn't exist.
    return File::Temp::tempnam($dir, $firstchar . "MStemp");
}

# Unpack a tar file into the named directory.
# Return 1 if an error occurred, else 0.
sub UnpackTar {
    my ($this, $tarname, $explodeinto) = @_;

    return 1;    # Not yet implemented
}

# Try to parse all the text bits of each message, looking to see if they
# can be parsed into files which might be infected.
# I then throw these sections back to the MIME parser.
sub ExplodePart {
    my ($this, $explodeinto) = @_;

    my ($dir, $file, $part, @parts);

    $dir  = new DirHandle;
    $file = new FileHandle;

    $dir->open($explodeinto);
    @parts = $dir->read();
    $dir->close();

    my ($linenum, $foundheader, $prevline, $line, $position, $prevpos,
        $nextpos);
    foreach $part (@parts) {

        #print STDERR "Reading $part\n";
        # Allow for leading type indicator character.
        next unless $part =~ /^.msg.*txt/;

        # Try and find hidden messages in the text files
        #print STDERR "About to read $explodeinto/$part\n";
        $file->open("$explodeinto/$part") or next;

        # Try reading the first few lines to see if they look like mail headers
        $linenum     = 0;
        $foundheader = 0;
        $prevline    = "";
        $prevpos     = 0;
        $nextpos     = 0;
        $line        = undef;

        for ($linenum = 0; $linenum < 30; $linenum++) {

            #$position = $file->getpos();
            $line = <$file>;
            last unless defined $line;
            $nextpos += length $line;

            # Must have 2 lines of header
            if (   $prevline =~ /^[^:\s]+: /
                && $line =~ /(^\s+)|(^[^:]+ )|(^\s+.*=)/) {

          #print STDERR "Found header start at \"$prevline\"\n and \"$line\"\n";
                $foundheader = 1;
                last;
            }
            $prevline = $line;
            $prevpos  = $position;
            $position = $nextpos;
        }

        unless ($foundheader) {
            $file->close();
            next;
        }

        # Rewind to the start of the header
        #$file->setpos($prevpos);
        seek $file, $prevpos, 0;

        #print STDERR "First line is \"" . <$file> . "\"\n";

        # Setup everything for the MIME parser
        my $parser = MIME::Parser->new;
        my $filer  = Baruwa::Scanner::FileInto->new($explodeinto);

        # Over-ride the default default character set handler so it does it
        # much better than the MIME-tools default handling.
        MIME::WordDecoder->default->handler('*' => \&WordDecoderKeep7Bit);

        #print STDERR "Exploding message " . $this->{id} . " into " .
        #             $explodeinto . "\n";
        $parser->filer($filer);
        $parser->extract_uuencode(1);       # uue is off by default
        $parser->output_to_core('NONE');    # everything into files

        # Do the actual parsing
        my $entity = eval {$parser->parse($file)};

        $file->close;
    }
}

# Print the infection reports for this message
sub PrintInfections {
    my $this = shift;

    my ($filename, $report, $type);

    print STDERR "Virus reports for " . $this->{id} . ":\n";
    foreach $filename (keys %{$this->{virusreports}}) {
        print STDERR "    ";
        print STDERR $filename . "\t" . $this->{virusreports}{$filename} . "\n";
        print STDERR "    " . $this->{virustypes}{$filename} . "\n";
    }

    print STDERR "Name reports for " . $this->{id} . ":\n";
    foreach $filename (keys %{$this->{namereports}}) {
        print STDERR "    ";
        print STDERR $filename . "\t" . $this->{namereports}{$filename} . "\n";
        print STDERR "    " . $this->{nametypes}{$filename} . "\n";
    }

    print STDERR "Other reports for " . $this->{id} . ":\n";
    foreach $filename (keys %{$this->{otherreports}}) {
        print STDERR "    ";
        print STDERR $filename . "\t" . $this->{otherreports}{$filename} . "\n";
        print STDERR "    " . $this->{othertypes}{$filename} . "\n";
    }

    print STDERR "Entity reports for " . $this->{id} . ":\n";
    foreach $filename (keys %{$this->{entityreports}}) {
        print STDERR "    ";
        print STDERR $filename . "\t"
          . $this->{entityreports}{$filename} . "\n";
    }

    print STDERR "All reports for " . $this->{id} . ":\n";
    foreach $filename (keys %{$this->{allreports}}) {
        print STDERR "    ";
        print STDERR $filename . "\t" . $this->{allreports}{$filename} . "\n";
    }

    print STDERR "Message is TNEF? "
      . ($this->{tnefentity} ? "Yes" : "No") . "\n";
    print STDERR "Message is bad TNEF? "
      . ($this->{badtnef} ? "Yes" : "No") . "\n";
    print STDERR "Message has "
      . $this->{virusinfected}
      . " virus infections\n";
    print STDERR "Message has " . $this->{sizeinfected} . " size problems\n";

# JKF 19/12/2007 print STDERR "Message has " . $this->{passwordinfected} . " passworded archive problems\n";
    print STDERR "Message has " . $this->{otherinfected} . " other problems\n";

    print STDERR "\n";
}

# Create the Entity2Parent and Entity2File hashes for a message
#    $message->CreateEntitiesHelpers($this->{entity2parent},
#                                    $this->{entity2file});

sub CreateEntitiesHelpers {
    my $this = shift;

    #my($Entity2Parent, $Entity2File) = @_;

    return undef unless $this->{entity};

    # Set this up so it's ready for de-miming filenames in odd charsets.
    MIME::WordDecoder->default->handler(
        '*' => \&Baruwa::Scanner::Message::WordDecoderKeep7Bit);

    $this->{numberparts} = CountParts($this->{entity}) || 1;

    # Put something useless in the 2 hashes so that they exist.
    $this->{entity2file}{""}     = 0;
    $this->{entity2safefile}{""} = 0;
    $this->{entity2parent}{""}   = 0;
    $this->{file2entity}{""}     = $this->{entity};    # Root of this message
    $this->{name2entity}{""}     = 0;
    $this->{file2safefile}{""}   = "";
    $this->{safefile2file}{""}   = "";
    BuildFile2EntityAndEntity2File(
        $this->{entity},        $this->{file2entity},
        $this->{file2safefile}, $this->{safefile2file},
        $this->{entity2file},   $this->{entity2safefile},
        $this->{name2entity}
    );
    BuildEntity2Parent($this->{entity}, $this->{entity2parent}, undef);
}

# For the MIME entity given, work out the number of message parts.
# Recursive. This is a class function, not a normal method.
sub CountParts {
    my ($entity) = @_;
    my (@parts, $total, $part);

    return 0 unless $entity;
    @parts = $entity->parts;
    $total += int(@parts);
    foreach $part (@parts) {
        $total += CountParts($part);
    }
    return $total;
}

# Build the file-->entity and entity-->file mappings for a message.
# This will let us replace infected entities later. Key is the filename,
# value is the entity.
# This is recursive. This is a class function, not a normal method.
sub BuildFile2EntityAndEntity2File {
    my ($entity, $file2entity, $file2safefile, $safefile2file, $entity2file,
        $entity2safefile, $name2entity)
      = @_;

    # Build the conversion hash from scalar(entity) --> real entity object
    # Need to do this as objects cannot be hash keys.
    $name2entity->{scalar($entity)} = $entity;

    my (@parts, $body, $headfile, $part, $path, $namewithouttype);

    # Find the body for this entity
    $body = $entity->bodyhandle;
    if (defined($body) && defined($body->path)) {    # data is on disk:
        $path = $body->path;
        $path =~ s#^.*/([^/]*)$#$1#;

      # At this point $path will contain the filename with the leading type char
        $namewithouttype = substr($path, 1);
        $file2entity->{$namewithouttype} = $entity;
        $entity2file->{$entity}          = $namewithouttype;

        #print STDERR "Path is $path\n";
    }

    # And the head, which is where the recommended filename is stored
    # This is so we can report infections in the filenames which are
    # recommended, even if they are evil and we hence haven't used them.
    $headfile =
      $entity->head->recommended_filename || $namewithouttype;    # $path;
      #print STDERR "rec filename for \"$headfile\" is \"" . $entity->head->recommended_filename . "\"\n";
    $headfile = MIME::WordDecoder::unmime($headfile);

    #print STDERR "headfile is $headfile\n";
    if ($headfile) {

        # headfile does *NOT* have the type indicator character on it.
        $file2entity->{$headfile}   = $entity if !$file2entity->{$headfile};
        $file2safefile->{$headfile} = $path;
        $entity2safefile->{$entity} = $path;
        $safefile2file->{$path}     = $headfile;

        #print STDERR "File2SafeFile (\"$headfile\") = \"$path\"\n";
    }

    # And for all its children
    @parts = $entity->parts;
    foreach $part (@parts) {
        BuildFile2EntityAndEntity2File($part, $file2entity, $file2safefile,
            $safefile2file, $entity2file, $entity2safefile, $name2entity);
    }
}

# Build a hash that gives the parent of any entity
# (except for root ones which will be undef).
# This is recursive.
sub BuildEntity2Parent {
    my ($entity, $Entity2Parent, $parent) = @_;

    my (@parts, $part);

    $Entity2Parent->{$entity} = $parent;
    @parts = $entity->parts;
    foreach $part (@parts) {

        #print STDERR "BuildEntity2Parent: Doing part $part\n";
        $Entity2Parent->{$part} = $entity;
        BuildEntity2Parent($part, $Entity2Parent, $entity);
    }
}

# Combine the virus reports and the other reports, as otherwise the
# cleaning code is really messy. I might combine them when I create
# them some time later, but I wanted to keep them separate if possible
# in case anyone wanted a feature in the future which would be easier
# with separate reports.
# If safefile2file does not map for a filename, ban the whole message
# to be on the safe side.
# No text in reports will contain any file type indicators.
# But the data structures will, as they must be accurate filenames (safefiles).
sub CombineReports {
    my $this = shift;

    my ($file, $text, $Name);
    my (%reports, %types);

    #print STDERR "Combining reports for " . $this->{id} . "\n";

    # If they want to include the scanner name in the reports, then also
    # include the translation of "Baruwa" in the filename/type/content
    # reports.
    # If they set "Baruwa = " in languages.conf then this string will
    # *not* be inserted at the start of the reports.
    $Name = Baruwa::Scanner::Config::LanguageValue($this, 'baruwa')
      if Baruwa::Scanner::Config::Value('showscanner', $this);
    $Name .= ': ' if $Name ne "" && $Name !~ /:/;

    # Or the flags together
    $this->{infected} =
      $this->{virusinfected} | $this->{nameinfected} | $this->{sizeinfected} |

      # JKF 19/12/2007 $this->{passwordinfected} |
      $this->{otherinfected};

    # Combine all the reports and report-types
    while (($file, $text) = each %{$this->{virusreports}}) {

        #print STDERR "Adding file $file report $text\n";
        $this->{allreports}{$file} .= $text;
        $reports{$file} .= $text;
    }
    while (($file, $text) = each %{$this->{virustypes}}) {

        #print STDERR "Adding file $file type $text\n";
        $this->{alltypes}{$file} .= $text;
        $types{$file} .= $text;
    }
    while (($file, $text) = each %{$this->{namereports}}) {

        #print STDERR "Adding file \"$file\" report \"$text\"\n";
        $this->{allreports}{$file} .= $Name . $text;
        $reports{$file} .= $Name . $text;
    }
    while (($file, $text) = each %{$this->{nametypes}}) {

        #print STDERR "Adding file $file type $text\n";
        $this->{alltypes}{$file} .= $text;
        $types{$file} .= $text;
    }
    while (($file, $text) = each %{$this->{otherreports}}) {

        #print STDERR "Adding file $file report $text\n";
        $this->{allreports}{$file} .= $Name . $text;
        $reports{$file} .= $Name . $text;
    }
    while (($file, $text) = each %{$this->{othertypes}}) {

        #print STDERR "Adding file $file type $text\n";
        $this->{alltypes}{$file} .= $text;
        $types{$file} .= $text;
    }

    # Now try to map all the reports onto their parents as far as possible
    #print STDERR "About to combine reports\n";
    my ($key, $value, $parentwithtype);
    while (($key, $value) = each %reports) {
        $parentwithtype = $this->{file2parent}{$key};
        if ($parentwithtype ne ""
            && exists($this->{safefile2file}{$parentwithtype})) {

            #print STDERR "Found parent of $key is $parentwithtype\n";
            $this->{allreports}{$parentwithtype} .= $value;
            $this->{alltypes}{$parentwithtype}   .= $types{$key};
        } else {

            #print STDERR "Promoting report for $key\n";
            if ($parentwithtype eq "" and exists($this->{safefile2file}{$key}))
            {   delete $this->{allreports}{$key};
                delete $this->{alltypes}{$key};
                $this->{allreports}{$key} .= $value;
                $this->{alltypes}{$key}   .= $types{$key};
            } else {
                delete $this->{allreports}{$key};
                delete $this->{alltypes}{$key};
                $this->{allreports}{""} .= $value;
                $this->{alltypes}{""}   .= $types{$key};
            }
        }
    }

    #print STDERR "Finished combining reports\n";
    #$this->PrintInfections();
}

# Clean the message. This involves removing all the infected or
# troublesome sections of the message and replacing them with
# nice little text files explaining what happened.
# We do not do true macro-virus disinfection here.
# Also mark the message as having had its body modified.
sub Clean {
    my $this = shift;

    #print STDERR "\n\n\nStart Of Clean\n\n";
    #$this->PrintInfections();
    # Get out if nothing to do
    #print STDERR "Have we got anything to do?\n";
    return
      unless ($this->{allreports} && %{$this->{allreports}})
      || ($this->{entityreports} && %{$this->{entityreports}});

    #print STDERR "Yes we have\n";

    my ($file, $text, $entity, $parent, $filename, $everyreport,
        %AlreadyCleaned);
    my ($untypedfile);

    # Work out whether infected bits of this message should be stored
    my $storeme = 0;
    $storeme = 1
      if Baruwa::Scanner::Config::Value('quarantineinfections', $this) =~ /1/;

    #print STDERR "StoreMe = $storeme\n";
    # Cancel the storage if it is silent and no-one wants it quarantined
    $storeme = 0
      if $this->{silent}
      && !$this->{noisy}
      && Baruwa::Scanner::Config::Value('quarantinesilent', $this) !~ /1/;

    # Construct a string of all the reports, which is used if there is
    # cleaning needing doing on the whole message
    $everyreport = join("\n", values %{$this->{allreports}});

    # Construct a hash of all the entities we will clean,
    # so we clean parents in preference to their children.
    my (%EntitiesWeClean);
    $EntitiesWeClean{scalar($this->{tnefentity})} = 1 if $this->{tnefentity};

    # Work through each filename-based report in turn, 1 per attachment
    while (($file, $text) = each %{$this->{allreports}}) {

        #print STDERR "Cleaning $file\n";
        $this->{bodymodified} =
          1;    # This message body has been changed in memory

        # If it's a TNEF message, then use the entity of the winmail.dat
        # file, else use the entity of the infected file.
        my $tnefentity = $this->{tnefentity};

        #print STDERR "It's a TNEF message\n" if $tnefentity;
        if ($file eq "") {

    #print STDERR "It's a whole body infection, entity = ".$this->{entity}."\n";
            $entity = $this->{entity};
        } else {

            #print STDERR "It's just 1 file, which is $file\n";
            if ($tnefentity) {
                $entity = $tnefentity;
            } else {

                # Find the top-level parent's entity
                my %visited =
                  ();    # This makes sure we can't loop forever (typed files)
                my @entities
                  ;    # Entities we hit on the way to the top, delete 'em all!
                my $parententity = $this->{file2entity}{substr($file, 1)};
                while ($this->{file2parent}{$file} ne ""
                    && !defined($visited{$this->{file2parent}{$file}})) {

             #print STDERR "Traversing to top-level via $file, $parententity\n";
                    $file = $this->{file2parent}{$file};
                    $visited{$file} = 1;
                    push @entities, $parententity;
                    $parententity = $this->{entity2parent}{$parententity};
                }

        # Delete all the entities on the way so we don't have any strays.
        #print STDERR "Must also delete entities " . join(',',@entities) . "\n";
                foreach (@entities) {

  #print STDERR "Deleting entity $_, file = " . $this->{entity2file}{$_} . "\n";
                    $this->DeleteEntity($_, $this->{entity}, $tnefentity) if $_;
                }
                $untypedfile = substr($file, 1);
                $entity = scalar($this->{file2entity}{$untypedfile})
                  if $untypedfile ne "";

            #print STDERR "Found entity $entity for untypedfile $untypedfile\n";
                next if $entity && $EntitiesWeClean{$entity};

                #print STDERR "Survived the cut\n";

                # Could not find parent, give up and zap whole message
                if (!$entity) {
                    $entity = $this->{entity};
                }

             #print STDERR "Top-level parent's entity is $entity, file $file\n";
            }
        }

        # Avoid cleaning the same entity twice as it will clean the wrong thing!
        next if $AlreadyCleaned{$entity};
        $AlreadyCleaned{$entity} = 1;

        # Work out which message to replace the attachment with.
        # As there may be multiple types for 1 file, find them in
        # in decreasing order of importance.
        my $ModificationOnly = 0;    # Is this just an "m" modification?
        my $type = $this->{alltypes}{"$file"};

        #print STDERR "In Clean message, type = $type and quar? = $storeme\n";
        if ($type =~ /v/i) {

            # It's a virus. Either delete or store it.
            if ($storeme) {
                $filename =
                  Baruwa::Scanner::Config::Value('storedvirusmessage', $this);
            } else {
                $filename =
                  Baruwa::Scanner::Config::Value('deletedvirusmessage', $this);
            }
        } elsif ($type =~ /f/i) {

            # It's a filename trap. Either delete or store it.
            if ($storeme) {
                $filename =
                  Baruwa::Scanner::Config::Value('storedfilenamemessage',
                    $this);
            } else {
                $filename =
                  Baruwa::Scanner::Config::Value('deletedfilenamemessage',
                    $this);
            }
        } elsif ($type =~ /c/i) {

            # It's dangerous content, either delete or store it.
            if ($storeme) {
                $filename =
                  Baruwa::Scanner::Config::Value('storedcontentmessage', $this);
            } else {
                $filename =
                  Baruwa::Scanner::Config::Value('deletedcontentmessage',
                    $this);
            }
        } elsif ($type =~ /s/i) {

            # It's dangerous content, either delete or store it.
            if ($storeme) {
                $filename =
                  Baruwa::Scanner::Config::Value('storedsizemessage', $this);
            } else {
                $filename =
                  Baruwa::Scanner::Config::Value('deletedsizemessage', $this);
            }
        } elsif ($type eq 'm') {

            # The only thing wrong here is that the MIME structure has been
            # modified, so the message must be re-built. Nothing needs to
            # be removed from the message.
            $ModificationOnly = 1;
        } else {

            # Treat it like a virus anyway, to be on the safe side.
            if ($storeme) {
                $filename =
                  Baruwa::Scanner::Config::Value('storedvirusmessage', $this);
            } else {
                $filename =
                  Baruwa::Scanner::Config::Value('deletedvirusmessage', $this);
            }
        }

        # If entity is null then there was a parsing problem with the message,
        # so don't try to walk its tree as it will fail.
        next unless $entity;

        # MIME structure has been modified, so the message must be rebuilt.
        # Nothing needs to be cleaned though.
        next if $ModificationOnly;

# If it's a silent virus, then only generate the report if anyone
# wants a copy of it in the quarantine. Or else it won't be quarantined
# but they will still get a copy of the report.
#print STDERR "\n\nSilent = " . $this->{silent} . " and Noisy = " . $this->{noisy} . "\n";
        $filename = ""
          if $this->{silent}
          && !$this->{noisy}
          && !Baruwa::Scanner::Config::Value('deliversilent', $this);    # &&
          #             Baruwa::Scanner::Config::Value('quarantinesilent', $this) !~ /1/;

        # Do the actual attachment replacement
        #print STDERR "File = \"$file\"\nthis = \"$this\"\n";
        #print STDERR "Entity to clean is $entity\n" .
        #             "root entity is " . $this->{entity} . "\n";
        #print STDERR "About to try to clean $entity, $text, $filename\n";
        if ($file eq "") {

            # It's a report on the whole message, so use all the reports
            # This is a virus disinfection on the *whole* message, so the
            # cleaner needs to know not to generate any mime parts.
            $this->CleanEntity($entity, $everyreport, $filename);
        } else {

            # It's a report on 1 section, so just use the report for that
            $this->CleanEntity($entity, $text, $filename);
        }
    }

    # Now do the entity reports. These are for things like unparsable tnef
    # files, partial messages, external-body messages, things like that
    # which are always just errors.
    # Work through each report in turn, 1 per attachment
    #print STDERR "Entity reports are " . $this->{entityreports} . "\n";
    while (($entity, $text) = each %{$this->{entityreports}}) {

        #print STDERR "Cleaning $entity which had a report of $text\n";

        # Find rogue entity reports that should point to tnefentity but don't
        $entity = $this->{tnefentity} if $this->{badtnef} && !$entity;
        next unless $entity;    # Skip rubbish in the reports

        # Turn the text name of the entity into the object itself
        $entity = $this->{name2entity}{scalar($entity)};

        $this->{bodymodified} =
          1;                    # This message body has been changed in memory

      #print STDERR "In Clean message, quar? = $storeme and entity = $entity\n";
      # It's always an error, so handle it like a virus.
      # Either delete or store it.
        if ($storeme) {
            $filename =
              Baruwa::Scanner::Config::Value('storedvirusmessage', $this);
        } else {
            $filename =
              Baruwa::Scanner::Config::Value('deletedvirusmessage', $this);
        }

        # Do the actual attachment replacement
        #print STDERR "About to try to clean $entity, $text, $filename\n";
        $this->CleanEntity($entity, $text, $filename);
    }

    # Sign the top of the message body with a text/html warning if they want.
    if (Baruwa::Scanner::Config::Value('markinfectedmessages', $this) =~ /1/
        && !$this->{signed}) {

        #print STDERR "In Clean message, about to sign message " . $this->{id} .
        #             "\n";
        $this->SignWarningMessage($this->{entity});
        $this->{signed} = 1;
    }

    #print STDERR "\n\n\nAfter Clean()\n";
    #$this->PrintInfections();
}

# Do the actual attachment replacing
sub CleanEntity {
    my $this = shift;
    my ($entity, $report, $reportname) = @_;

    my (@parts, $Warning, $Disposition, $warningfile, $charset, $i);

    # Knock out the helper's list of entity to filename mapping,
    # so auto-zip won't find the attachment
    delete $this->{entity2safefile}{$entity};

    # Find the parent as that's what you have to change
    #print STDERR "CleanEntity: In ".$this->{id}." entity is $entity and " .
    #             "its parent is " . $this->{entity2parent}{$entity} . "\n";
    #print STDERR "Reportname is $reportname\n";
    my $parent = $this->{entity2parent}{$entity};
    $warningfile =
      Baruwa::Scanner::Config::Value('attachmentwarningfilename', $this);
    $charset = Baruwa::Scanner::Config::Value('attachmentcharset', $this);

    #print STDERR "Cleaning entity whose report is $report\n";

    # Infections applying to the entire message cannot be simply disinfected.
    # Have to replace the entire message with a text/plain error.
    unless ($parent) {

#print STDERR "Doing the whole message\n";
#print STDERR "ConstructingWarning for $report, " . $this->{id} . ", $reportname\n";
        $Warning = $this->ConstructWarning(
            Baruwa::Scanner::Config::LanguageValue($this, 'theentiremessage'),
            $report, $this->{id}, $reportname);

        #print STDERR "Warning message is $Warning\n";
        #031118 if ($this->{entity} eq $entity) {
        if ($entity->bodyhandle) {

            # Output message back into body
            my ($io, $filename, $temp);
            $io = $entity->open("w");
            $io->print($Warning . "\n");
            $io->close;

            # Set the MIME type if it was wrong
            $filename =
              Baruwa::Scanner::Config::Value('attachmentwarningfilename',
                $this);
            $temp = $entity->head->mime_attr('content-type');
            $entity->head->mime_attr('Content-Type', 'text/plain')
              if $temp && $temp ne 'text/plain';

            # Set the charset if there was already a Content-type: header
            $entity->head->mime_attr('Content-type.charset', $charset) if $temp;
            $temp = $entity->head->mime_attr('content-type.name');
            $entity->head->mime_attr('Content-type.name', $filename) if $temp;
            $temp = $entity->head->mime_attr('content-disposition');
            $entity->head->mime_attr('content-disposition', 'inline') if $temp;
            $temp = $entity->head->mime_attr('content-disposition.filename');
            $entity->head->mime_attr('content-disposition.filename', $filename)
              if $temp;
            return;
        } else {

            # If the message is multipart but the boundary is "" then it won't
            # have any parts() which makes it impossible to overwrite without
            # first forcing it to throw away all the structure by becoming
            # single-part.
            $entity->make_singlepart
              if $entity->is_multipart
              && $entity->head
              && $entity->head->multipart_boundary eq "";

            $parts[0] = MIME::Entity->build(
                Type        => 'text/plain',
                Filename    => $warningfile,
                Disposition => 'inline',
                Data        => $Warning,
                Encoding    => 'quoted-printable',
                Charset     => $charset,
                Top         => 0
            );
            $entity->make_multipart()
              if $entity->head
              && $entity->head->mime_attr('content-type') eq "";
            $entity->parts(\@parts);
            return;
        }
    }

    # Now know that the infection only applies to one part of the message,
    # so replace that part with an error message.
    @parts = $parent->parts;

    # Find the infected part
    my $tnef = $this->{tnefentity};

    #print STDERR "TNEF entity is " . scalar($tnef) . "\n";
    my $infectednum = -1;

    #print STDERR "CleanEntity: Looking for entity $entity\n";
    for ($i = 0; $i < @parts; $i++) {

        #print STDERR "CleanEntity: Comparing " . scalar($parts[$i]) .
        #             " with $entity\n";
        if (scalar($parts[$i]) eq scalar($entity)) {

            #print STDERR "Found it in part $i\n";
            $infectednum = $i;
            last;
        }
        if ($tnef && (scalar($parts[$i]) eq scalar($tnef))) {

            #print STDERR "Found winmail.dat in part $i\n";
            $infectednum = $i;
            last;
        }
    }

  #Baruwa::Scanner::Log::WarnLog(
  #  "Oh bother, missed infected entity in message %s :-(", $this->{id}), return
  #  if $infectednum<0;

    # Now to actually do something about it...
    #print STDERR "About to constructwarning from $report\n";
    $Warning = $this->ConstructWarning($this->{entity2file}{$entity},
        $report, $this->{id}, $reportname);

    #print STDERR "Reportname is \"$reportname\"\n";
    #print STDERR "Warning is \"$Warning\"\n";
    # If the warning is now 0 bytes, don't add it, just remove the virus
    if ($Warning ne "") {
        $Disposition =
          Baruwa::Scanner::Config::Value('warningisattachment', $this)
          ? 'attachment'
          : 'inline';
        $parts[$infectednum] = build MIME::Entity
          Type        => 'text/plain',
          Filename    => $warningfile,
          Disposition => $Disposition,
          Data        => $Warning,
          Encoding    => 'quoted-printable',
          Charset     => $charset,
          Top         => 0;
    } else {

        # We are just deleting the part, not replacing it
        # @parts = splice @parts, $infectednum, 1;
        $parts[$infectednum] = undef;   # We prune the tree just during delivery
    }
    $parent->parts(\@parts);

    # And make the parent a multipart/mixed if it's a multipart/alternative
    # or multipart/related or message/partial
    $parent->head->mime_attr("Content-type" => "multipart/mixed")
      if ($parent->is_multipart)
      && ($parent->head->mime_attr("content-type") =~
        /multipart\/(alternative|related)/i);
    if ($parent->head->mime_attr("content-type") =~ /message\/partial/i) {
        $parent->head->mime_attr("Content-type" => "multipart/mixed");

        #  $parent->make_singlepart();
    }

    #print STDERR "Finished CleanEntity\n";
}

# Construct a warning message given an attachment filename, a copy of
# what the virus scanner said, the message id and a message filename to parse.
# The id is passed in purely for substituting into the warning message file.
sub ConstructWarning {
    my $this = shift;
    my ($attachmententity, $scannersaid, $id, $reportname) = @_;

    # If there is no report file then we create no warning
    return "" unless $reportname;

    my $date   = $this->{datestring};         # scalar localtime;
    my $textfh = new FileHandle;
    my $dir    = $global::MS->{work}{dir};    # Get the working directory
    my $localpostmaster =
      Baruwa::Scanner::Config::Value('localpostmaster', $this);
    my $postmastername =
      Baruwa::Scanner::Config::LanguageValue($this, 'baruwa');

    #print STDERR "ConstructWarning for $attachmententity. Scanner said \"" .
    #             "$scannersaid\", message id $id, file = $reportname\n";

    # Reformat the virus scanner report a bit, and optionally remove dirs
    $scannersaid =~ s/^/   /gm;
    if (Baruwa::Scanner::Config::Value('hideworkdir', $this)) {
        my $pattern = '(' . quotemeta($global::MS->{work}->{dir}) . "|\\\.)/";

        #print STDERR "In replacement, regexp is \"$pattern\"\n";
        $scannersaid =~ s/$pattern//g;     #m # Remove the work dir
        $scannersaid =~ s/\/?$id\/?//g;    # Remove the message id
    }

    #print STDERR "After replacement, scanner said \"$scannersaid\"\n";

    my $output = "";
    my $result = "";

    # These are all the variables that are allowed to appear
    # in the report template.
    my $filename = ($attachmententity
          || Baruwa::Scanner::Config::LanguageValue($this, 'notnamed'));

    #my $date = scalar localtime; Already defined above
    my $report       = $scannersaid;
    my $hostname     = Baruwa::Scanner::Config::Value('hostname', $this);
    my $linkhostname = lc($hostname);
    $linkhostname =~ tr/a-z0-9_-//dc;
    my $quarantinedir = Baruwa::Scanner::Config::Value('quarantinedir', $this);

    # And let them put the date number in there too
    my ($day, $month, $year);

    #($day, $month, $year) = (localtime)[3,4,5];
    #$month++;
    #$year += 1900;
    #my $datenumber = sprintf("%04d%02d%02d", $year, $month, $day);
    my $datenumber = $this->{datenumber};

    open($textfh, $reportname)
      or Baruwa::Scanner::Log::WarnLog("Cannot open message file %s, %s",
        $reportname, $!);
    my $line;
    while (defined($line = <$textfh>)) {
        chomp $line;

        #$line =~ s/"/\\"/g; # Escape any " characters
        #$line =~ s/@/\\@/g; # Escape any @ characters
        $line =~
          s/([\(\)\[\]\.\?\*\+\^"'@])/\\$1/g;    # Escape any regex characters
                                                 # Untainting joy...
        $line = $1 if $line =~ /(.*)/;
        $result = eval "\"$line\"";
        $output .= Baruwa::Scanner::Config::DoPercentVars($result) . "\n";
    }
    $output;
}

# Sign the body of the message with a text or html warning message
# directing users to read the VirusWarning.txt attachment.
# Return 0 if nothing was signed, true if it signed something.
sub SignWarningMessage {
    my $this = shift;
    my $top  = shift;

    #print STDERR "Top is $top\n";
    return 0 unless $top;

    # If multipart, try to sign our first part
    if ($top->is_multipart) {
        my $sigcounter = 0;

        #print STDERR "It's a multipart message\n";
        $sigcounter += $this->SignWarningMessage($top->parts(0));
        $sigcounter += $this->SignWarningMessage($top->parts(1))
          if $top->head and $top->effective_type =~ /multipart\/alternative/i;
        return $sigcounter;
    }

    my $MimeType = $top->head->mime_type if $top->head;

    #print STDERR "MimeType is $MimeType\n";
    return 0 unless $MimeType =~ m{text/}i;    # Won't sign non-text message.
                                               # Won't sign attachments.
    return 0 if $top->head->mime_attr('content-disposition') =~ /attachment/i;

    # Get body data as array of newline-terminated lines
    #print STDERR "Bodyhandle is " . $top->bodyhandle . "\n";
    $top->bodyhandle or return undef;
    my @body = $top->bodyhandle->as_lines;

    #print STDERR "Signing message part\n";

    # Output message back into body, followed by original data
    my ($line, $io, $warning);
    $io = $top->open("w");
    if ($MimeType =~ /text\/html/i) {
        $warning = $this->ReadVirusWarning('inlinehtmlwarning');

        #$warning = quotemeta $warning; # Must leave HTML tags alone!
        foreach $line (@body) {
            $line =~ s/\<html\>/$&$warning/i;
            $io->print($line);
        }
    } else {
        $warning = $this->ReadVirusWarning('inlinetextwarning');
        $io->print($warning . "\n");
        foreach $line (@body) {$io->print($line)};    # Original body data
    }
    (($body[-1] || '') =~ /\n\Z/) or $io->print("\n");    # Ensure final newline
    $io->close;

    # We signed something
    return 1;
}

# Read the appropriate warning message to sign the top of cleaned messages.
# Passed in the name of the config variable that points to the filename.
# This is also used to read the inline signature added to the bottom of
# clean messages.
# Substitutions allowed in the message are
#     $viruswarningfilename -- by default VirusWarning.txt
#     $from
#     $subject
# and $filename -- comma-separated list of infected attachments
sub ReadVirusWarning {
    my $this = shift;
    my ($option) = @_;

    my $file = Baruwa::Scanner::Config::Value($option, $this);
    my $viruswarningname =
      Baruwa::Scanner::Config::Value('attachmentwarningfilename', $this);
    my ($line);

    #print STDERR "Reading virus warning message from $filename\n";
    my $fh = new FileHandle;
    $fh->open($file)
      or (
        Baruwa::Scanner::Log::WarnLog(
            "Could not open inline file %s, %s",
            $file, $!
        ),
        return undef
      );

    # Work out the list of all the infected attachments, including
    # reports applying to the whole message
    my ($typedattach, $attach, $text, %infected, $filename, $from, $subject,
        $id);
    while (($typedattach, $text) = each %{$this->{allreports}}) {

        # It affects the entire message if the entity of this file matches
        # the entity of the entire message.
        $attach = substr($typedattach, 1);
        my $entity = $this->{file2entity}{"$attach"};

        #if ($attach eq "") {
        if ($this->{entity} eq $entity) {
            $infected{
                Baruwa::Scanner::Config::LanguageValue($this,
                    "theentiremessage")
              }
              = 1;
        } else {
            $infected{"$attach"} = 1;
        }
    }

    # And don't forget the external bodies which are just entity reports
    while (($typedattach, $text) = each %{$this->{entityreports}}) {
        $infected{Baruwa::Scanner::Config::LanguageValue($this, 'notnamed')} =
          1;
    }
    $attach = substr($typedattach, 1);
    $filename = join(', ', keys %infected);
    $id       = $this->{id};
    $from     = $this->{from};
    $subject  = $this->{subject};

    my $result = "";
    while (<$fh>) {
        chomp;
        s#"#\\"#g;
        s#@#\\@#g;

        # Boring untainting again...
        /(.*)/;
        $line = eval "\"$1\"";
        $result .= Baruwa::Scanner::Config::DoPercentVars($line) . "\n";
    }
    $fh->close();
    $result;
}

# Work out if the message is a reply or an original posting
sub IsAReply {
    my $this = shift;

    # Are we a reply or an original message?

    # Bail out very quickly if the list of header names is empty.
    my $lookfor = Baruwa::Scanner::Config::Value('isareply', $this);
    return 0 unless $lookfor;

    # Find the list of all the names of all the headers
    my @headers;
    foreach my $line (@{$this->{headers}}) {

        #print STDERR "Looking at $line\n";
        next if $line =~ /^\s/;
        next unless $line =~ /^([^:]+):/i;
        push @headers, $1;
    }

    #@headers = map { s/://; $_; } @headers; # Strip out all ':' characters

    my $headernames = join(',', @headers);

    # Must test the next line to make sure it does what I intend!
    $headernames = ',' . $headernames . ',';
    $headernames =~ s/,{2,}/,/g;
    $headernames =~ s/^,*/,/;    # Make sure line starts and
    $headernames =~ s/,*$/,/;    # ends with exactly 1 ','
        # $headernames now contains a comma-separated list of the msg's headers

    #print STDERR "Headers to look for are $lookfor\n";
    $lookfor =~ s/://g;
    $lookfor =~ s/[\s,]+/\|/g;    # Turn comma/space-separated list into
    $lookfor =~ s/^\|//;          # regexp matching ',(alternatives-list),'
    $lookfor =~ s/\|$//;
    $lookfor = ',(' . $lookfor . '),';

    # $lookfor is now a regexp which will match if any isareply are present

    # Are there any "lookfor" headers in the "headernames"?
    $this->{isreply} = 0;
    $this->{isreply} = 1 if $headernames =~ /$lookfor/i;
}

# Sign the bottom of the message with a tag-line saying it is clean
# and Baruwa is wonderful :-)
# Have already checked that message is not infected, and that they want
# clean signatures adding to messages.
sub SignUninfected {
    my $this = shift;

    return if $this->{infected};    # Double-check!

    my ($entity, $scannerheader);

    # Use the presence of an X-Baruwa: header to decide if the
    # message will have already been signed by another Baruwa server.
    $scannerheader = Baruwa::Scanner::Config::Value('mailheader', $this);
    $scannerheader =~ tr/://d;

    #print STDERR "Signing uninfected message " . $this->{id} . "\n";

    # Want to sign the bottom of the highest-level MIME entity
    $entity = $this->{entity};
    if (Baruwa::Scanner::Config::Value('signalreadyscanned', $this)
        || (defined($entity) && !$entity->head->count($scannerheader))) {
        $this->AppendSignCleanEntity($entity, 0);

        #$this->PrependSignCleanEntity($entity)
        #  if Baruwa::Scanner::Config::Value('signtopaswell', $this);
        if ($entity && $entity->head) {
            $entity->head->add('MIME-Version', '1.0')
              unless $entity->head->get('mime-version');
        }
        $this->{bodymodified} = 1;
    }
}

# Sign the end of a message (which is an entity) with the given tag-line
sub PrependSignCleanEntity {
    my $this = shift;
    my ($top) = @_;

    my ($MimeType, $signature, @signature);

    return unless $top;

    #print STDERR "In PrependSignCleanEntity, signing $top\n";

    # If multipart, try to sign our first part
    if ($top->is_multipart) {
        my $sigcounter = 0;

        # JKF Signed and encrypted multiparts must not be touched.
        # JKF Instead put the sig in the epilogue. Breaks the RFC
        # JKF but in a harmless way.
        if ($top->effective_type =~ /multipart\/(signed|encrypted)/i) {

            # Read the sig and put it in the epilogue, which may be ignored
            $signature = $this->ReadVirusWarning('inlinetextpresig');
            @signature = map {"$_\n"} split(/\n/, $signature);
            unshift @signature, "\n";
            $top->preamble(\@signature);
            return 1;
        }

        # If any of the PSCE() calls said they didn't sign anything then return
        # a marker saying we didn't sign anything, and DON'T sign anything!
        my $result0 = $this->PrependSignCleanEntity($top->parts(0));
        if ($result0 >= 0) {
            $sigcounter += $result0;
        } else {
            $sigcounter = -1;
        }
        if ($top->head and $top->effective_type =~ /multipart\/alternative/i) {
            my $result1 = $this->PrependSignCleanEntity($top->parts(1));
            if ($result1 >= 0) {
                $sigcounter += $result1;
            } else {
                $sigcounter = -1;
            }
        }

        if ($sigcounter == 0) {

            # If we haven't signed anything by now, it must be a multipart
            # message containing only things we can't sign. So add a text/plain
            # section on the front and sign that.
            my $text    = $this->ReadVirusWarning('inlinetextpresig') . "\n\n";
            my $newpart = build MIME::Entity
              Type => 'text/plain',
              Charset =>
              Baruwa::Scanner::Config::Value('attachmentcharset', $this),
              Disposition => 'inline',
              Data        => $text,
              Encoding    => 'quoted-printable',
              Top         => 0;
            $top->add_part($newpart, 0);
            $sigcounter = 1;
        }
        return $sigcounter;
    }

    $MimeType = $top->head->mime_type if $top->head;
    return 0 unless $MimeType =~ m{text/}i;    # Won't sign non-text message.
                                               # Won't sign attachments.
    return 0 if $top->head->mime_attr('content-disposition') =~ /attachment/i;

    # Get body data as array of newline-terminated lines
    $top->bodyhandle or return undef;
    my @body = $top->bodyhandle->as_lines;

    # Output original data back into body, followed by message
    my ($line, $io);
    $io = $top->open("w");
    if ($MimeType =~ /text\/html/i) {
        if (
            (   $this->{sigimagepresent}
                && Baruwa::Scanner::Config::Value('allowmultsigs', $this) !~ /1/
            )
            || (Baruwa::Scanner::Config::Value('isareply', $this)
                && $this->{isreply})
          ) {
            # Either: there is an image already and we don't want multiples,
            # Or    : it's a reply and we don't sign replies,
            # Then  : We don't want an image, so do nothing
            $io->close;
            return
              -1;    # Send back a token saying we found one and didn't sign it
        } else {
            $signature = $this->ReadVirusWarning('inlinehtmlpresig');
            foreach $line (@body) {
                $line =~ s/\<x?html\>/$&$signature/i;
                $io->print($line);
            }

        #(($body[-1]||'') =~ /\n\Z/) or $io->print("\n"); # Ensure final newline
        }
    } else {
        $signature = $this->ReadVirusWarning('inlinetextpresig');
        $io->print("$signature\n");
        foreach $line (@body) {$io->print($line)};    # Original body data
    }
    $io->close;

    # We signed something
    return 1;
}

# Sign the end of a message (which is an entity) with the given tag-line
sub AppendSignCleanEntity {
    my $this = shift;
    my ($top, $parent) = @_;

    my ($MimeType, $signature, @signature);

    return unless $top;

    #print STDERR "In AppendSignCleanEntity, signing $top\n";

    # If multipart, try to sign our first part
    if ($top->is_multipart) {
        my $sigcounter = 0;

        # JKF Signed and encrypted multiparts must not be touched.
        # JKF Instead put the sig in the epilogue. Breaks the RFC
        # JKF but in a harmless way.
        if ($top->effective_type =~ /multipart\/(signed|encrypted)/i) {

            # Read the sig and put it in the epilogue, which may be ignored
            $signature = $this->ReadVirusWarning('inlinetextsig');
            @signature = map {"$_\n"} split(/\n/, $signature);
            unshift @signature, "\n";
            $top->epilogue(\@signature);
            return 1;
        }

       # If the ASCE(0) returned -1 then we found something we could sign but
       # chose not to, so set $sigcounter so we won't try to sign anything else.
        my $result0 = $this->AppendSignCleanEntity($top->parts(0), $top);
        if ($result0 >= 0) {
            $sigcounter += $result0;
        } else {
            $sigcounter = -1;
        }

       # If the ASCE(1) returned -1 then we found something we could sign but
       # chose not to, so set $sigcounter so we won't try to sign anything else.
        if ($top->head and $top->effective_type =~ /multipart\/alternative/i) {
            my $result1 = $this->AppendSignCleanEntity($top->parts(1), $top);
            if ($result1 >= 0) {
                $sigcounter += $result1;
            } else {
                $sigcounter = -1;
            }
        }

        if ($sigcounter == 0) {

            # If we haven't signed anything by now, it must be a multipart
            # message containing only things we can't sign. So add a text/plain
            # section on the front and sign that.
            my $text    = $this->ReadVirusWarning('inlinetextsig') . "\n\n";
            my $newpart = build MIME::Entity
              Type => 'text/plain',
              Charset =>
              Baruwa::Scanner::Config::Value('attachmentcharset', $this),
              Disposition => 'inline',
              Data        => $text,
              Encoding    => 'quoted-printable',
              Top         => 0;
            $top->add_part($newpart, 0);
            $sigcounter = 1;
        }
        return $sigcounter;
    }

    $MimeType = $top->head->mime_type if $top->head;
    return 0
      unless $MimeType =~ m{text/(html|plain)}i;  # Won't sign non-text message.
                                                  # Won't sign attachments.
    return 0 if $top->head->mime_attr('content-disposition') =~ /attachment/i;

   # Won't sign HTML parts when we already have a sig and don't allow duplicates
   # Or we are a reply and we don't sign replies.
   # We return -1 as a special token indicating that there was something we
   # could sign but chose not to. If I pick up a -1 when called then don't
   # try to sign anything else.
    return -1
      if ( $this->{sigimagepresent}
        && $MimeType =~ /text\/html/i
        && Baruwa::Scanner::Config::Value('allowmultsigs', $this) !~ /1/)
      || ($this->{isreply}
        && Baruwa::Scanner::Config::Value('isareply', $this));

    # Get body data as array of newline-terminated lines
    $top->bodyhandle or return undef;
    my @body = $top->bodyhandle->as_lines;

    # Output original data back into body, followed by message
    my ($line, $io, $FoundHTMLEnd, $FoundBodyEnd, $FoundSigMark, $html);
    $FoundHTMLEnd = 0;  # If there is no </html> tag, still append the signature
    $FoundBodyEnd = 0;  # If there is no </body> tag, still append the signature
    $FoundSigMark = 0;  # Try to replace _SIGNATURE_ with the sig if it's there
    $html         = 0;
    $io = $top->open("w");
    if ($MimeType =~ /text\/html/i) {
        $signature = $this->ReadVirusWarning('inlinehtmlsig');
        foreach $line (@body) {

            # Try to insert the signature where they want it.
            $FoundSigMark = 1 if $line =~ s/_SIGNATURE_/$signature/;
            $FoundBodyEnd = 1
              if !$FoundSigMark && $line =~ s/\<\/body\>/$signature$&/i;
            $FoundHTMLEnd = 1
              if !$FoundSigMark
              && !$FoundBodyEnd
              && $line =~ s/\<\/x?html\>/$signature$&/i;
            $io->print($line);
        }
        $io->print($signature . "\n")
          unless $FoundBodyEnd || $FoundHTMLEnd || $FoundSigMark;
        (($body[-1] || '') =~ /\n\Z/)
          or $io->print("\n");    # Ensure final newline
        $html = 1;
    } else {
        $signature = $this->ReadVirusWarning('inlinetextsig');
        foreach $line (@body) {

            # Replace _SIGNATURE_ with the inline sig, if it's present.
            $FoundSigMark = 1 if $line =~ s/_SIGNATURE_/$signature/;
            $io->print($line);    # Original body data
        }

        # Else just tack the sig on the end.
        $io->print("\n$signature\n") unless $FoundSigMark;
    }
    $io->close;

    # Add Image Attachment from Mail Scanner, unless there already is one
    if (Baruwa::Scanner::Config::Value('attachimage', $this) =~ /1/
        && !$this->{sigimagepresent}) {

        #print STDERR "Adding image signature\n";
        my $attach =
          Baruwa::Scanner::Config::Value('attachimagetohtmlonly', $this);
        if (($html && $attach =~ /1/) || $attach =~ /0/) {
            my $filename =
              Baruwa::Scanner::Config::Value('attachimagename', $this);
            my $ext = 'unknown';
            $ext = $1     if $filename =~ /\.([a-z]{3,4})$/;
            $ext = 'jpeg' if $ext =~ /jpg/i;
            my $internalname =
              Baruwa::Scanner::Config::Value('attachimageinternalname', $this);
            if (length($filename) && -f $filename) {
                my $newentity = MIME::Entity->build(
                    Path          => $filename,
                    Top           => 0,
                    Type          => "image/$ext",
                    Encoding      => "base64",
                    Filename      => $internalname,
                    Disposition   => "inline",
                    'Content-Id:' => '<' . $internalname . '>'
                );
                if ($parent && $parent->effective_type =~ /multipart\/related/i)
                {
          # It's already been signed once, so don't nest the MIME structure more
                    $parent->add_part($newentity);
                } else {

                    # It's a first-time sig, so next it into a multipart/related
                    $top->make_multipart('related');
                    $top->add_part($newentity);
                }
            }
        }
    }

    # We signed something
    return 1;
}

# Deliver an uninfected message. It is already signed as necessary.
# If the body has been modified then we need to reconstruct it from
# the MIME structure. If not modified, then just link it across to
# the outgoing queue.
sub DeliverUninfected {
    my $this = shift;

    if ($this->{bodymodified}) {

        # The body of this message has been modified, so reconstruct
        # it from the MIME structure and deliver that.
        #print STDERR "Body modified\n";
        $this->DeliverModifiedBody('cleanheader');
    } else {

        #print STDERR "Body not modified\n";
        if (Baruwa::Scanner::Config::Value('virusscan', $this) =~ /1/) {

            #print STDERR "Message is scanned and clean\n";
            $this->DeliverUnmodifiedBody('cleanheader');
        } else {

            #print STDERR "Message is unscanned\n";
            $this->DeliverUnmodifiedBody('unscannedheader');
        }
    }
}

my ($DisarmFormTag,       $DisarmScriptTag,          $DisarmCodebaseTag,
    $DisarmIframeTag,     $DisarmWebBug,             $DisarmPhishing,
    $DisarmNumbers,       $DisarmHTMLChangedMessage, $DisarmWebBugFound,
    $DisarmPhishingFound, $PhishingSubjectTag,       $PhishingHighlight,
    $StrictPhishing,      $WebBugWhitelist,          $WebBugReplacement,
    $WebBugBlacklist,     $SigImageFound
);

# Deliver a message which has not had its body modified in any way.
# This is a lot faster as it doesn't involve reconstructing the message
# body at all, it is just copied from the inqueue to the outqueue.
sub DeliverUnmodifiedBody {
    my $this = shift;
    my ($headervalue) = @_;

#print STDERR "DisarmPhishingFound = " . $DisarmPhishingFound . " for message " . $this->{id} . "\n";

    return if $this->{deleted};    # This should never happen

    # Prune the entity tree to remove all undef values
    PruneEntityTree($this->{entity}, $this->{entity2file},
        $this->{file2entity});

    #print STDERR "Delivering Unmodified Body message\n";

    my $OutQ = Baruwa::Scanner::Config::Value('outqueuedir', $this);
    my $store = $this->{store};

    # Link the queue data file from in to out
    $store->LinkData($OutQ);

  # Set up the output envelope with its (possibly modified) headers
  # Used to do next line but it breaks text-only messages with no MIME
  # structure as the MIME explosion will have created a MIME structure.
  #$global::MS->{mta}->AddHeadersToQf($this, $this->{entity}->stringify_header);
    $global::MS->{mta}->AddHeadersToQf($this);

    # Remove duplicate subject: lines
    $global::MS->{mta}->UniqHeader($this, 'Subject:');

    # Add the information/help X- header
    my $infoheader = Baruwa::Scanner::Config::Value('infoheader', $this);
    if ($infoheader) {
        my $infovalue = Baruwa::Scanner::Config::Value('infovalue', $this);
        $global::MS->{mta}->ReplaceHeader($this, $infoheader, $infovalue);
    }
    my $idheader = Baruwa::Scanner::Config::Value('idheader', $this);
    if ($idheader) {
        $global::MS->{mta}->ReplaceHeader($this, $idheader, $this->{id});
    }

    my $headervalue2 = Baruwa::Scanner::Config::Value($headervalue, $this);
    $global::MS->{mta}
      ->AddMultipleHeader($this, 'mailheader', $headervalue2, ', ')
      if $headervalue2 ne "";

    # Delete all content length headers anyway. They are unsafe.
    # No, leave them if nothing in the body has been modified.
    #$global::MS->{mta}->DeleteHeader($this, 'Content-length:');

    # Add IPv6 or IPv4 protocol version header
    my $ipverheader = Baruwa::Scanner::Config::Value('ipverheader', $this);
    $global::MS->{mta}->ReplaceHeader($this, $ipverheader,
        (($this->{clientip} =~ /:/) ? 'IPv6' : 'IPv4'))
      if $ipverheader;

    # Add the spamvirusreport to the input to SA.
    # The header name should be documented in the baruwa.conf docs.
    # 20090730
    my $svheader = Baruwa::Scanner::Config::Value('spamvirusheader', $this);
    if ($svheader && $this->{spamvirusreport}) {
        $svheader .= ':' unless $svheader =~ /:$/;
        $global::MS->{mta}
          ->AppendHeader($this, $svheader, $this->{spamvirusreport}, ' ');
    }

    $global::MS->{mta}
      ->AddMultipleHeader($this, 'spamheader', $this->{spamreport}, ', ')
      if Baruwa::Scanner::Config::Value('includespamheader', $this)
      || ($this->{spamreport} && $this->{isspam});

    # Add the spam stars if they want that. Limit it to 60 characters to avoid
    # a potential denial-of-service attack.
    my ($stars, $starcount, $scoretext, $minstars, $scorefmt);
    $starcount = int($this->{sascore}) + 0;
    $starcount = 0 if $this->{spamwhitelisted};    # 0 stars if white-listed
    $scorefmt  = Baruwa::Scanner::Config::Value('scoreformat', $this);
    $scorefmt  = '%d' if $scorefmt eq '';
    $scoretext = sprintf($scorefmt, $this->{sascore} + 0);
    $minstars  = Baruwa::Scanner::Config::Value('minstars', $this);
    $starcount = $minstars
      if $this->{isrblspam}
      && $minstars
      && $starcount < $minstars;

    if (Baruwa::Scanner::Config::Value('spamscorenotstars', $this)) {
        $stars = $scoretext;    # int($starcount);
    } else {
        $starcount = 60 if $starcount > 60;
        $stars =
          Baruwa::Scanner::Config::Value('spamstarscharacter') x $starcount;
    }
    if (Baruwa::Scanner::Config::Value('spamstars', $this) =~ /1/
        && $starcount > 0) {
        $global::MS->{mta}
          ->AddMultipleHeader($this, 'spamstarsheader', $stars, ', ');
    }

    # Add the Envelope to and from headers
    AddFromAndTo($this);

    # Repair the subject line
    $global::MS->{mta}->ReplaceHeader($this, 'Subject:', $this->{safesubject})
      if $this->{subjectwasunsafe};

# Remove duplicate subject because replaceheader does not delete if in dkimsafe mode
    $global::MS->{mta}->UniqHeader($this, 'Subject:');

    # Modify the subject line for Disarming
    my $subjectchanged = 0;
    my $disarmtag = Baruwa::Scanner::Config::Value('disarmsubjecttext', $this);
    my $phishingtag =
      Baruwa::Scanner::Config::Value('phishingsubjecttag', $this);

    if ($this->{messagedisarmed}) {

        #print STDERR "MessageDisarmed is set at 3878\n";
        my $where =
          Baruwa::Scanner::Config::Value('disarmmodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}
            ->TextEndsHeader($this, 'Subject:', $disarmtag)) {
            $global::MS->{mta}
              ->AppendHeader($this, 'Subject:', $disarmtag, ' ');
            $subjectchanged = 1;

            #print STDERR "MessageDisarmed is set (end)\n";
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $disarmtag)) {
            $global::MS->{mta}
              ->PrependHeader($this, 'Subject:', $disarmtag, ' ');
            $subjectchanged = 1;

            #print STDERR "MessageDisarmed is set (start)\n";
        }

    #print STDERR "disarmedtags = " . join(',',@{$this->{disarmedtags}}) . "\n";
    }

    #print STDERR "Hello from 3840\n";
    if ($this->{disarmphishingfound})
    {    # grep /phishing/i, @{$this->{disarmedtags}}) {
         # We found it had a phishing link in it. Are we tagging phishing Subject?
         #print STDERR "DisarmPhishingFound at 3896!\n";
         #print STDERR "ID = " . $this->{id} . "\n";
        my $where = Baruwa::Scanner::Config::Value('tagphishingsubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}
            ->TextEndsHeader($this, 'Subject:', $phishingtag)) {

            #print STDERR "end\n";
            $global::MS->{mta}
              ->AppendHeader($this, 'Subject:', $phishingtag, ' ');
            $subjectchanged = 1;
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $phishingtag)) {

            #print STDERR "start\n";
            $global::MS->{mta}
              ->PrependHeader($this, 'Subject:', $phishingtag, ' ');
            $subjectchanged = 1;
        }

        #}
    }

    # Add watermark header if chosen to do so.
    if ($this->{addmshmac}) {
        my $mshmacheader =
          Baruwa::Scanner::Config::Value('mshmacheader', $this);
        my $mshmac = $this->{mshmac};

        $global::MS->{mta}->ReplaceHeader($this, $mshmacheader, $mshmac);
    }

    # Modify the subject line for spam
    # if it's spam AND they want to modify the subject line AND it's not
    # already been modified by another of your Baruwas.
    my $spamtag = Baruwa::Scanner::Config::Value('spamsubjecttext', $this);
    $spamtag =~ s/_SCORE_/$scoretext/;
    $spamtag =~ s/_STARS_/$stars/i;

    if ($this->{isspam} && !$this->{ishigh}) {
        my $where = Baruwa::Scanner::Config::Value('spammodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}->TextEndsHeader($this, 'Subject:', $spamtag))
        {   $global::MS->{mta}->AppendHeader($this, 'Subject:', $spamtag, ' ');
            $subjectchanged = 1;
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $spamtag)) {
            $global::MS->{mta}->PrependHeader($this, 'Subject:', $spamtag, ' ');
            $subjectchanged = 1;
        }
    }

    # If it is high-scoring spam, then add a different bit of text
    $spamtag = Baruwa::Scanner::Config::Value('highspamsubjecttext', $this);
    $spamtag =~ s/_SCORE_/$scoretext/;
    $spamtag =~ s/_STARS_/$stars/i;

    if ($this->{isspam} && $this->{ishigh}) {
        my $where =
          Baruwa::Scanner::Config::Value('highspammodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}->TextEndsHeader($this, 'Subject:', $spamtag))
        {   $global::MS->{mta}->AppendHeader($this, 'Subject:', $spamtag, ' ');
            $subjectchanged = 1;
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $spamtag)) {
            $global::MS->{mta}->PrependHeader($this, 'Subject:', $spamtag, ' ');
            $subjectchanged = 1;
        }
    }

    # Modify the subject line for scanning -- but only do it if the
    # subject hasn't already been modified by Baruwa for another reason.
    my $modifscan =
      Baruwa::Scanner::Config::Value('scannedmodifysubject', $this);
    my $scantag = Baruwa::Scanner::Config::Value('scannedsubjecttext', $this);
    if (   $modifscan =~ /start/
        && !$subjectchanged
        && !$global::MS->{mta}->TextStartsHeader($this, 'Subject:', $scantag)) {
        $global::MS->{mta}->PrependHeader($this, 'Subject:', $scantag, ' ');
        $subjectchanged = 1;
    } elsif ($modifscan =~ /end|1/
        && !$subjectchanged
        && !$global::MS->{mta}->TextEndsHeader($this, 'Subject:', $scantag)) {
        $global::MS->{mta}->AppendHeader($this, 'Subject:', $scantag, ' ');
        $subjectchanged = 1;
    }

    # Remove any headers we don't want in the message
    my (@removeme, $remove);
    @removeme =
      split(/[,\s]+/, Baruwa::Scanner::Config::Value('removeheaders', $this));
    foreach $remove (@removeme) {

        # Add a : if there isn't one already, it's needed for DeleteHeader()
        # 20090312 Done in DeleteHeader: $remove .= ':' unless $remove =~ /:$/;
        $global::MS->{mta}->DeleteHeader($this, $remove);
    }

    # Add the extra headers they want for spam messages
    my (@extraheaders, $extraheader);
    my ($key,          $value);
    push @extraheaders, @{$this->{extraspamheaders}}
      if $this->{extraspamheaders};
    foreach $extraheader (@extraheaders) {

        #print STDERR "Unmod Adding extra header $extraheader\n";
        next unless $extraheader =~ /:/;
        ($key, $value) = split(/:\s*/, $extraheader, 2);
        $key =~ s/\s+/-/g;    # Replace spaces in header name with dashes

        # Replace _TO_ in the header value with a comma-separated list of recips
        if ($value =~ /_TO_/) {

            # Get the actual text for the header value
            my ($recipient, %tolist);
            foreach $recipient (@{$this->{to}}) {
                $tolist{$recipient} = 1;
            }
            $recipient = join(', ', sort keys %tolist);

            # Now reflow the To list in case it is very long
            $recipient = $this->ReflowHeader($key . ':', $recipient);
            $value =~ s/_TO_/$recipient/g;
        }

        $global::MS->{mta}
          ->AddMultipleHeaderName($this, $key . ':', $value, ', ');
    }

    # Add the secret archive recipients
    my ($extra, @extras, %alreadydone);
    foreach $extra (@{$this->{archiveplaces}}) {

        # Email archive recipients include a '@'
        next if $extra =~ /^\//;
        next unless $extra =~ /@/;
        $extra =~ s/_HOUR_/$this->{hournumber}/g;
        $extra =~ s/_DATE_/$this->{datenumber}/g;
        $extra =~ s/_FROMUSER_/$this->{fromuser}/g;
        $extra =~ s/_FROMDOMAIN_/$this->{fromdomain}/g;
        if ($extra !~ /_TOUSER_|_TODOMAIN_/) {

            # It's a simple email address
            push @extras, $extra unless $alreadydone{$extra};
            $alreadydone{$extra} = 1;
        } else {

          # It contains a substitution so we need to loop through all the recips
            my $numrecips = scalar(@{$this->{to}});
            foreach my $recip (0 .. $numrecips - 1) {
                my $extracopy = $extra;
                my $u         = $this->{touser}[$recip];
                my $d         = $this->{todomain}[$recip];
                $extracopy =~ s/_TOUSER_/$u/g;
                $extracopy =~ s/_TODOMAIN_/$d/g;
                push @extras, $extracopy unless $alreadydone{$extracopy};
                $alreadydone{$extracopy} = 1;  # Dont add the same address twice
            }
        }
    }
    $global::MS->{mta}->AddRecipients($this, @extras) if @extras;

    # Write the new qf file, delete originals and unlock the message
    $store->WriteHeader($this, $OutQ);
    unless ($this->{gonefromdisk}) {
        $store->DeleteUnlock();
        $this->{gonefromdisk} = 1;
    }

    # Note this does not kick the MTA into life here any more
}

# Deliver a message which has had its body modified.
# This is slower as the message has to be reconstructed from all its
# MIME entities.
sub DeliverModifiedBody {
    my $this = shift;
    my ($headervalue) = @_;

    return if $this->{deleted};    # This should never happen

#print STDERR "Delivering Modified Body message with header \"$headervalue\"\n";

    my $store = $this->{store};

    # If there is no data structure at all for this message, then we
    # can't sensibly deliver anything, so just delete it.
    # The parsing must have failed completely.
    my $entity = $this->{entity};
    unless ($entity) {

        #print STDERR "Deleting duff message\n";
        unless ($this->{gonefromdisk}) {
            $store->DeleteUnlock();
            $this->{gonefromdisk} = 1;
        }
        return;
    }

    # Prune the entity tree to remove all undef values
    #PruneEntityTree($this->{entity},$this->{entity2file},$this->{file2entity});
    PruneEntityTree($entity, $this->{entity2file}, $this->{file2entity});

    my $OutQ = Baruwa::Scanner::Config::Value('outqueuedir', $this);

    # Write the new body file
    #print STDERR "Writing the MIME body of $this, " . $this->{id} . "\n";
    $store->WriteMIMEBody($this->{id}, $entity, $OutQ);

    #print STDERR "Written the MIME body\n";

    # Set up the output envelope with its (possibly modified) headers
    $global::MS->{mta}
      ->AddHeadersToQf($this, $this->{entity}->stringify_header);

    # Remove duplicate subject: lines
    $global::MS->{mta}->UniqHeader($this, 'Subject:');

    # Add the information/help X- header
    my $infoheader = Baruwa::Scanner::Config::Value('infoheader', $this);
    if ($infoheader) {
        my $infovalue = Baruwa::Scanner::Config::Value('infovalue', $this);
        $global::MS->{mta}->ReplaceHeader($this, $infoheader, $infovalue);
    }
    my $idheader = Baruwa::Scanner::Config::Value('idheader', $this);
    if ($idheader) {
        $global::MS->{mta}->ReplaceHeader($this, $idheader, $this->{id});
    }

    # Add the clean/dirty header
    #print STDERR "Adding clean/dirty header $headervalue\n";
    my $headervalue2 = Baruwa::Scanner::Config::Value($headervalue, $this);
    $global::MS->{mta}
      ->AddMultipleHeader($this, 'mailheader', $headervalue2, ', ')
      if $headervalue2 ne "";

    # Delete all content length headers as the body has been modified.
    $global::MS->{mta}->DeleteHeader($this, 'Content-length:');

    # Add IPv6 or IPv4 protocol version header
    my $ipverheader = Baruwa::Scanner::Config::Value('ipverheader', $this);
    $global::MS->{mta}->ReplaceHeader($this, $ipverheader,
        (($this->{clientip} =~ /:/) ? 'IPv6' : 'IPv4'))
      if $ipverheader;

    # Add the spamvirusreport to the input to SA.
    # The header name should be documented in the baruwa.conf docs.
    # 20090730
    my $svheader = Baruwa::Scanner::Config::Value('spamvirusheader', $this);
    if ($svheader && $this->{spamvirusreport}) {
        $svheader .= ':' unless $svheader =~ /:$/;
        $global::MS->{mta}
          ->AppendHeader($this, $svheader, $this->{spamvirusreport}, ' ');
    }

    $global::MS->{mta}
      ->AddMultipleHeader($this, 'spamheader', $this->{spamreport}, ', ')
      if Baruwa::Scanner::Config::Value('includespamheader', $this)
      || ($this->{spamreport} && $this->{isspam});

    # Add the spam stars if they want that. Limit it to 60 characters to avoid
    # a potential denial-of-service attack.
    my ($stars, $starcount, $scoretext, $minstars, $scorefmt);
    $starcount = int($this->{sascore}) + 0;
    $starcount = 0 if $this->{spamwhitelisted};    # 0 stars if white-listed
    $scorefmt  = Baruwa::Scanner::Config::Value('scoreformat', $this);
    $scorefmt  = '%d' if $scorefmt eq '';
    $scoretext = sprintf($scorefmt, $this->{sascore} + 0);
    $minstars  = Baruwa::Scanner::Config::Value('minstars', $this);
    $starcount = $minstars
      if $this->{isrblspam}
      && $minstars
      && $starcount < $minstars;

    if (Baruwa::Scanner::Config::Value('spamscorenotstars', $this)) {
        $stars = $scoretext;    # int($starcount);
    } else {
        $starcount = 60 if $starcount > 60;
        $stars =
          Baruwa::Scanner::Config::Value('spamstarscharacter') x $starcount;
    }
    if (Baruwa::Scanner::Config::Value('spamstars', $this) =~ /1/
        && $starcount > 0) {
        $global::MS->{mta}
          ->AddMultipleHeader($this, 'spamstarsheader', $stars, ', ');
    }

    # Add the Envelope to and from headers
    AddFromAndTo($this);

    # Repair the subject line
    #print STDERR "Metadata is " . join("\n", @{$this->{metadata}}) . "\n";
    $global::MS->{mta}->ReplaceHeader($this, 'Subject:', $this->{safesubject})
      if $this->{subjectwasunsafe};

# Remove duplicate subject because replaceheader does not delete if in dkimsafe mode
    $global::MS->{mta}->UniqHeader($this, 'Subject:');

    my $subjectchanged = 0;

    # Modify the subject line for viruses or filename traps.
    # Only use the filename trap test if it isn't infected by anything else.
    my $nametag = Baruwa::Scanner::Config::Value('namesubjecttext', $this);
    my $contenttag =
      Baruwa::Scanner::Config::Value('contentsubjecttext', $this);
    my $sizetag = Baruwa::Scanner::Config::Value('sizesubjecttext', $this);

    #print STDERR "I have triggered a size trap\n" if $this->{sizeinfected};
    if ($this->{nameinfected}   &&  # Triggered a filename trap
        !$this->{virusinfected} &&  # No other reports about it
        !$this->{otherinfected} &&  # They want the tagging & not already tagged
        !$global::MS->{mta}->TextStartsHeader($this, 'Subject:', $nametag)
      ) {

        my $where = Baruwa::Scanner::Config::Value('namemodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}->TextEndsHeader($this, 'Subject:', $nametag))
        {   $global::MS->{mta}->AppendHeader($this, 'Subject:', $nametag, ' ');
            $subjectchanged = 1;
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $nametag)) {
            $global::MS->{mta}->PrependHeader($this, 'Subject:', $nametag, ' ');
            $subjectchanged = 1;
        }

    } elsif (
        $this->{sizeinfected}   &&                       # Triggered a size trap
        !$this->{virusinfected} && !$this->{nameinfected}
      ) {

        my $where = Baruwa::Scanner::Config::Value('sizemodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}->TextEndsHeader($this, 'Subject:', $sizetag))
        {   $global::MS->{mta}->AppendHeader($this, 'Subject:', $sizetag, ' ');
            $subjectchanged = 1;
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $sizetag)) {
            $global::MS->{mta}->PrependHeader($this, 'Subject:', $sizetag, ' ');
            $subjectchanged = 1;
        }

    } elsif (
        $this->{otherinfected}  &&    # Triggered a content trap
        !$this->{virusinfected} &&    # No other reports about it
        !$this->{nameinfected}
      ) {

        my $where =
          Baruwa::Scanner::Config::Value('contentmodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}
            ->TextEndsHeader($this, 'Subject:', $contenttag)) {
            $global::MS->{mta}
              ->AppendHeader($this, 'Subject:', $contenttag, ' ');
            $subjectchanged = 1;
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $contenttag)) {
            $global::MS->{mta}
              ->PrependHeader($this, 'Subject:', $contenttag, ' ');
            $subjectchanged = 1;
        }

    } else {

        # It may be really virus infected.
        # Modify the subject line for viruses
        # if it's infected AND they want to modify the subject line AND it's not
        # already been modified by another of your Baruwas.
        my $virustag =
          Baruwa::Scanner::Config::Value('virussubjecttext', $this);

        #print STDERR "I am infected\n" if $this->{infected};

        if ($this->{infected}) {
            my $where =
              Baruwa::Scanner::Config::Value('virusmodifysubject', $this);
            if ($where =~ /end/
                && !$global::MS->{mta}
                ->TextEndsHeader($this, 'Subject:', $virustag)) {
                $global::MS->{mta}
                  ->AppendHeader($this, 'Subject:', $virustag, ' ');
                $subjectchanged = 1;
            } elsif ($where =~ /start|1/
                && !$global::MS->{mta}
                ->TextStartsHeader($this, 'Subject:', $virustag)) {
                $global::MS->{mta}
                  ->PrependHeader($this, 'Subject:', $virustag, ' ');
                $subjectchanged = 1;
            }
        }

    }

    # Modify the subject line for Disarming
    my $disarmtag = Baruwa::Scanner::Config::Value('disarmsubjecttext', $this);
    my $phishingtag =
      Baruwa::Scanner::Config::Value('phishingsubjecttag', $this);

    #print STDERR "phishingtag = $phishingtag\n";
    if ($this->{messagedisarmed}) {

        my $where =
          Baruwa::Scanner::Config::Value('disarmmodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}
            ->TextEndsHeader($this, 'Subject:', $disarmtag)) {
            $global::MS->{mta}
              ->AppendHeader($this, 'Subject:', $disarmtag, ' ');
            $subjectchanged = 1;

            #print STDERR "MessageDisarmed is set (end)\n";
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $disarmtag)) {
            $global::MS->{mta}
              ->PrependHeader($this, 'Subject:', $disarmtag, ' ');
            $subjectchanged = 1;

            #print STDERR "MessageDisarmed is set (start)\n";
        }
    }

    if ($this->{disarmphishingfound}) {

    #print STDERR "disarmedtags = " . join(',',@{$this->{disarmedtags}}) . "\n";
    # We found it had a phishing link in it. Are we tagging phishing Subject?
        my $where = Baruwa::Scanner::Config::Value('tagphishingsubject', $this);

#print STDERR "Where is $where\n";
#print STDERR "Subject tag check = " . $global::MS->{mta}->TextStartsHeader($this, 'Subject:', $phishingtag) . "***\n";
        if ($where =~ /end/
            && !$global::MS->{mta}
            ->TextEndsHeader($this, 'Subject:', $phishingtag)) {
            $global::MS->{mta}
              ->AppendHeader($this, 'Subject:', $phishingtag, ' ');
            $subjectchanged = 1;

            #print STDERR "end\n";
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $phishingtag)) {
            $global::MS->{mta}
              ->PrependHeader($this, 'Subject:', $phishingtag, ' ');
            $subjectchanged = 1;

            #print STDERR "start\n";
        }
    }

    # Add watermark header if chosen to do so.
    if ($this->{addmshmac}) {
        my $mshmacheader =
          Baruwa::Scanner::Config::Value('mshmacheader', $this);
        my $mshmac = $this->{mshmac};

        $global::MS->{mta}->ReplaceHeader($this, $mshmacheader, $mshmac);
    }

    # Modify the subject line for spam
    # if it's spam AND they want to modify the subject line AND it's not
    # already been modified by another of your Baruwas.
    my $spamtag = Baruwa::Scanner::Config::Value('spamsubjecttext', $this);
    $spamtag =~ s/_SCORE_/$scoretext/;
    $spamtag =~ s/_STARS_/$stars/i;

    if ($this->{isspam} && !$this->{ishigh}) {
        my $where = Baruwa::Scanner::Config::Value('spammodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}->TextEndsHeader($this, 'Subject:', $spamtag))
        {   $global::MS->{mta}->AppendHeader($this, 'Subject:', $spamtag, ' ');
            $subjectchanged = 1;
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $spamtag)) {
            $global::MS->{mta}->PrependHeader($this, 'Subject:', $spamtag, ' ');
            $subjectchanged = 1;
        }
    }

    # If it is high-scoring spam, then add a different bit of text
    $spamtag = Baruwa::Scanner::Config::Value('highspamsubjecttext', $this);
    $spamtag =~ s/_SCORE_/$scoretext/;
    $spamtag =~ s/_STARS_/$stars/i;

    if ($this->{isspam} && $this->{ishigh}) {
        my $where =
          Baruwa::Scanner::Config::Value('highspammodifysubject', $this);
        if ($where =~ /end/
            && !$global::MS->{mta}->TextEndsHeader($this, 'Subject:', $spamtag))
        {   $global::MS->{mta}->AppendHeader($this, 'Subject:', $spamtag, ' ');
            $subjectchanged = 1;
        } elsif ($where =~ /start|1/
            && !$global::MS->{mta}
            ->TextStartsHeader($this, 'Subject:', $spamtag)) {
            $global::MS->{mta}->PrependHeader($this, 'Subject:', $spamtag, ' ');
            $subjectchanged = 1;
        }
    }

    # Modify the subject line for scanning -- but only do it if the
    # subject hasn't already been modified by Baruwa for another reason.
    my $modifscan =
      Baruwa::Scanner::Config::Value('scannedmodifysubject', $this);
    my $scantag = Baruwa::Scanner::Config::Value('scannedsubjecttext', $this);
    if (   $modifscan =~ /start/
        && !$subjectchanged
        && !$global::MS->{mta}->TextStartsHeader($this, 'Subject:', $scantag)) {
        $global::MS->{mta}->PrependHeader($this, 'Subject:', $scantag, ' ');
    } elsif ($modifscan =~ /end|1/
        && !$subjectchanged
        && !$global::MS->{mta}->TextEndsHeader($this, 'Subject:', $scantag)) {
        $global::MS->{mta}->AppendHeader($this, 'Subject:', $scantag, ' ');
    }

    # Remove any headers we don't want in the message
    my (@removeme, $remove);
    @removeme =
      split(/[,\s]+/, Baruwa::Scanner::Config::Value('removeheaders', $this));
    foreach $remove (@removeme) {

        # Add a : if there isn't one already, it's needed for DeleteHeader()
        # 20090312 Done in DeleteHeader: $remove .= ':' unless $remove =~ /:$/;
        $global::MS->{mta}->DeleteHeader($this, $remove);
    }

    # Add the extra headers they want for spam messages
    my (@extraheaders, $extraheader);
    my ($key,          $value);
    push @extraheaders, @{$this->{extraspamheaders}}
      if $this->{extraspamheaders};
    foreach $extraheader (@extraheaders) {

        #print STDERR "Mod Adding extra header $extraheader\n";
        next unless $extraheader =~ /:/;
        ($key, $value) = split(/:\s*/, $extraheader, 2);
        $key =~ s/\s+/-/g;    # Replace spaces in header name with dashes

        # Replace _TO_ in the header value with a comma-separated list of recips
        if ($value =~ /_TO_/) {

            # Get the actual text for the header value
            my ($recipient, %tolist);
            foreach $recipient (@{$this->{to}}) {
                $tolist{$recipient} = 1;
            }
            $recipient = join(', ', sort keys %tolist);

            # Now reflow the To list in case it is very long
            $recipient = $this->ReflowHeader($key . ':', $recipient);
            $value =~ s/_TO_/$recipient/g;
        }

        $global::MS->{mta}
          ->AddMultipleHeaderName($this, $key . ':', $value, ', ');
    }

    # Add the secret archive recipients
    my ($extra, @extras, %alreadydone);
    foreach $extra (@{$this->{archiveplaces}}) {

        # Email archive recipients include a '@'
        next if $extra =~ /^\//;
        next unless $extra =~ /@/;
        $extra =~ s/_HOUR_/$this->{hournumber}/g;
        $extra =~ s/_DATE_/$this->{datenumber}/g;
        $extra =~ s/_FROMUSER_/$this->{fromuser}/g;
        $extra =~ s/_FROMDOMAIN_/$this->{fromdomain}/g;
        if ($extra !~ /_TOUSER_|_TODOMAIN_/) {

            # It's a simple email address
            push @extras, $extra unless $alreadydone{$extra};
            $alreadydone{$extra} = 1;
        } else {

          # It contains a substitution so we need to loop through all the recips
            my $numrecips = scalar(@{$this->{to}});
            foreach my $recip (0 .. $numrecips - 1) {
                my $extracopy = $extra;
                my $u         = $this->{touser}[$recip];
                my $d         = $this->{todomain}[$recip];
                $extracopy =~ s/_TOUSER_/$u/g;
                $extracopy =~ s/_TODOMAIN_/$d/g;
                push @extras, $extracopy unless $alreadydone{$extracopy};
                $alreadydone{$extracopy} = 1;  # Dont add the same address twice
            }
        }
    }
    $global::MS->{mta}->AddRecipients($this, @extras) if @extras;

    # Write the new qf file, delete originals and unlock the message
    #print STDERR "Writing the new qf file\n";
    $store->WriteHeader($this, $OutQ);
    unless ($this->{gonefromdisk}) {
        $store->DeleteUnlock();
        $this->{gonefromdisk} = 1;
    }

    # Note this does not kick the MTA into life here any more
}

# Prune all the undef branches out of an entity tree
sub PruneEntityTree {
    my ($entity, $entity2file, $file2entity) = @_;

    return undef   unless $entity;
    return $entity unless $entity->parts;

    my (@newparts, $part, $newpart, $counter);

 # Do a pre-traversal depth-first search of the tree
 #print STDERR "Looking at $entity, has " . scalar($entity->parts) . " parts\n";
    foreach $part ($entity->parts) {

        #print STDERR "$counter Going down to $part\n";
        next unless $part;

        #print STDERR "Non null $part\n";
        $newpart = PruneEntityTree($part, $entity2file, $file2entity);

        #print STDERR "Replacement is $newpart\n";
        if ($newpart) {

            #print STDERR "Adding replacement $newpart\n";
            push @newparts, $newpart;
        }

        #print STDERR "Coming up, added $newpart\n";
    }

    #print STDERR "About to return\n";
    # Keep all the parts we found, prune as much as we can
    if (@newparts) {

    #print STDERR "Returning entity $entity with " . join(',',@newparts) . "\n";
        $entity->parts(\@newparts);
        return $entity;
    } else {

        #print STDERR "Returning undef\n";
        return undef;
    }
}

# Delete a message from the incoming queue
sub DeleteMessage {
    my $this = shift;

    #print STDERR "DeletingMessage " . $this->{id} . "\n";

    unless ($this->{gonefromdisk}) {
        $this->{store}->DeleteUnlock();
        $this->{gonefromdisk} = 1;
    }
    $this->{deleted}   = 1;
    $this->{abandoned} = 0;    # It was intentionally deleted
}

# Work out if the message is infected with a "silent" virus such as Klez.
# Set the "silent" flag on all such messages.
# At the same time, find the "noisy" non-spoofing infections such as
# document macro viruses.
sub FindSilentAndNoisyInfections {
    my $this = shift;

    my (@silentin) =
      split(" ", Baruwa::Scanner::Config::Value('silentviruses', $this));
    my ($silent,     $silentin,  @silent, $regexp,
        $allreports, $logstring, $allsilent
    );
    my ($virusreports);

    my (@noisyin) =
      split(" ", Baruwa::Scanner::Config::Value('noisyviruses', $this));
    my ($noisy, $noisyin, @noisy, $nregexp);

    # Get out quickly if there's nothing to do
    return unless @silentin || @noisyin;

    # Turn each silent and noisy report into a regexp
    $allsilent = 0;
    foreach $silent (@silentin) {
        if (lc($silent) eq 'all-viruses') {
            $allsilent = 1;
            next;
        }
        $silentin = quotemeta $silent;
        push @silent, $silentin;
    }
    foreach $noisy (@noisyin) {
        next if lc($noisy) eq 'all-viruses';
        $noisyin = quotemeta $noisy;
        push @noisy, $noisyin;
    }

    # Make 2 big regexps from them all
    $regexp  = "";
    $nregexp = "";
    $regexp  = '(?:' . join(')|(?:', @silent) . ')' if @silent;
    $nregexp = '(?:' . join(')|(?:', @noisy) . ')' if @noisy;

    # Make 1 big string from all the reports
    $allreports   = join('',  values %{$this->{allreports}});
    $virusreports = join(' ', values %{$this->{virusreports}});

    # Do this with grep so I can extract the matching line.
    $this->{silent} = 1
      if $regexp && grep {$logstring .= "$_ " if /$regexp/i;}
      values %{$this->{allreports}};
    if ($allsilent && $virusreports) {
        $this->{silent} = 1;
        $logstring .= $virusreports;
    }
    $this->{noisy} = 1
      if $nregexp && grep /$nregexp/i,
      values %{$this->{allreports}};

    return unless Baruwa::Scanner::Config::Value('logsilentviruses', $this);

    $logstring = join(',', values %{$this->{allreports}})
      if !$logstring && $allsilent && $this->{silent} == 1;
    $logstring =~ s/[\n,]+(.)/,$1/g;
    Baruwa::Scanner::Log::NoticeLog("Viruses marked as silent: %s", $logstring)
      if $logstring;
}

# Deliver a cleaned message and remove it from the incoming queue
sub DeliverCleaned {
    my $this = shift;

    # The body of this message has been modified, so reconstruct
    # it from the MIME structure and deliver that.
    #print STDERR "Delivering cleaned up message " . $this->{id} . "\n";
    $this->DeliverModifiedBody('dirtyheader');
}

# Send a warning message to the person who sent this message.
# Need to create variables for from, to, subject, date and report
# for use within the message.
sub WarnSender {
    my $this = shift;

    my ($from, $to, $subject, $date, $allreports, $alltypes, $report, $type);
    my ($entityreports, @everyreportin, $entitytypes, @everytype);
    my ($emailmsg, $line, $messagefh, $msgname, $localpostmaster, $id);
    my ($hostname, $postmastername, $messagesize, $maxmessagesize);

    # Do we want to send the sender a warning at all?
    # If nosenderprecedence is set to non-blank and contains this
    # message precedence header, then just return.
    my (@preclist, $prec, $precedence, $header);
    @preclist =
      split(" ",
        lc(Baruwa::Scanner::Config::Value('nosenderprecedence', $this)));
    $precedence = "";
    foreach $header (@{$this->{headers}}) {
        $precedence = lc($1) if $header =~ /^precedence:\s+(\S+)/i;
    }
    if (@preclist && $precedence ne "") {
        foreach $prec (@preclist) {
            if ($precedence eq $prec) {
                Baruwa::Scanner::Log::InfoLog(
                    "Skipping sender of precedence %s", $precedence);
                return;
            }
        }
    }

    # Now we know we want to send the message, it's not a bulk mail
    $from = $this->{from};

    # Don't ever send a message to "" or "<>"
    return if $from eq "" || $from eq "<>";

    # Setup other variables they can use in the message template
    $id              = $this->{id};
    $localpostmaster = Baruwa::Scanner::Config::Value('localpostmaster', $this);
    $postmastername  = Baruwa::Scanner::Config::LanguageValue($this, 'baruwa');
    $hostname        = Baruwa::Scanner::Config::Value('hostname', $this);
    $subject         = $this->{subject};
    $date           = $this->{datestring};      # scalar localtime;
                                                # Some more for the size reports
    $messagesize    = $this->{size};
    $maxmessagesize = $this->{maxmessagesize};

    my (%tolist);
    foreach $to (@{$this->{to}}) {
        $tolist{$to} = 1;
    }
    $to = join(', ', sort keys %tolist);

    $allreports    = $this->{allreports};
    $entityreports = $this->{entityreports};
    push @everyreportin, values %$allreports;
    push @everyreportin, values %$entityreports;
    my $reportword = Baruwa::Scanner::Config::LanguageValue($this, "report");
    my ($reportline, @everyreport);
    foreach $reportline (@everyreportin) {
        push @everyreport,
          map {((/^$reportword: /m) ? $_ : "$reportword: $_") . "\n"}
          split(/\n/, $reportline);
    }

    #print STDERR "Reports are \"" . join('", "', @everyreport) . "\"\n";
    my %seen = ();
    $report = join('', grep {!$seen{$_}++} @everyreport);

    #print STDERR "***Report to sender is***\n$report***END***\n";

    $alltypes    = $this->{alltypes};
    $entitytypes = $this->{entitytypes};
    push @everytype, values %$alltypes;
    push @everytype, values %$entitytypes;
    $type = join('', @everytype);

    # Do we want to hide the directory and message id from the report path?
    if (Baruwa::Scanner::Config::Value('hideworkdir', $this)) {
        my $pattern = "(" . quotemeta($global::MS->{work}->{dir}) . "|\\\.)/";
        $report =~ s/$pattern//g;     # m # Remove the work dir
        $report =~ s/\/?$id\/?//g;    # Remove the message id
    }

    # Set the report filename dependent on what triggered Baruwa, be it
    # a virus, a filename trap, a Denial Of Service attack, or an parsing error.
    if ($type =~ /v/i) {
        $msgname = Baruwa::Scanner::Config::Value('sendervirusreport', $this);
    } elsif ($type =~ /f/i) {
        $msgname =
          Baruwa::Scanner::Config::Value('senderfilenamereport', $this);
    } elsif ($type =~ /e/i) {
        $msgname = Baruwa::Scanner::Config::Value('sendererrorreport', $this);
    } elsif ($type =~ /c/i) {
        $msgname = Baruwa::Scanner::Config::Value('sendercontentreport', $this);
    } elsif ($type =~ /s/i) {
        $msgname = Baruwa::Scanner::Config::Value('sendersizereport', $this);
    } else {
        $msgname = Baruwa::Scanner::Config::Value('sendervirusreport', $this);
    }

    #print STDERR "Report is $msgname\n";

    # Work out the list of all the infected attachments, including
    # reports applying to the whole message
    my ($attach, $text, %infected, $filename);
    while (($attach, $text) = each %$allreports) {
        if ($attach eq "") {
            $infected{
                Baruwa::Scanner::Config::LanguageValue($this,
                    "theentiremessage")
              }
              = 1;
        } else {
            $infected{substr($attach, 1)} = 1;    # Remove the type identifier
        }
    }

    # And don't forget the external bodies which are just entity reports
    while (($attach, $text) = each %$entityreports) {
        $infected{Baruwa::Scanner::Config::LanguageValue($this, 'notnamed')} =
          1;
    }
    $filename = join(', ', keys %infected);

    $messagefh = new FileHandle;
    $messagefh->open($msgname)
      or Baruwa::Scanner::Log::WarnLog("Cannot open message file %s, %s",
        $msgname, $!);
    $emailmsg = "";
    while (<$messagefh>) {
        chomp;
        s#"#\\"#g;
        s#@#\\@#g;

        # Boring untainting again...
        /(.*)/;
        $line = eval "\"$1\"";
        $emailmsg .= Baruwa::Scanner::Config::DoPercentVars($line) . "\n";
    }
    $messagefh->close();

    # This did say $localpostmaster in the last parameter, but I changed
    # it to '<>' so that the sender warnings couldn't bounce.
    $global::MS->{mta}->SendMessageString($this, $emailmsg, '<>')
      or Baruwa::Scanner::Log::WarnLog("Could not send sender warning, %s", $!);
}

# Create the headers for a postmaster notification message.
# This is expensive so don't do it much!
sub CreatePostmasterHeaders {
    my $this = shift;
    my ($to) = @_;

    my ($result, $charset);

    # Make sure the Postmaster notice is in the right character set
    $charset = Baruwa::Scanner::Config::Value('attachmentcharset', $this);

    $result =
        "From: \""
      . Baruwa::Scanner::Config::Value('noticesfrom',     $this) . "\" <"
      . Baruwa::Scanner::Config::Value('localpostmaster', $this)
      . ">\nTo: ";
    $result .=
        $to
      . "\nSubject: "
      . Baruwa::Scanner::Config::LanguageValue($this, 'noticesubject') . "\n";
    $result .= "Content-type: text/plain; charset=$charset\n" if $charset;

    return $result;
}

# Create the notification text for 1 email message.
sub CreatePostmasterNotice {
    my $this = shift;

    my (@everyrept);
    push @everyrept, values %{$this->{allreports}};
    push @everyrept, values %{$this->{entityreports}};

    foreach (@everyrept) {
        chomp;
        s/\n/\n            /g;
        $_ .= "\n";
    }

    my $reportword = Baruwa::Scanner::Config::LanguageValue($this, "report");
    my $id         = $this->{id};
    my $from       = $this->{from};

    #my $to   = join(', ', @{$this->{to}});
    my $subj = $this->{subject};
    my $ip   = $this->{clientip};
    my $rept = join("    $reportword: ", @everyrept);

    #print STDERR "Rept is\n$rept\n";

    # Build list of unique archive and quarantine storage locations
    my @quarantines = grep /\//, @{$this->{archiveplaces}};
    push @quarantines, grep /\//, @{$this->{quarantineplaces}};
    my ($quarantine, %quarantinelist);
    foreach $quarantine (@quarantines) {
        $quarantinelist{$quarantine} = 1;
    }
    $quarantine = join(', ', sort keys %quarantinelist);

    # Build unique list of recipients. Avoids Postfix problem which has
    # separate lists of real recipients and original recipients.
    my ($to, %tolist);
    foreach $to (@{$this->{to}}) {
        $tolist{$to} = 1;
    }
    $to = join(', ', sort keys %tolist);

    my ($result, $headers);

    if (Baruwa::Scanner::Config::Value('hideworkdirinnotice', $this)) {
        my $pattern = '(' . quotemeta($global::MS->{work}->{dir}) . "|\\\.)/";

        #print STDERR "In replacement, regexp is \"$pattern\"\n";
        $rept =~ s/$pattern//g;     #m # Remove the work dir
        $rept =~ s/\/?$id\/?//g;    # Remove the message id
    }

    my $reportspaces = 10 - length($reportword);
    $reportword = ' ' x $reportspaces . $reportword if $reportspaces > 0;
    $result = "\n"
      . "    Sender: $from\n"
      . "IP Address: $ip\n"
      . " Recipient: $to\n"
      . "   Subject: $subj\n"
      . " MessageID: $id\n"
      . "Quarantine: $quarantine\n"
      . "$reportword: $rept\n";

    if (Baruwa::Scanner::Config::Value('noticefullheaders', $this)) {
        $headers = join("\n ", $global::MS->{mta}->OriginalMsgHeaders($this));
        $result .=
          Baruwa::Scanner::Config::LanguageValue($this, 'fullheadersare')
          . ":\n\n $headers\n\n";
    }

    $result;
}

# Find the attachments that have been disinfected and deliver them all
# in a new MIME message.
sub DeliverDisinfectedAttachments {
    my $this = shift;

    my (@list, $reports, $attachment);

    $reports = $this->{oldviruses};

    # Loop through every attachment in the original list.
    # $attachment will contain the type indicator.
    foreach $attachment (keys %$reports) {

       #print STDERR "Looking to see if \"$attachment\" has been disinfected\n";
       # Never attempt "whole body" disinfections
        next if $attachment eq "";

        # Skip messages that are in the new report list
        next if defined $this->{virusreports}{"$attachment"};

        # Don't disinfect files the disinfector renamed
        if (!$global::MS->{work}->FileExists($this, $attachment)) {

            #print STDERR "Skipping deleted/renamed attachment $attachment\n";
            next;
        }

        # Add it to the list
        #print STDERR "Adding $attachment to list of disinfected files\n";
        push @list, $attachment;
    }

    # Is there nothing to do?
    return unless @list;

    #print STDERR "Have disinfected attachments " . join(',',@list) . "\n";
    # Deliver a message to the original recipients containing the
    # disinfected attachments. This is really a Sendmail-specific thing.
    $global::MS->{work}->ChangeToMessage($this);
    $this->DeliverFiles(@list);
}

# Create and deliver a new message from Baruwa about the
# disinfected files passed in @list.
sub DeliverFiles {
    my $this = shift;
    my (@files) = @_;

    my ($MaxSubjectLength, $from, $to, $subject, $newsubject, $top);
    my ($localpostmaster, $postmastername);
    $MaxSubjectLength = 25;
    $from             = $this->{from};

    #$to   = join(', ', @{$this->{to}});
    my (%tolist);
    foreach $to (@{$this->{to}}) {
        $tolist{$to} = 1;
    }
    $to = join(', ', sort keys %tolist);

    $subject         = $this->{subject};
    $localpostmaster = Baruwa::Scanner::Config::Value('localpostmaster', $this);
    $postmastername  = Baruwa::Scanner::Config::LanguageValue($this, 'baruwa');

    $newsubject =
      Baruwa::Scanner::Config::LanguageValue($this, 'disinfected') . ": "
      . substr($subject, 0, $MaxSubjectLength);
    $newsubject .= '...' if length($subject) > $MaxSubjectLength;

    #print STDERR "About to deliver " . join(',',@files) . " to original " .
    #             "recipients after disinfection\n";

    # Create the top-level MIME entity, just the headers
    $top = MIME::Entity->build(
        Type       => 'multipart/mixed',
        From       => "$postmastername <$localpostmaster>",
        To         => $to,
        Subject    => $newsubject,
        'X-Mailer' => 'Baruwa',
        Baruwa::Scanner::Config::Value('mailheader', $this) =>
          Baruwa::Scanner::Config::Value('disinfectedheader', $this)
    );

    # Construct the text of the message body
    my ($textfh, $textfile, $output, $result, $attachment);
    $textfh = new FileHandle;
    $textfile = Baruwa::Scanner::Config::Value('disinfectedreporttext', $this);
    $textfh->open($textfile)
      or Baruwa::Scanner::Log::WarnLog(
        "Cannot open disinfected report message " . "file %s, %s",
        $textfile, $!);
    $output = "";
    my $line;
    my $ea = qr/([\(\)\[\]\.\?\*\+\^"'@<>:])/;

    while (<$textfh>) {
        $line = chomp;

        #s#"#\\"#g; # Escape any " characters
        #s#@#\\@#g; # Escape any @ characters
        $line =~ s/$ea/\\$1/g;    # Escape any regex characters
                                  # Untainting joy...
        $line =~ /(.*)/;
        $result = eval "\"$1\"";
        $output .= Baruwa::Scanner::Config::DoPercentVars($result) . "\n";
    }
    $textfh->close();
    $top->attach(Data => $output);

    # Construct all the attachments
    my ($notype);
    foreach $attachment (@files) {

        # As each $attachment will contain the type indicator, we need to
        # create one which doesn't to name it with in the resulting message.
        $notype = substr($attachment, 1);

        # Added "./" to start of next line to avoid potential DoS attack
        $top->attach(
            Filename    => "$notype",
            Path        => "./$attachment",
            Type        => "application/octet-stream",
            Encoding    => "base64",
            Disposition => "attachment"
        );
    }

    # Now send the message
    $global::MS->{mta}->SendMessageEntity($this, $top, $localpostmaster)
      or Baruwa::Scanner::Log::WarnLog("Could not send disinfected message, %s",
        $!);
}

# Archive this message to any directories in its archiveplaces attribute
sub ArchiveToFilesystem {
    my $this = shift;

    my ($dir, $todaydir, $target, $didanything, %alreadydone);
    $didanything = 0;
    my $numrecips = scalar(@{$this->{to}});

    # Assume it's a filename or a directory name. d=>directory, f=>file.
    my $assumeisdir =
      (Baruwa::Scanner::Config::Value("assumeisdir", $this) =~ /1/) ? 1 : 0;
    $todaydir = $this->{datenumber};   #Baruwa::Scanner::Quarantine::TodayDir();

    foreach $dir (@{$this->{archiveplaces}}) {

        #print STDERR "Archive to $dir\n";
        next unless $dir =~ /^\//;     # Must be a pathname
        $dir =~ s/_HOUR_/$this->{hournumber}/g;
        $dir =~ s/_DATE_/$this->{datenumber}/g;
        $dir =~ s/_FROMUSER_/$this->{fromuser}/g;
        $dir =~ s/_FROMDOMAIN_/$this->{fromdomain}/g;
        foreach my $recip (0 .. $numrecips - 1) {
            my $dircopy = $dir;
            my $u       = $this->{touser}[$recip];
            my $d       = $this->{todomain}[$recip];
            $dircopy =~ s/_TOUSER_/$u/g;
            $dircopy =~ s/_TODOMAIN_/$d/g;

            # Don't archive to the same place twice
            next if $alreadydone{$dircopy};
            $alreadydone{$dircopy} = 1;

            # If it exists, and it's a file, then append the message to it
            # in mbox format.
            if (-f $dircopy || !$assumeisdir) {

                #print STDERR "It is a file\n";
                $this->AppendToMbox($dircopy);
                $didanything = 1;
                next;
            }
            $target = "$dircopy/$todaydir";
            $target =~ m|(.*)|;
            $target = $1;
            unless (-d "$target") {
                umask $global::MS->{quar}->{dirumask};
                mkpath "$target"
                  or Baruwa::Scanner::Log::WarnLog("Cannot create directory %s",
                    $target);
                umask 0077;
            }

            #print STDERR "It is a dir\n";
            umask $global::MS->{quar}->{fileumask};
            $this->{store}->CopyToDir($target, $this->{id});

            #print STDERR "Stored " . $this->{id} . " to $target\n";
            umask 0077;
            $didanything = 1;
        }
    }
    return $didanything;
}

# Append a message to an mbox file.
# The mbox file may not exist, nor may its directory.
sub AppendToMbox {
    my ($this, $mbox) = @_;

    #untaint
    $mbox =~ m|(.*)|;
    $mbox = $1;

    # Find the complete directory name.
    my $dir = $mbox;
    $dir =~ s#^(.*)/[^/]+$#$1#;

    # Create the directory (and its tree) if it doesn't exist.
    unless (-d $dir) {
        umask $global::MS->{quar}->{dirumask};
        mkpath $dir;
        umask 0077;
    }

    my $fh = new IO::File "$mbox", "a";
    if ($fh) {

        # Print the mbox message header starting with a blank line and "From"
        # From $from `date "+%a %b %d %T %Y"`
        my ($now, $recip);
        $now = ctime();
        $now =~ s/  (\d)/ 0$1/g;    # Insert leading zeros where needed

        print $fh "From " . $this->{from} . ' ' . $now . "\n";
        foreach $recip (@{$this->{to}}) {
            print $fh "X-Baruwa-Recipient: $recip\n";
        }
        $fh->flush;

        # Write the entire message to this handle, then close.
        $this->{store}->WriteEntireMessage($this, $fh);
        print $fh "\n";    # Blank line at end of message to separate messages
        $fh->close;
        Baruwa::Scanner::Log::InfoLog("Archived message %s to mbox file %s",
            $this->{id}, $mbox);
    } else {
        Baruwa::Scanner::Log::WarnLog(
            "Failed to append message to pre-existing " . "mbox file %s",
            $mbox);
    }
}

sub ReflowHeader {
    my ($this, $key, $input) = @_;
    my ($output, $pos, $len, $firstline, @words, $word);
    $output    = "";
    $pos       = 0;
    $firstline = 1;

    @words = split(/,\s*/, $input);
    foreach $word (@words) {
        $len = length($word);
        if ($firstline) {
            $output = "$word";
            $pos    = $len + length($key) + 1; # 1 = space between key and input
            $firstline = 0;
            next;
        }

        # Wrap at column 75 (pretty arbitrary number just less than 80)
        if ($pos + $len < 75) {
            $output .= ", $word";
            $pos += 2 + $len;
        } else {
            $output .= ",\n\t$word";
            $pos = 8 + $len;
        }
    }

    return $output;
}

# Strip the HTML out of this message. All the checks have already
# been done, so just get on with it.
sub StripHTML {
    my $this = shift;

    #print STDERR "Stripping HTML from message " . $this->{id} . "\n";
    $this->HTMLToText($this->{entity});
}

# Disarm some of the HTML tags in this message.
sub DisarmHTML {
    my $this = shift;

#print STDERR "Tags to convert are " . $this->{tagstoconvert} . " on message " . $this->{id} . "\n";

    # Set the disarm booleans for this message
    $DisarmFormTag      = 0;
    $DisarmScriptTag    = 0;
    $DisarmCodebaseTag  = 0;
    $DisarmCodebaseTag  = 0;
    $DisarmIframeTag    = 0;
    $DisarmWebBug       = 0;
    $DisarmPhishing     = 0;
    $DisarmNumbers      = 0;
    $StrictPhishing     = 0;
    $DisarmWebBugFound  = 0;
    $PhishingSubjectTag = 0;
    $PhishingHighlight  = 0;
    $SigImageFound      = 0;
    $DisarmFormTag      = 1 if $this->{tagstoconvert} =~ /form/i;
    $DisarmScriptTag    = 1 if $this->{tagstoconvert} =~ /script/i;
    $DisarmCodebaseTag  = 1 if $this->{tagstoconvert} =~ /codebase/i;
    $DisarmCodebaseTag  = 1 if $this->{tagstoconvert} =~ /data/i;
    $DisarmIframeTag    = 1 if $this->{tagstoconvert} =~ /iframe/i;
    $DisarmWebBug       = 1 if $this->{tagstoconvert} =~ /webbug/i;
    $PhishingSubjectTag = 1
      if Baruwa::Scanner::Config::Value('tagphishingsubject', $this) =~ /1/;

    #print STDERR "PhishingSubjectTag = $PhishingSubjectTag\n";
    $PhishingHighlight = 1
      if Baruwa::Scanner::Config::Value('phishinghighlight', $this) =~ /1/;

    #print STDERR "PhishingHighlight = $PhishingHighlight\n";
    $DisarmPhishingFound         = 0;
    $this->{disarmphishingfound} = 0;
    $DisarmHTMLChangedMessage    = 0;
    if (Baruwa::Scanner::Config::Value('findphishing', $this) =~ /1/) {
        $DisarmPhishing = 1;
        $DisarmNumbers  = 1
          if Baruwa::Scanner::Config::Value('phishingnumbers', $this) =~ /1/;
        $StrictPhishing = 1
          if Baruwa::Scanner::Config::Value('strictphishing', $this) =~ /1/;
    }

    # Construct the WebBugWhitelist - space and comma-separated list of words
    $WebBugWhitelist = Baruwa::Scanner::Config::Value('webbugwhitelist', $this);
    $WebBugWhitelist =~ s/^\s+//;
    $WebBugWhitelist =~ s/\s+$//;
    $WebBugWhitelist =~ s/[\s,]+/|/g;
    $WebBugReplacement = Baruwa::Scanner::Config::Value('webbugurl', $this);
    $WebBugBlacklist = Baruwa::Scanner::Config::Value('webbugblacklist', $this);
    $WebBugBlacklist =~ s/^\s+//;
    $WebBugBlacklist =~ s/\s+$//;
    $WebBugBlacklist =~ s/[\s,]+/|/g;

    my ($counter, @disarmedtags);
    ($counter, @disarmedtags) = $this->DisarmHTMLTree($this->{entity});

    #print STDERR "disarmedtags = ". join(', ', @disarmedtags) . "\n";

# If the HTML checks found a real problem or there really was a phishing
# attack, only then should we log anything.
#print "DisarmPhishingFound = $DisarmPhishingFound on message " . $this->{id} . "\n";
    $this->{disarmphishingfound} = 1 if $DisarmPhishingFound;
    @disarmedtags = ('phishing')
      if $DisarmPhishingFound
      && $PhishingHighlight
      && !@disarmedtags;    #JKF1 && $PhishingHighlight && !@disarmedtags;
        #print STDERR "Found DisarmPhishingFound\n" if $DisarmPhishingFound;
    Baruwa::Scanner::Log::InfoLog(
        'Content Checks: Detected and have disarmed '
          . join(', ', @disarmedtags)
          . ' tags in '
          . 'HTML message in %s from %s',
        $this->{id},
        $this->{from}
    ) if $DisarmHTMLChangedMessage || $DisarmPhishingFound;

    # And save the results from the phishing trip
    if ($DisarmPhishingFound) {

        # Do we want this or not? I say no. $this->{otherinfected} = 1;
        $this->{bodymodified} = 1;

        #print STDERR "DisarmPhishingFound = $DisarmPhishingFound\n";
    }
    if ($DisarmHTMLChangedMessage) {

        #print STDERR "Disarm Changed the message at 5132.\n";
        $this->{bodymodified}    = 1;
        $this->{messagedisarmed} = 1;
    } else {
        $this->{messagedisarmed} = 0;
    }

    # Did we find signs of a Baruwa signature image?
    $this->{sigimagepresent} = $SigImageFound;

    # Store all the tags we disarmed
    #print STDERR "Storing " . join(',', @disarmedtags) . "\n";
    @{$this->{disarmedtags}} = @disarmedtags;
}

# Search for a multipart/alternative.
# If found, change it to multipart/mixed and make all its members into
# suitable named attachments.
sub EncapsulateAttachments {
    my ($message, $searchtype, $entity, $filename) = @_;

    # Reached a leaf node?
    return 0 unless $entity && defined($entity->head);

    my (@parts, $part, $type, $extension, $newname);
    my $counter = 0;

    $type = $entity->head->mime_attr('content-type');
    if (!$searchtype || ($type && $type =~ /$searchtype/i)) {

        #print STDERR "Found alternative message at entity $entity\n";

        # Turn it into a multipart/mixed
        $entity->head->mime_attr('content-type' => 'multipart/mixed')
          if $searchtype;

        # Change the parts into attachments
        @parts = $entity->parts;
        foreach $part (@parts) {
            my $head = $part->head;
            $type = $head->mime_attr('content-type') || 'text/plain';
            $extension = '.dat';
            $type =~ /\/([a-z0-9-]+)$/i and $extension = '.' . lc($1);
            $extension = '.txt'  if $type =~ /text\/plain/i;
            $extension = '.html' if $type =~ /text\/html/i;

            $newname = $filename . $extension;

            $head->mime_attr('Content-Type'                 => $type);
            $head->mime_attr('Content-Disposition'          => 'attachment');
            $head->mime_attr('Content-Disposition.filename' => $newname)
              unless $head->mime_attr('Content-Disposition.filename');
            $head->mime_attr('Content-Type.name' => $newname)
              unless $head->mime_attr('Content-Type.name');

            $counter++;
        }
    } else {

        # Now try the same on all the parts
        foreach $part (@parts) {
            $counter +=
              $message->EncapsulateAttachments($searchtype, $part, $filename);
        }
    }

    return $counter;
}

sub EncapsulateMessageHTML {
    my $this = shift;

    my ($entity, $filename, $newpart);

    $entity = $this->{entity};

    $filename = Baruwa::Scanner::Config::Value('originalmessage', $this);

    $entity->make_multipart('mixed');
    $this->EncapsulateAttachments('multipart/alternative', $entity, $filename)
      or $this->EncapsulateAttachments(undef, $entity, $filename);

    # Insert the new message part
    $newpart = MIME::Entity->build(
        Type        => "text/plain",
        Disposition => undef,
        Data        => ["Hello\n", "There\n", "Last line\n"],
        Filename    => undef,
        Top         => 0,
        'X-Mailer'  => undef
    );
    $entity->add_part($newpart, 0);    # Insert at the start of the message

    # Clean up the message so spammers can't pollute me
    $this->{entity}->preamble(undef);
    $this->{entity}->epilogue(undef);
    $this->{entity}->head->add('MIME-Version', '1.0')
      unless $this->{entity}->head->get('mime-version');
    $this->{bodymodified} = 1;
    return;
}

# Encapsulate the message in an RFC822 structure so that it becomes a
# single atachment of the message. Need to build the spam report to put
# in as the text/plain body of the main message.
sub EncapsulateMessage {
    my $this = shift;

    my ($entity, $rfc822, $mimeversion, $mimeboundary, @newparts);
    my ($messagefh, $filename, $emailmsg, $line, $charset, $datenumber);
    my ($id, $to, $from, $localpostmaster, $hostname, $subject, $date);
    my ($fullspamreport, $briefspamreport, $longspamreport, $sascore);
    my ($postmastername);

    # For now, if there is no entity structure at all then just return,
    # we cannot encapsulate a message without it.
    # Unfortunately that means we can't encapsulate messages that are
    # Virus Scanning = no ("yes" but also having "Virus Scanners=none" is
    # fine, and works). The encapsulation will merely fail to do anything.
    # Hopefully this will only be used by corporates who are virus scanning
    # everything anyway.
    # Workaround: Instead of using "Virus Scanning = no", use
    # "Virus Scanners = none" and a set of filename rules that pass all files.
    return unless $this->{entity};

    # Construct the RFC822 attachment
    $mimeversion = $this->{entity}->head->get('mime-version');

    # Prune all the dead branches off the tree
    my $Pruned = PruneEntityTree($this->{entity}, $this->{entity2file},
        $this->{file2entity});

    #print STDERR "Pruned tree = $Pruned\n";
    return unless $Pruned;    # Bail out if the tree has no leaves

    $entity = $this->{entity};
    $rfc822 = $entity->stringify;

    # Setup variables they can use in the spam report that is inserted at
    # the top of the message.
    $id = $this->{id};

    #$to = join(', ', @{$this->{to}});
    my (%tolist);
    foreach $to (@{$this->{to}}) {
        $tolist{$to} = 1;
    }
    $to = join(', ', sort keys %tolist);

    $from            = $this->{from};
    $localpostmaster = Baruwa::Scanner::Config::Value('localpostmaster', $this);
    $postmastername  = Baruwa::Scanner::Config::LanguageValue($this, 'baruwa');
    $hostname        = Baruwa::Scanner::Config::Value('hostname', $this);
    $subject         = $this->{subject};
    $date           = $this->{datestring};     # scalar localtime;
    $fullspamreport = $this->{spamreport};
    $longspamreport = $this->{salongreport};
    $sascore        = $this->{sascore};

    #$this->{salongreport} = ""; # Reset it so we don't ever insert it twice

    # Delete everything in brackets after the SA report, if it exists
    $briefspamreport = $fullspamreport;
    $briefspamreport =~ s/(spamassassin)[^(]*\([^)]*\)/$1/i;
    $charset = Baruwa::Scanner::Config::Value('attachmentcharset', $this);
    $datenumber = $this->{datenumber};

    # Construct the spam report at the top of the message
    $messagefh = new FileHandle;
    $filename = Baruwa::Scanner::Config::Value('inlinespamwarning', $this);
    $messagefh->open($filename)
      or Baruwa::Scanner::Log::WarnLog(
        "Cannot open inline spam warning file %s, %s",
        $filename, $!);
    $emailmsg = "";
    while (<$messagefh>) {
        chomp;
        s#"#\\"#g;
        s#@#\\@#g;

        # Boring untainting again...
        /(.*)/;
        $line = eval "\"$1\"";
        $emailmsg .= Baruwa::Scanner::Config::DoPercentVars($line) . "\n";
    }
    $messagefh->close();

    $newparts[0] = MIME::Entity->build(
        Type        => 'text/plain',
        Disposition => 'inline',
        Encoding    => 'quoted-printable',
        Top         => 0,
        'X-Mailer'  => undef,
        Charset     => $charset,
        Data        => $emailmsg
    );

    $newparts[1] = MIME::Entity->build(
        Type        => 'message/rfc822',
        Disposition => 'attachment',
        Top         => 0,
        'X-Mailer'  => undef,
        Data        => $rfc822
    );

    # If there was a multipart boundary, then create a new one so that
    # the main message has a different boundary from the RFC822 attachment.
    # Leave the RFC822 one alone, so we don't corrupt the original message,
    # but make sure we create a new one instead.
    # Keep generating random boundaries until we have definitely got a new one.
    my $oldboundary = $entity->head->multipart_boundary;
    do {
        $mimeboundary = '======' . $$ . '==' . int(rand(100000)) . '======';
    } while $mimeboundary eq $oldboundary;

    # Put the new parts in place, hopefully it will correct all the multipart
    # headers for me. Wipe the preamble and epilogue or else someone will use
    # them to bypass the encapsulation process.
    # Make it a report if it wasn't multipart already.
    $entity->make_multipart("report");    # Used to be digest
                                          # Try *real* hard to make it a digest.
    $entity->head->mime_attr("Content-type" => "multipart/report")
      ;                                   # Used to be digest
    $entity->head->mime_attr("Content-type.boundary" => $mimeboundary);

    # Delete the "type" subfield which I don't think should be there
    $entity->head->mime_attr("Content-type.type" => undef);

    # JKF 09/11/2005 Added after bug report from Georg@hackt.net
    $entity->head->mime_attr("Content-type.report-type" => 'spam-notification');
    $entity->parts(\@newparts);
    $entity->preamble(undef);
    $entity->epilogue(undef);
    $entity->head->add('MIME-Version', '1.0') unless $mimeversion;
    $this->{bodymodified} = 1;    # No infection but we changed the MIIME tree
}

sub DisarmHTMLTree {
    my ($this, $entity) = @_;

    my $counter = 0;              # Have we modified this message at all?
    my @disarmed;                 # List of tags we have disarmed

    #print STDERR "Disarming HTML Tree\n";

    # Reached a leaf node?
    return 0 unless $entity && defined($entity->head);

    if (   $entity->head->mime_attr('content-disposition') !~ /attachment/i
        && $entity->head->mime_attr('content-type') =~ /text\/html/i) {

        #print STDERR "Found text/html message at entity $entity\n";
        @disarmed = $this->DisarmHTMLEntity($entity);

        #print STDERR "Disarmed = " . join(', ',@disarmed) . "\n";
        if (@disarmed) {
            $this->{bodymodified} = 1;
            $DisarmHTMLChangedMessage = 1;
            $counter++;
        }
    }

    # Now try the same on all the parts
    my (@parts, $part, $newcounter, @newtags);
    @parts = $entity->parts;
    foreach $part (@parts) {
        ($newcounter, @newtags) = $this->DisarmHTMLTree($part);
        $counter += $newcounter;
        @disarmed = (@disarmed, @newtags);
    }

  #print STDERR "Returning " . join(', ', @disarmed) . " from DisarmHTMLTree\n";
    return ($counter, @disarmed);
}

# Walk the MIME tree, looking for text/html entities. Whenever we find
# one, create a new filename for a text/plain entity, and replace the
# part that pointed to the filename with a replacement that points to
# the new txt filename.
# Only replace inline sections, don't replace attachments, so that your
# users can still mail HTML attachments to each other.
# Then tag the message to say it has been modified, so that it is
# rebuilt from the MIME tree when it is delivered.
sub HTMLToText {
    my ($this, $entity) = @_;

    my $counter;    # Have we modified this message at all?

    # Reached a leaf node?
    return 0 unless $entity && defined($entity->head);

    if (   $entity->head->mime_attr('content-disposition') !~ /attachment/i
        && $entity->head->mime_attr('content-type') =~ /text\/html/i) {

        #print STDERR "Found text/html message at entity $entity\n";
        $this->HTMLEntityToText($entity);
        Baruwa::Scanner::Log::InfoLog(
            'Content Checks: Detected and will convert '
              . 'HTML message to plain text in %s',
            $this->{id}
        );
        $this->{bodymodified} = 1;  # No infection but we changed the MIIME tree
        $counter++;
    }

    # Now try the same on all the parts
    my (@parts, $part);
    @parts = $entity->parts;
    foreach $part (@parts) {
        $counter += $this->HTMLToText($part);
    }

    return $counter;
}

# HTML::Parset callback function for normal text
my (%DisarmDoneSomething, $DisarmLinkText,   $DisarmLinkURL,
    $DisarmAreaURL,       $DisarmInsideLink, $DisarmBaseURL
);

# Convert 1 MIME entity from html to dis-armed HTML using HTML::Parser.
sub DisarmHTMLEntity {
    my ($this, $entity) = @_;

    my ($oldname, $newname, $oldfh, $outfh, $htmlparser);

    #print STDERR "Disarming HTML $entity\n";

    # Initialise all the variables we will use in the parsing, so nothing
    # is inherited from old messages
    $DisarmLinkText      = "";
    $DisarmLinkURL       = "";
    $DisarmInsideLink    = 0;
    $DisarmBaseURL       = "";
    $DisarmAreaURL       = "";
    %DisarmDoneSomething = ();

    # Replace the filename with a new one
    $oldname = $entity->bodyhandle->path();

    #print STDERR "Path is $oldname\n";
    $newname = $oldname;
    $newname =~ s/\..?html?$//i;    # Remove .htm .html .shtml
    $newname .= '2.html';    # This should always pass the filename checks
    $entity->bodyhandle->path($newname);

    # Process the old HTML file into the new one
    my $pipe = new IO::Pipe
      or Baruwa::Scanner::Log::DieLog(
        'Failed to create pipe, %s, while parsing '
          . 'HTML. Try reducing the maximum number of unscanned '
          . 'messages per batch',
        $!
      );
    my $PipeReturn = 0;
    my $pid        = fork();
    die "Can't fork: $!" unless defined($pid);
    if ($pid == 0) {

        # In the child
        $pipe->writer();
        $pipe->autoflush();
        $outfh = new FileHandle;
        unless ($outfh->open(">$newname")) {
            Baruwa::Scanner::Log::WarnLog(
                'Could not create disarmed HTML file %s', $newname);
            exit 1;
        }
        select $outfh;
        if ($DisarmPhishing) {
            HTML::Parser->new(
                api_version => 3,
                start_h =>
                  [\&DisarmTagCallback, "tagname, text, attr, attrseq"],
                end_h => [
                    \&DisarmEndtagCallback,
                    "tagname, text, '" . $this->{id} . "'"
                ],
                text_h => [\&DisarmTextCallback, "text"],
                default_h => [sub {print @_;}, "text"],
              )->parse_file($oldname)
              or Baruwa::Scanner::Log::WarnLog(
                "HTML disarming, can't open file %s: %s",
                $oldname, $!);

            # JKF 20101107 Try to fix unterminated links
            if ($DisarmInsideLink) {
                DisarmEndtagCallback('a', " ", $this->{id});
                print $outfh "\n";
            }
        } else {
            HTML::Parser->new(
                api_version => 3,
                start_h =>
                  [\&DisarmTagCallback, "tagname, text, attr, attrseq"],
                end_h => [
                    \&DisarmEndtagCallback,
                    "tagname, text, '" . $this->{id} . "'"
                ],
                default_h => [sub {print @_;}, "text"],
              )->parse_file($oldname)
              or Baruwa::Scanner::Log::WarnLog(
                "HTML disarming, can't open file %s: %s",
                $oldname, $!);
        }

        # Dump the contents of %DisarmDoneSomething down the pipe
        foreach my $ddskey (keys %DisarmDoneSomething) {
            print $pipe "$ddskey\n";
        }
        print $pipe "ENDENDEND\n";
        $pipe->close;
        $pipe = undef;
        exit 0;

        # The child will never get here.
    }

    # In the parent.
    my @DisarmDoneSomething;
    eval {
        $pipe->reader();
        local $SIG{ALRM} = sub {die "Command Timed Out"};
        alarm Baruwa::Scanner::Config::Value('spamassassintimeout');

        # Read the contents of %DisarmDoneSomething from the pipe
        my ($pipedata);
        while (defined($pipedata = <$pipe>)) {
            last if $pipedata eq "ENDENDEND\n";
            chomp $pipedata;
            push @DisarmDoneSomething, $pipedata;

            #print STDERR "DisarmDoneSomething $pipedata\n";
        }
        waitpid $pid, 0;
        $pipe->close;
        $PipeReturn = $?;
        alarm 0;
        $pid = 0;
    };
    alarm 0;

    # Workaround for bug in perl shipped with Solaris 9,
    # it doesn't unblock the SIGALRM after handling it.
    eval {
        my $unblockset = POSIX::SigSet->new(SIGALRM);
        sigprocmask(SIG_UNBLOCK, $unblockset)
          or die "Could not unblock alarm: $!\n";
    };

   # If pid != 0 then it failed so we have to kill the child and mark it somehow
   #print STDERR "pid==$pid\n";
   #print STDERR "PipeReturn==$PipeReturn\n";
    if ($pid > 0) {
        kill 15, $pid;    # Was -15
                          # Wait for up to 10 seconds for it to die
        for (my $i = 0; $i < 5; $i++) {
            sleep 1;
            waitpid($pid, &POSIX::WNOHANG);
            ($pid = 0), last unless kill(0, $pid);
            kill 15, $pid;    # Was -15
        }

        # And if it didn't respond to 11 nice kills, we kill -9 it
        if ($pid) {
            kill 9, $pid;     # Was -9
            waitpid $pid, 0;  # 2.53
        }
    }

    if ($PipeReturn) {

        # It went badly wrong!
        # Overwrite the output file to kill it, and return the error.
        $outfh = new FileHandle;
        unless ($outfh->open(">$newname")) {
            Baruwa::Scanner::Log::WarnLog('Could not wipe deadly HTML file %s',
                $newname);
            exit 1;
        }
        my $report =
          "Baruwa was attacked by a Denial Of Service attack, and has therefore
    \ndeleted this part of the message. Please contact your e-mail providers
    \nfor more information if you need it, giving them the whole of this report.\n";
        my $report2 =
          Baruwa::Scanner::Config::LanguageValue(0, 'htmlparserattack');
        $report = $report2 if $report2 && $report2 ne 'htmlparserattack';
        print $outfh $report . "\n\nAttack in: $oldname\n";
        $outfh->close;

        #print STDERR "HTML::Parser was killed by the message, " .
        #             "$newname has been overwritten\n";
        return ('KILLED');
    }

#print STDERR "Results of HTML::Parser are " . join(',',@DisarmDoneSomething) . "\n";
    return @DisarmDoneSomething;
}

# HTML::Parser callback for text so we can collect the contents of links
sub DisarmTextCallback {
    my ($text) = @_;

    unless ($DisarmInsideLink) {
        print $text;

        #print STDERR "DisarmText just printed \"$text\"\n";
        return;
    }

    # We are inside a link.
    # Save the original text, we well might need it.
    $DisarmLinkText .= $text;

    #print STDERR "DisarmText just added \"$text\"\n";
}

# HTML::Parser callback function for start tags
sub DisarmTagCallback {
    my ($tagname, $text, $attr, $attrseq) = @_;

    #print STDERR "Disarming $tagname\n";

    my $output = "";
    my $webbugfilename;

    if ($tagname eq 'form' && $DisarmFormTag) {

        #print "It's a form\n";
        $text = substr $text, 1;
        $output .= "<BR><BaruwaForm$$ " . $text;
        $DisarmDoneSomething{'form'} = 1;
    } elsif ($tagname eq 'input' && $DisarmFormTag) {

        #print "It's an input button\n";
        $attr->{'type'} = "reset";
        $output .= '<' . $tagname;
        foreach (@$attrseq) {
            next if /^on/;
            $output .= ' ' . $_ . '="' . $attr->{$_} . '"';
        }
        $output .= '>';
        $DisarmDoneSomething{'form input'} = 1;
    } elsif ($tagname eq 'button' && $DisarmFormTag) {

        #print "It's a button\n";
        $attr->{'type'} = "reset";
        $output .= '<' . $tagname;
        foreach (@$attrseq) {
            next if /^on/;
            $output .= ' ' . $_ . '="' . $attr->{$_} . '"';
        }
        $output .= '>';
        $DisarmDoneSomething{'form button'} = 1;
    } elsif ($tagname eq 'object' && $DisarmCodebaseTag) {

        #print "It's an object\n";
        if (exists $attr->{'codebase'}) {
            $text = substr $text, 1;
            $output .= "<BaruwaObject$$ " . $text;
            $DisarmDoneSomething{'object codebase'} = 1;
        } elsif (exists $attr->{'data'}) {
            $text = substr $text, 1;
            $output .= "<BaruwaObject$$ " . $text;
            $DisarmDoneSomething{'object data'} = 1;
        } else {
            $output .= $text;
        }
    } elsif ($tagname eq 'iframe' && $DisarmIframeTag) {

        #print "It's an iframe\n";
        $text = substr $text, 1;
        $output .= "<BaruwaIFrame$$ " . $text;
        $DisarmDoneSomething{'iframe'} = 1;
    } elsif ($tagname eq 'script' && $DisarmScriptTag) {

        #print "It's a script\n";
        $text = substr $text, 1;
        $output .= "<BaruwaScript$$ " . $text;
        $DisarmDoneSomething{'script'} = 1;
    } elsif ($tagname eq 'a' && $DisarmPhishing) {

        #print STDERR "It's a link\n";
        $output .= $text;
        $DisarmLinkText = '';    # Reset state of automaton
        $DisarmLinkURL  = '';
        $DisarmLinkURL    = $attr->{'href'} if exists $attr->{'href'};
        $DisarmInsideLink = 1;
        $DisarmInsideLink = 0 if $DisarmLinkURL eq ''; # JPSB empty A tags. Was:
          #Old: $DisarmInsideLink = 0 if $text =~ /\/\>$/; # JKF Catch /> empty A tags
          #print STDERR "DisarmInsideLink = $DisarmInsideLink\n";
    } elsif ($tagname eq 'img') {

 #print STDERR "It's an image\n";
 #print STDERR "The src is \"" . $attr->{'src'} . "\"\n";
 # If the alt text has the required magic text in it then it's a sig image.
 # Look for "Baruwa" and "Signature" and "%org-name%" (if %org-name% is defined)
        my $orgname = Baruwa::Scanner::Config::DoPercentVars('%org-name%');
        $SigImageFound = 1
          if exists $attr->{'alt'}
          && $attr->{'alt'} =~ /Baruwa/i
          && $attr->{'alt'} =~ /Signature/i
          && ($orgname eq ''
            || ($orgname && $attr->{'alt'} =~ /$orgname/i));

        #print STDERR "Found a signature image\n"
        #  if exists $attr->{'alt'} && $attr->{'alt'} =~ /Baruwa.*Signature/i;
        if ($DisarmWebBug) {
            my $server = $attr->{'src'};
            $server =~ s#^[^:]+:/+([^/]+)/.*$#$1#;
            if (($server && $WebBugBlacklist && $server =~ /$WebBugBlacklist/i)
                || (   exists $attr->{'width'}
                    && $attr->{'width'} <= 2
                    && exists $attr->{'height'}
                    && $attr->{'height'} <= 2
                    && exists $attr->{'src'}
                    && $attr->{'src'} !~ /^cid:|^$WebBugReplacement/i)
              ) {
                # Is the filename in the WebBug whitelist?
                $webbugfilename = $attr->{'src'};
                $webbugfilename = $1 if $webbugfilename =~ /\/([^\/]+)$/;
                if (   $webbugfilename
                    && $WebBugWhitelist
                    && $webbugfilename =~ /$WebBugWhitelist/i) {

                    # It's in the whitelist, so ignore it
                    $output .= $text;
                } else {

                    # It's not in the whitelist, so zap it with insecticide!
                    $output .=
                        '<img src="'
                      . $WebBugReplacement
                      . '" width="'
                      . $attr->{'width'}
                      . '" height="'
                      . $attr->{'height'}
                      . '" alt="';
                    $output .= 'Web Bug from ' . $attr->{'src'}
                      if $attr->{'src'};
                    $output .= '" />';
                    $DisarmWebBugFound = 1;
                    $DisarmDoneSomething{'web bug'} = 1;
                }
            } else {
                $output .= $text;
            }
        } else {
            $output .= $text;
        }
    } elsif ($tagname eq 'base') {

        #print STDERR "It's a Base URL\n";
        $output .= $text;

        #print STDERR "Base URL = " . $attr->{'href'} . "\n";
        $DisarmBaseURL = $attr->{'href'} if exists $attr->{'href'};
    } elsif ($tagname eq 'area' && $DisarmInsideLink && $DisarmPhishing) {

        #print STDERR "It's an imagemap area\n";
        $output .= $text;

        #print STDERR "Area URL = " . $attr->{'href'} . "\n";
        $DisarmAreaURL = $attr->{'href'};
    } else {

        #print STDERR "The tag was a \"$tagname\"\n";
        $output .= $text;

        #print STDERR "output text is now \"$output\"\n";
    }

    # tagname DisarmPhishing
    #    a     0               0 1
    #    a     1               0 0 tagname=a && Disarm=1
    #    b     0               1 1
    #    b     1               1 0
    #if ($DisarmInsideLink && !($tagname eq 'a' && $DisarmPhishing)) {
    if ($DisarmInsideLink && ($tagname ne 'a' || !$DisarmPhishing)) {
        $DisarmLinkText .= $output;

 #print STDERR "StartCallback: DisarmLinkText now equals \"$DisarmLinkText\"\n";
    } else {
        print $output;

        #print STDERR "StartCallback: Printed2 \"$output\"\n";
    }
}

# HTML::Parser callback function for end tags
sub DisarmEndtagCallback {
    my ($tagname, $text, $id) = @_;

    if ($tagname eq 'iframe' && $DisarmIframeTag) {
        print "</BaruwaIFrame$$>";
        $DisarmDoneSomething{'iframe'} = 1;
    } elsif ($tagname eq 'form' && $DisarmFormTag) {
        print "</BaruwaForm$$>";
        $DisarmDoneSomething{'form'} = 1;
    } elsif ($tagname eq 'script' && $DisarmScriptTag) {
        print "</BaruwaScript$$>";
        $DisarmDoneSomething{'script'} = 1;
    } elsif ($tagname eq 'map' && $DisarmAreaURL) {

        # We are inside an imagemap that is part of a phishing imagemap
        $DisarmLinkText .= '</map>';
    } elsif ($tagname eq 'a' && $DisarmPhishing) {

        #print STDERR "---------------------------\n";
        #print STDERR "Endtag Callback found link, " .
        #             "disarmlinktext = \"$DisarmLinkText\"\n";
        my ($squashedtext, $linkurl, $alarm, $numbertrap);
        $DisarmInsideLink = 0;
        $squashedtext     = lc($DisarmLinkText);
        if ($DisarmAreaURL) {
            $squashedtext  = $DisarmLinkURL;
            $DisarmLinkURL = lc($DisarmAreaURL);
            $DisarmAreaURL = "";                  # End of a link, so reset this
        } else {
            $squashedtext = lc($DisarmLinkText);
        }

        # Try to filter out mentions of Microsoft's .NET system
        $squashedtext = "" if $squashedtext eq ".net";
        $squashedtext = "" if $squashedtext =~ /(^|\b)(ado|asp)\.net($|\b)/;

        $squashedtext =~ s/\%a0//g;
        $squashedtext =~
          s#%([0-9a-f][0-9a-f])#chr(hex('0x' . $1))#gei;    # Unescape
            #Moved below tag removal, as required by new 'Remove tags' re.
            #$squashedtext =~ s/\s+//g; # Remove any whitespace
        $squashedtext =~ s/\\/\//g;     # Change \ to / as many browsers do this
        $squashedtext =~ s/^\[\d*\]//;  # Removing leading [numbers]
            #$squashedtext =~ s/(\<\/?[^>]*\>)*//ig; # Remove tags
        $squashedtext =~ tr/\n/ /;    # Join multiple lines onto 1 line
        $squashedtext =~
          s/(\<\/?[a-z][a-z0-9:._-]*((\s+[a-z][a-z0-9:._-]*(\s*=\s*(?:\".*?\"|\'.*?\'|[^\'\">\s]+))?)+\s*|\s*)\/?\>)*//ig
          ;    # Remove tags, better re from snifer_@hotmail.com
        $squashedtext =~ s/\s+//g;          # Remove any whitespace
        $squashedtext =~ s/^[^\/:]+\@//;    # Remove username of email addresses
            #$squashedtext =~ s/\&\w*\;//g; # Remove things like &lt; and &gt;
        $squashedtext =~
          s/^.*(\&lt\;|\<)((https?|ftp|mailto|webcal):.+?)(\&gt\;|\>).*$/$2/i
          ; # Turn blah-blah <http://link.here> blah-blah into "http://link.here"
        $squashedtext =~ s/^\&lt\;//g;     # Remove leading &lt;
        $squashedtext =~ s/\&gt\;$//g;     # Remove trailing &gt;
        $squashedtext =~ s/\&lt\;/\</g;    # Remove things like &lt; and &gt;
        $squashedtext =~ s/\&gt\;/\>/g;    # rEmove things like &lt; and &gt;
        $squashedtext =~ s/\&nbsp\;//g;    # Remove fixed spaces
        $squashedtext =~
          s/^(http:\/\/[^:]+):80(\D|$)/$1$2/i;      # Remove http:...:80
        $squashedtext =~
          s/^(https:\/\/[^:]+):443(\D|$)/$1$2/i;    # Remove https:...:443
            #$squashedtext =~ s/./CharToIntnl("$&")/ge;
        $squashedtext =
          StringToIntnl($squashedtext);    # s/./CharToIntnl("$&")/ge;
                                           #print STDERR "Text = \"$text\"\n";
            #print STDERR "1SquashedText = \"$squashedtext\"\n";
            #print STDERR "1LinkURL      = \"$DisarmLinkURL\"\n";
            # If it looks like a link, remove any leading https:// or ftp://
        ($linkurl, $alarm) = CleanLinkURL($DisarmLinkURL);

        #print STDERR "linkurl = $linkurl\nBefore If statement\n";
        #print STDERR "squashedtext = $squashedtext\nBefore If statement\n";

        # Has it fallen foul of the numeric-ip phishing net? Must treat x
        # like a digit so it catches 0x41 (= 'A')
        $numbertrap = ($DisarmNumbers && $linkurl !~ /[<>g-wyz]+/) ? 1 : 0;

        if (   $alarm
            || $squashedtext =~ /^(w+|ft+p|fpt+|ma[il]+to)([.,]|\%2e)/i
            || $squashedtext =~ /[.,](com|org|net|info|biz|ws)/i
            || $squashedtext =~ /[.,]com?[.,][a-z][a-z]/i
            || $squashedtext =~
            /^(ht+ps?|ft+p|fpt+|mailto|webcal)[:;](\/\/)?(.*(\.|\%2e))/i
            || $numbertrap) {
            $squashedtext =~
              s/^(ht+ps?|ft+p|fpt+|mailto|webcal)[:;](\/\/)?(.*(\.|\%2e))/$3/i;
            $squashedtext =~
              s/^.*?-http:\/\///;    # 20080206 Delete common pre-pended text
            $squashedtext =~ s/\/.*$//;     # Only compare the hostnames
            $squashedtext =~ s/[,.]+$//;    # Allow trailing dots and commas
            $squashedtext = 'www.' . $squashedtext
              unless $squashedtext =~ /^ww+|ft+p|fpt+|mailto|webcal/
              || $numbertrap;

            #print STDERR "2SquashedText = \"$squashedtext\"\n";
            # If we have already tagged this link as a phishing attack, spot the
            # warning text we inserted last time and don't tag it again.
            my $possiblefraudstart =
              Baruwa::Scanner::Config::LanguageValue(0, 'possiblefraudstart');
            my $squashedpossible = lc($possiblefraudstart);
            my $squashedsearch   = lc($DisarmLinkText);
            $squashedpossible =~ s/\s//g;
            $squashedpossible =~ s/(\<\/?[^>]*\>)*//ig;    # Remove tags
            $squashedsearch =~ s/\s//g;
            $squashedsearch =~ s/(\<\/?[^>]*\>)*//ig;      # Remove tags
                #$squashedpossible = "www.$squashedpossible\"$linkurl\"";
            $squashedpossible = quotemeta($squashedpossible);

            #print STDERR "NEW CODE: SquashedText     = $squashedtext\n";
            #print STDERR "NEW CODE: DisarmLinkText   = $DisarmLinkText\n";
            #print STDERR "NEW CODE: Text             = $text\n";
            #print STDERR "NEW CODE: SquashedPossible = $squashedpossible\n";
            #print STDERR "NEW CODE: LinkURL          = $linkurl\n";
            if ($squashedtext =~ /$squashedpossible/) {

                #print STDERR "FOUND IT\n";
                #print STDERR "$DisarmLinkText$text\n";
                print "$DisarmLinkText$text";
                $DisarmLinkText = "";    # Reset state of automaton
                return;
            }

            #
            # Known Dangerous Sites List code here
            #
            my $AlreadyReported = 0;
            if (InPhishingBlacklist($linkurl)
                and not InPhishingWhitelist($linkurl)) {
                use bytes;
                print Baruwa::Scanner::Config::LanguageValue(0,
                    'definitefraudstart')
                  . ' "'
                  . $linkurl . '"'
                  . Baruwa::Scanner::Config::LanguageValue(0,
                    'definitefraudend')
                  . ' '
                  if $PhishingHighlight;
                $DisarmPhishingFound = 1;
                $linkurl             = substr $linkurl, 0, 80;
                $squashedtext        = substr $squashedtext, 0, 80;
                $DisarmDoneSomething{'phishing'} = 1 if $PhishingHighlight;
                use bytes;    # Don't send UTF16 to syslog, it breaks!
                Baruwa::Scanner::Log::NoticeLog(
                    'Found definite phishing fraud from %s ' . 'in %s',
                    $DisarmLinkURL, $id);

                #'in %s', $linkurl, $id);
                no bytes;
                $AlreadyReported = 1;
            }

            #
            # Less strict phishing net code is here
            #

            if (!$StrictPhishing) {
                my $TheyMatch = 0;

                unless (InPhishingWhitelist($linkurl)) {

        #print STDERR "Not strict phishing\n";
        # We are just looking at the domain name and country code (more or less)
        # Find the end of the domain name so we know what to strip
                    my $domain = $linkurl;
                    $domain =~ s/\/*$//;                # Take off trailing /
                    $domain =~ s/\.([^.]{2,100})$//;    # Take off .TLD
                    my $tld = $1;
                    $domain =~ s/([^.]{2,100})$//;      # Take off SLD
                    my $sld = $1;

            # Now do the same for the squashed text, i.e. where they claim it is
                    my $text = $squashedtext;

                    #print STDERR "Comparing $linkurl and $squashedtext\n";
                    #print STDERR "tld = $tld and sld = $sld\n";
                    $text =~ s/\/*$//;                # Take off trailing /
                    $text =~ s/\.([^.]{2,100})$//;    # Take off .TLD
                    my $ttld = $1;
                    $text =~ s/([^.]{2,100})$//;      # Take off SLD
                    my $tsld = $1;

                    #print STDERR "ttld = $ttld and tsld = $tsld\n";
                    if (   $tld
                        && $ttld
                        && $sld
                        && $tsld
                        && $tld eq $ttld
                        && $sld eq $tsld) {

               #print STDERR "tld/sld test matched\n";
               # domain.org or domain.3rd.2nd.india
               # Last 2 words match (domain.org), should that be enough or do we
               # need to compare the next word too (domain.org.uk) ?
               # We need to check the next word too.
                        $domain =~ s/([^.]{2,100})\.$//;    # Take off 3LD.
                        my $third = $1;
                        $text =~ s/([^.]{2,100})\.$//;      # Take off 3LD.
                        my $tthird = $1;

                        #print STDERR "third = $third and tthird = $tthird\n";
                        if ($Baruwa::Scanner::Config::SecondLevelDomainExists{
                                "$sld.$tld"}) {

                            # domain.org.uk
                            $TheyMatch = 1
                              if $third && $tthird && $third eq $tthird;
                        } else {

                            # Maybe we have a 3rd level domain base?
                            if ($Baruwa::Scanner::Config::SecondLevelDomainExists{
                                    "$third.$sld.$tld"}) {

                                # We need to check the next (4th) word too.
                                $domain =~ /([^.]{2,100})\.$/;    # Store 4LD
                                my $fourth = $1;
                                $text =~ /([^.]{2,100})\.$/;      # Store 4LD
                                my $tfourth = $1;
                                $TheyMatch = 1
                                  if $fourth
                                  && $tfourth
                                  && $fourth eq $tfourth
                                  && $third
                                  && $tthird
                                  && $third eq $tthird;
                            } else {

                 # We don't have a 3rd level, and we cannot have got here if
                 # there was a 2nd level, so it must just look like domain.org,
                 # so matches if tld and sld are the same. But we must have that
                 # true or we would never have got here, so they must match.
                                $TheyMatch = 1;
                            }
                        }
                    }
                    #
                    # Put phishing reporting code in here too.
                    #
                    if ($linkurl ne "") {
                        if ($TheyMatch) {

                  # Even though they are the same, still squeal if it's a raw IP
                            if ($numbertrap) {
                                print Baruwa::Scanner::Config::LanguageValue(0,
                                    'numericlinkwarning')
                                  . ' '
                                  if $PhishingHighlight
                                  && !$AlreadyReported
                                  ;    # && !InPhishingWhitelist($linkurl);
                                $DisarmPhishingFound = 1;
                                $linkurl = substr $linkurl, 0, 80;
                                $squashedtext = substr $squashedtext, 0, 80;
                                $DisarmDoneSomething{'phishing'} = 1
                                  if
                                  $PhishingHighlight; #JKF1 $PhishingSubjectTag;
                                use bytes
                                  ;    # Don't send UTF16 to syslog, it breaks!
                                Baruwa::Scanner::Log::NoticeLog(
                                    'Found ip-based phishing fraud from '
                                      . '%s in %s',
                                    $DisarmLinkURL, $id
                                );

                                #'%s in %s', $linkurl, $id);
                            }

                            # If it wasn't a raw IP, then everything looks fine
                        } else {

                            # They didn't match so it's definitely an attack
                            print $possiblefraudstart . ' "'
                              . $linkurl . '" '
                              . Baruwa::Scanner::Config::LanguageValue(0,
                                'possiblefraudend')
                              . ' '
                              if $PhishingHighlight
                              && !$AlreadyReported
                              ;    # && !InPhishingWhitelist($linkurl);
                            $DisarmPhishingFound = 1;
                            $linkurl             = substr $linkurl, 0, 80;
                            $squashedtext        = substr $squashedtext, 0, 80;
                            $DisarmDoneSomething{'phishing'} = 1
                              if $PhishingHighlight;  #JKF1 $PhishingSubjectTag;
                            use bytes;  # Don't send UTF16 to syslog, it breaks!
                            Baruwa::Scanner::Log::NoticeLog(
                                'Found phishing fraud from %s '
                                  . 'claiming to be %s in %s',
                                $DisarmLinkURL, $squashedtext, $id);

                            #$linkurl, $squashedtext, $id);
                        }

                     # End of less strict reporting code.
                     # But it probably was a phishing attack so print it all out
                        no bytes;
                        print "$DisarmLinkText";    # JKF 20060820 $text";
                        $DisarmLinkText = "";       # Reset state of automaton
                    }
                }

                # End of less strict phishing net.
            } else {
                #
                # Strict Phishing Net Goes Here
                #
                if ($alarm
                    || (   $linkurl ne ""
                        && $squashedtext !~ /^(w+\.)?\Q$linkurl\E\/?$/)
                    || ($linkurl ne "" && $numbertrap)
                  ) {

                    unless (InPhishingWhitelist($linkurl)) {
                        use bytes;    # Don't send UTF16 to syslog, it breaks!
                        if (   $linkurl ne ""
                            && $numbertrap
                            && $linkurl eq $squashedtext) {

                # It's not a real phishing trap, just a use of numberic IP links
                            print Baruwa::Scanner::Config::LanguageValue(0,
                                'numericlinkwarning')
                              . ' '
                              if $PhishingHighlight && !$AlreadyReported;
                        } else {

                            # It's a phishing attack.
                            print $possiblefraudstart . ' "'
                              . $linkurl . '" '
                              . Baruwa::Scanner::Config::LanguageValue(0,
                                'possiblefraudend')
                              . ' '
                              if $PhishingHighlight && !$AlreadyReported;
                        }
                        $DisarmPhishingFound = 1;
                        $linkurl             = substr $linkurl, 0, 80;
                        $squashedtext        = substr $squashedtext, 0, 80;
                        $DisarmDoneSomething{'phishing'} = 1
                          if $PhishingHighlight;    #JKF1 $PhishingSubjectTag;
                        if ($numbertrap) {
                            Baruwa::Scanner::Log::InfoLog(
                                'Found ip-based phishing fraud from '
                                  . '%s in %s',
                                $DisarmLinkURL, $id
                            );

                            #'%s in %s', $linkurl, $id);
                        } else {
                            Baruwa::Scanner::Log::InfoLog(
                                'Found phishing fraud from %s '
                                  . 'claiming to be %s in %s',
                                $DisarmLinkURL, $squashedtext, $id);

                            #$linkurl, $squashedtext, $id);
                        }

                        #print STDERR "Fake\n";
                        no bytes;
                    }
                }
            }
        }

        #print STDERR "End tag printed \"$DisarmLinkText$text\"\n";
        print "$DisarmLinkText$text";
        $DisarmLinkText = "";    # Reset state of automaton
                                 #print STDERR "Reset disarmlinktext\n";
                                 #
                                 # End of all phishing code
                                 #
    } elsif ($DisarmInsideLink) {

        # If inside a link, add the text to the link text to allow tags in links
        $DisarmLinkText .= $text;
    } else {

        # It is not a tag we worry about, so just print the text and continue.
        print $text;
    }
}

my %CharToInternational = (
    160, 'nbsp',   161, 'iexcl',  162, 'cent',   163, 'pound',  164, 'curren',
    165, 'yen',    166, 'brvbar', 167, 'sect',   168, 'uml',    169, 'copy',
    170, 'ordf',   171, 'laquo',  172, 'not',    173, 'shy',    174, 'reg',
    175, 'macr',   176, 'deg',    177, 'plusmn', 178, 'sup2',   179, 'sup3',
    180, 'acute',  181, 'micro',  182, 'para',   183, 'middot', 184, 'cedil',
    185, 'sup1',   186, 'ordm',   187, 'raquo',  188, 'frac14', 189, 'frac12',
    190, 'frac34', 191, 'iquest', 192, 'Agrave', 193, 'Aacute', 194, 'Acirc',
    195, 'Atilde', 196, 'Auml',   197, 'Aring',  198, 'AElig',  199, 'Ccedil',
    200, 'Egrave', 201, 'Eacute', 202, 'Ecirc',  203, 'Euml',   204, 'Igrave',
    205, 'Iacute', 206, 'Icirc',  207, 'Iuml',   208, 'ETH',    209, 'Ntilde',
    210, 'Ograve', 211, 'Oacute', 212, 'Ocirc',  213, 'Otilde', 214, 'Ouml',
    215, 'times',  216, 'Oslash', 217, 'Ugrave', 218, 'Uacute', 219, 'Ucirc',
    220, 'Uuml',   221, 'Yacute', 222, 'THORN',  223, 'szlig',  224, 'agrave',
    225, 'aacute', 226, 'acirc',  227, 'atilde', 228, 'auml',   229, 'aring',
    230, 'aelig',  231, 'ccedil', 232, 'egrave', 233, 'eacute', 234, 'ecirc',
    235, 'euml',   236, 'igrave', 237, 'iacute', 238, 'icirc',  239, 'iuml',
    240, 'eth',    241, 'ntilde', 242, 'ograve', 243, 'oacute', 244, 'ocirc',
    245, 'otilde', 246, 'ouml',   247, 'divide', 248, 'oslash', 249, 'ugrave',
    250, 'uacute', 251, 'ucirc',  252, 'uuml',   253, 'yacute', 254, 'thorn',
    255, 'yuml'
);

# Turn any character into an international version of it if it is in the range
# 160 to 255.
sub CharToIntnl {
    my $p = shift @_;

    # Passed in an 8-bit character.
    #print STDERR "Char in is $p\n";
    ($a) = unpack 'C', $p;

    #print STDERR "Char is $a, $p\n";

    # Bash char 160 (space) to nothing
    return '' if $a == 160;
    my $char = $CharToInternational{$a};
    return '&' . $char . ';' if $char ne "";
    return $p;
}

# Like CharToIntnl but does entire string
sub StringToIntnl {
    my $original = shift;

    # Much faster char conversion for whole strings
    my (@newlinkurl, $newlinkurl, $char);
    @newlinkurl = unpack("C*", $original);    # Get an array of characters
    foreach (@newlinkurl) {
        next if $_ == 160;
        $char = $CharToInternational{$_};
        if (defined $char) {
            $newlinkurl .= '&' . $char . ';';
        } else {
            $newlinkurl .= chr($_);
        }
    }
    return $newlinkurl;

    #$linkurl = $newlinkurl unless $newlinkurl eq "";
    #$linkurl =~ s/./CharToIntnl("$&")/ge; -- Old slow version
}

# Clean up a link URL so it is suitable for phishing detection
# Return (clean url, alarm trigger value). An alarm trigger value non-zero
# means this is definitely likely to be a phishing trap, no matter what
# anything else says.
sub CleanLinkURL {
    my ($DisarmLinkURL) = @_;

    use bytes;

    my ($linkurl, $alarm);
    $alarm   = 0;
    $linkurl = $DisarmLinkURL;
    $linkurl = lc($linkurl);

    #print STDERR "Cleaning up $linkurl\n";
    #$linkurl =~ s/\%a0//ig;
    #$linkurl =~ s/\%e9/&eacute;/ig;

    $linkurl =~ s#%([0-9a-f][0-9a-f])#chr(hex('0x' . $1))#gei;    # Unescape
        #print STDERR "2Cleaning up $linkurl\n";

    $linkurl = StringToIntnl($linkurl);

    #$linkurl =~ s/./CharToIntnl("$&")/ge; -- Old slow version

    #print STDERR "Was $linkurl\n";
    return ("", 0)
      unless $linkurl =~ /[.\/]/;    # Ignore if it is not a website at all
     #$linkurl = "" unless $linkurl =~ /[.\/]/; # Ignore if it is not a website at all
    $linkurl =~ s/\s+//g;     # Remove any whitespace
    $linkurl =~ s/\\/\//g;    # Change \ to / as many browsers do this
                              #print STDERR "Is $linkurl\n";
    return ("", 0) if $linkurl =~ /\@/ && $linkurl !~ /\//;    # Ignore emails
         #$linkurl = "" if $linkurl =~ /\@/ && $linkurl !~ /\//; # Ignore emails
    $linkurl =~ s/[,.]+$//;  # Remove trailing dots, but also commas while at it
    $linkurl =~ s/^\[\d*\]//;              # Remove leading [numbers]
    $linkurl =~ s/^blocked[:\/]+//i;       # Remove "blocked::" labels
    $linkurl =~ s/^blocked[:\/]+//i;       # And again, in case there are 2
    $linkurl =~ s/^blocked[:\/]+//i;       # And again, in case there are 3
    $linkurl =~ s/^blocked[:\/]+//i;       # And again, in case there are 4
    $linkurl =~
      s/^outbind:\/\/\d+\//http:\/\//i;    # Remove "outbind://22/" type labels
     #$linkurl =~ s/^.*\<((https?|ftp|mailto|webcal):[^>]+)\>.*$/$1/i; # Turn blah-blah <http://link.here> blah-blah into "http://link.here"
    $linkurl = $DisarmBaseURL . '/' . $linkurl
      if $linkurl ne ""
      && $DisarmBaseURL ne ""
      && $linkurl !~ /^(https?|ftp|mailto|webcal):/i;
    $linkurl =~ s/^(https?:\/\/[^:]+):80($|\D)/$1/i;    # Remove http://....:80
    $linkurl =~ s/^(https?|ftp|webcal)[:;]\/\///i;
    return ("", 0) if $linkurl =~ /^ma[il]+to[:;]/i;

    #$linkurl = "" if $linkurl =~ /^ma[il]+to[:;]/i;
    $linkurl =~ s/[?\/].*$//;    # Only compare up to the first '/' or '?'
    $linkurl =~ s/(\<\/?(br|p|ul)\>)*$//ig;    # Remove trailing br, p, ul tags
    return ("", 0) if $linkurl =~ /^file:/i;   # Ignore file: URLs completely
         #$linkurl = "" if $linkurl =~ /^file:/i; # Ignore file: URLs completely
    return ("", 0) if $linkurl =~ /^#/;    # Ignore internal links completely
          #$linkurl = "" if $linkurl =~ /^#/; # Ignore internal links completely
    $linkurl =~ s/\/$//;     # LinkURL is trimmed -- note
    $linkurl =~ s/:80$//;    # Port 80 is the default anyway
    $alarm = 1 if $linkurl =~ s/[\x00-\x1f[:^ascii:]]/_BAD_/g;    # /\&\#/;
    $linkurl = 'JavaScript' if $linkurl =~ /^javascript:/i;
    ($linkurl, $alarm);
}

# Return 1 if the hostname in $linkurl is in the safe sites file.
# Return 0 otherwise.
sub InPhishingWhitelist {
    my ($linkurl) = @_;

    if (defined($$Baruwa::Scanner::Config::PhishingWhitelist)) {
        return 1
          if ($$Baruwa::Scanner::Config::PhishingWhitelist->EXISTS($linkurl));

        # Trim host. off the front of the hostname
        while ($linkurl ne "" && $linkurl =~ s/^[^.]+\.//) {

            #print STDERR "Looking up *.$linkurl\n";
            return 1
              if (
                $$Baruwa::Scanner::Config::PhishingWhitelist->EXISTS(
                    '*.' . $linkurl
                )
              );
        }
    }

    return 0;
}

# Return 1 if the hostname in $linkurl is in the bad sites file.
sub InPhishingBlacklist {
    my ($linkurl) = @_;

    if (defined($$Baruwa::Scanner::Config::PhishingBlacklist)) {
        return 1
          if ($$Baruwa::Scanner::Config::PhishingBlacklist->EXISTS($linkurl));

        # Trim host. off the front of the hostname
        while ($linkurl ne "" && $linkurl =~ s/^[^.]+\.//) {

            #print STDERR "Looking up *.$linkurl\n";
            return 1
              if (
                $$Baruwa::Scanner::Config::PhishingBlacklist->EXISTS(
                    '*.' . $linkurl
                )
              );
        }
    }

    return 0;
}

# Convert 1 MIME entity from html to text using HTML::Parser.
sub HTMLEntityToText {
    my ($this, $entity) = @_;

    my ($htmlname, $textname, $textfh, $htmlparser);

    # Replace the MIME Content-Type
    $entity->head->mime_attr('Content-type' => 'text/plain');

    # Replace the filename with a new one
    $htmlname = $entity->bodyhandle->path();
    $textname = $htmlname;
    $textname =~ s/\..?html?$//i;    # Remove .htm .html .shtml
    $textname .= '.txt';    # This should always pass the filename checks
    $entity->bodyhandle->path($textname);

    # Create the new file with the plain text in it
    $textfh = new FileHandle;
    unless ($textfh->open(">$textname")) {
        Baruwa::Scanner::Log::WarnLog('Could not create plain text file %s',
            $textname);
        return;
    }
    $htmlparser = HTML::TokeParser::Baruwa::Scanner->new($htmlname);

    # Turn links into text containing the URL
    $htmlparser->{textify}{a}   = 'href';
    $htmlparser->{textify}{img} = 'src';

    my $inscript = 0;
    my $instyle  = 0;
    while (my $token = $htmlparser->get_token()) {
        next if $token->[0] eq 'C';

        # Don't output the contents of style or script sections
        if ($token->[1] =~ /style/i) {
            $instyle = 1 if $token->[0] eq 'S';
            $instyle = 0 if $token->[0] eq 'E';
            next if $instyle;
        }
        if ($token->[1] =~ /script/i) {
            $inscript = 1 if $token->[0] eq 'S';
            $inscript = 0 if $token->[0] eq 'E';
            next if $inscript;
        }
        my $text = $htmlparser->get_trimmed_text();
        print $textfh $text . "\n" if $text;
    }
    $textfh->close();
}

#
# Delete all the recipients from a message, completely
# This is currently only used in the forwarding system in the filename
# and filetype checks in SweepOther.pm
#
sub DeleteAllRecipients {
    my ($message) = @_;

    $global::MS->{mta}->DeleteRecipients($message);
    my (@dummy);
    @{$message->{to}}       = @dummy;
    @{$message->{touser}}   = @dummy;
    @{$message->{todomain}} = @dummy;
}

# Quarantine a DoS attack message which has successfully killed
# Baruwa several times in the past.
sub QuarantineDOS {
    my ($message) = @_;

    Baruwa::Scanner::Log::WarnLog(
        'Quarantined message %s as it caused Baruwa to crash several times',
        $message->{id});

    $message->{quarantinedinfections} = 1;    # Stop it quarantining it twice
    $message->{deleted}               = 1;
    $message->{abandoned}             = 1;
    $message->{stillwarn}             = 1;
    $message->{infected}              = 1;
    $message->{virusinfected}         = 0;
    $message->{otherinfected}         = 1;
    my $report =
        Baruwa::Scanner::Config::LanguageValue($message, 'baruwa') . ': '
      . Baruwa::Scanner::Config::LanguageValue($message, 'killedbaruwa');
    $message->{reports}{""}    = $report;
    $message->{allreports}{""} = $report;
    $message->{types}{""}      = 'e';         # Error processing
    $message->{alltypes}{""}   = 'e';         # Error processing

    $global::MS->{quar}->StoreInfections($message);
}

#
# This is an improvement to the default HTML-Parser routine for getting
# the text out of an HTML message. The only difference to their one is
# that I join the array of items together with spaces rather than "".
#
package HTML::TokeParser::Baruwa::Scanner;

use HTML::Entities qw(decode_entities);

use vars qw(@ISA);
@ISA = qw(HTML::TokeParser);

sub get_text {
    my $self  = shift;
    my $endat = shift;
    my @text;
    while (my $token = $self->get_token) {
        my $type = $token->[0];
        if ($type eq "T") {
            my $text = $token->[1];
            decode_entities($text) unless $token->[2];
            push(@text, $text);
        } elsif ($type =~ /^[SE]$/) {
            my $tag = $token->[1];
            if ($type eq "S") {
                if (exists $self->{textify}{$tag}) {
                    my $alt = $self->{textify}{$tag};
                    my $text;
                    if (ref($alt)) {
                        $text = &$alt(@$token);
                    } else {
                        $text = $token->[2]{$alt || "alt"};
                        $text = "[\U$tag]" unless defined $text;
                    }
                    push(@text, $text);
                    next;
                }
            } else {
                $tag = "/$tag";
            }
            if (!defined($endat) || $endat eq $tag) {
                $self->unget_token($token);
                last;
            }
        }
    }

    # JKF join("", @text);
    join(" ", @text);
}

# And switch back to the original package we were in
package Baruwa::Scanner::Message;

#
# This is an improvement to the default MIME character set decoding that
# is done on attachment filenames. It decodes all the character sets it
# knows about, just as before. But instead of warning about character sets
# it doesn't know about (and removing characters in them), it strips
# out all the 8-bit characters (rare) and leaves the 7-bit ones (common).
#
sub WordDecoderKeep7Bit {
    local $_ = shift;

    # JKF 19/8/05 Allow characters with the top bit set.
    # JKF 19/8/05 Still blocks 16-bit characters though, as it should.
    #tr/\x00-\x7F/#/c;
    tr/\x00-\xFF/#/c;
    $_;
}

#
# Over-ride a function in MIME::Entity that gets called every time a MIME
# part is added to a message. The new version bails out if there were too
# many parts in the message. The limit will be read from the config.
# It just sets the entity to undef and relies on the supporting code to
# actually generate the error.
#

package MIME::Entity;

use vars qw(@ISA $EntityPartCounter $EntityPartCounterMax);
@ISA = qw(Mail::Internet);

# Reset the counter and the limit
sub ResetBaruwaCounter {
    my ($number) = @_;
    $EntityPartCounter    = 0;
    $EntityPartCounterMax = $number;
}

# Read the Counter
sub BaruwaCounter {
    return $EntityPartCounter || 0;
}

# Over-rise their add_part function with my own with counting added
sub add_part {
    my ($self, $part, $index) = @_;
    defined($index) or $index = -1;

    # Incrememt the part counter so I can detect messages with too many parts
    $EntityPartCounter++;

    #print STDERR "Added a part. Counter = $EntityPartCounter, Max = " .
    #             $EntityPartCounterMax\n";
    return undef
      if $EntityPartCounterMax > 0
      && $EntityPartCounter > $EntityPartCounterMax;

    ### Make $index count from the end if negative:
    $index = $#{$self->{ME_Parts}} + 2 + $index if ($index < 0);
    splice(@{$self->{ME_Parts}}, $index, 0, $part);
    $part;
}

#
# Over-ride a function in Mail::Header that parses the block of headers
# at the top of each MIME section. My improvement allows the first line
# of the header block to be missing, which breaks the original parser
# though the filename is still there.
#

package Mail::Header;
our $FIELD_NAME = '[^\x00-\x1f\x7f-\xff :]+:';

sub extract {
    my ($self, $lines) = @_;
    $self->empty;

    # JKF Make this more robust by allowing first line of header to be missing
    shift @{$lines}
      while scalar(@{$lines})
      && $lines->[0] =~ /\A[ \t]+/o
      && $lines->[1] =~ /\A$FIELD_NAME/o;

    # JKF End mod here

    while (@$lines) {
        unless ($lines->[0] =~ /^($FIELD_NAME|From )/o) {
            if ($lines->[0] =~ /^$/o) {
                last;
            }
            shift @$lines;
            next;
        }
        my $tag  = $1;
        my $line = shift @$lines;
        $line .= shift @$lines while @$lines && $lines->[0] =~ /^[ \t]+/o;

        ($tag, $line) = _fmt_line $self, $tag, $line;

        _insert $self, $tag, $line, -1 if defined $line;
    }

    shift @$lines
      if @$lines && $lines->[0] =~ /^\s*$/o;

    $self;
}

#
# Over-ride the read function similar to extract but reads from file
# Only change is my comment below. MAS
#

sub read {
    my ($self, $fd) = @_;

    $self->empty;

    my ($tag, $line);
    my $ln = '';
    while (1) {
        $ln = <$fd>;

        if (defined $ln && defined $line && $ln =~ /\A[ \t]+/o) {
            $line .= $ln;
            next;
        }

        if (defined $line) {
            ($tag, $line) = _fmt_line $self, $tag, $line;
            _insert $self, $tag, $line, -1
              if defined $line;
        }

        # MAS - Change begins here
        if (defined $ln && $ln =~ /^($FIELD_NAME|From )/o) {
            ($tag, $line) = ($1, $ln);
        } elsif ($ln =~ /^$/) {

            # Only stop on empty line - just drop a non-header,
            # non continuation line
            last;
        }    # MAS End of change
    }

    $self;
}

