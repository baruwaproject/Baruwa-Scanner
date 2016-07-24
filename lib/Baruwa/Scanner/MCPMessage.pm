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
use MIME::WordDecoder;
use POSIX qw(setsid);
use HTML::TokeParser;

# Install an extra MIME decoder for badly-header uue messages.
install MIME::Decoder::UU 'uuencode';

our $VERSION = '4.086000';

# Is this message spam? Try to build the spam report and store it in
# the message.
sub IsMCP {
    my $this = shift;
    my ( $includesaheader, $iswhitelisted );

    my $spamheader    = "";
    my $rblspamheader = "";
    my $saspamheader  = "";
    my $RBLsaysspam   = 0;
    my $rblcounter    = 0;
    my $LogSpam       = Baruwa::Scanner::Config::Value('logmcp');
    my $LocalSpamText = Baruwa::Scanner::Config::LanguageValue( $this, 'mcp' );

    # Construct a pretty list of all the unique domain names for logging
    my ( %todomain, $todomain );
    foreach $todomain ( @{ $this->{todomain} } ) {
        $todomain{$todomain} = 1;
    }
    $todomain = join( ',', keys %todomain );

    $this->{mcpwhitelisted} = 0;
    $this->{ismcp}          = 0;
    $this->{ishighmcp}      = 0;
    $this->{mcpreport}      = "";
    $this->{mcpsascore}     = 0;

    # Work out if they always want the SA header
    $includesaheader = Baruwa::Scanner::Config::Value( 'includemcpheader', $this );

    # Do the whitelist check before the blacklist check.
    # If anyone whitelists it, then everyone gets the message.
    # If no-one has whitelisted it, then consider the blacklist.
    $iswhitelisted = 0;
    if ( Baruwa::Scanner::Config::Value( 'mcpwhitelist', $this ) ) {

        # Whitelisted, so get out unless they want SA header
        #print STDERR "Message is whitelisted\n";
        $iswhitelisted = 1;
        $this->{mcpwhitelisted} = 1;

        # whitelisted and doesn't want SA header so get out
        return 0 unless $includesaheader;
    }

    # If it's a blacklisted address, don't bother doing any checks at all
    if ( Baruwa::Scanner::Config::Value( 'mcpblacklist', $this ) ) {
        $this->{ismcp}     = 1;
        $this->{ishighmcp} = 1
          if Baruwa::Scanner::Config::Value( 'mcpblacklistedishigh', $this );
        $this->{mcpreport} = $LocalSpamText . ' ('
          . Baruwa::Scanner::Config::LanguageValue( $this, 'mcpblacklisted' ) . ')';
        Baruwa::Scanner::Log::InfoLog(
            "Message %s from %s (%s) to %s" . " is banned (MCP blacklisted)",
            $this->{id}, $this->{clientip}, $this->{from}, $todomain )
          if $LogSpam;
        return 1;
    }

    # They must want the SA checks doing.

    my $SAsaysspam    = 0;
    my $SAHighScoring = 0;
    my $saheader      = "";
    my $sascore       = 0;
    ( $SAsaysspam, $SAHighScoring, $saheader, $sascore ) =
      Baruwa::Scanner::MCP::Checks($this);
    $this->{mcpsascore} = $sascore;    # Save the actual figure for use later...

    # Fix the return values
    $SAsaysspam = 0 unless $saheader;    # Solve bug with empty SAreports
    $saheader =~ s/\s+$//g if $saheader; # Solve bug with trailing space

    $saheader =
      Baruwa::Scanner::Config::LanguageValue( $this, 'mcpspamassassin' )
      . " ($saheader)"
      if $saheader;

    # The message really is spam if SA says so (unless it's been whitelisted)
    unless ($iswhitelisted) {
        $this->{ismcp} |= $SAsaysspam;
        $this->{issamcp} = $SAsaysspam;
    }

    # If it's spam...
    if ( $this->{ismcp} ) {
        $spamheader = $rblspamheader;

        # If it's SA spam as well, or they always want the SA header
        if ( $SAsaysspam || $includesaheader ) {

            #print STDERR "Spam or Add SA Header\n";
            $spamheader = $LocalSpamText unless $spamheader;
            $spamheader .= ', ' if $spamheader && $saheader;
            $spamheader .= $saheader;
            $this->{ishighmcp} = 1 if $SAHighScoring;
        }
    }
    else {
        # It's not spam...
        $spamheader = Baruwa::Scanner::Config::LanguageValue( $this, 'mcpnotspam' );
        if ($iswhitelisted) {
            $spamheader .= ' ('
              . Baruwa::Scanner::Config::LanguageValue( $this, 'mcpwhitelisted' )
              . ')';
        }
        $spamheader .= ", $saheader";
    }

    # Now just reflow and log the results
    if ( $spamheader ne "" ) {
        $spamheader =
          $this->ReflowHeader( Baruwa::Scanner::Config::Value( 'mcpheader', $this ),
            $spamheader );
        $this->{mcpreport} = $spamheader;
    }

    # Do the spam logging here so we can log high-scoring spam too
    if ( $LogSpam && $this->{ismcp} ) {
        my $ReportText = $spamheader;
        $ReportText =~ s/\s+/ /sg;
        Baruwa::Scanner::Log::InfoLog( "Message %s from %s (%s) to %s is %s",
            $this->{id}, $this->{clientip},
            $this->{from}, $todomain, $ReportText );
    }

    return $this->{ismcp};
}

# Do whatever is necessary with this message to deal with spam.
# We can assume the message passed is indeed spam (isspam==true).
# Call it with either 'spam' or 'nonspam'. Don't use 'ham'!
sub HandleMCP {
    my ( $this, $HamSpam ) = @_;

    my ( $actions, $action, @actions, %actions );
    my ( @extraheaders, $actionscopy, $actionkey );

    # Get a space-separated list of all the actions
    if ( $HamSpam eq 'nonmcp' ) {
        $actions = Baruwa::Scanner::Config::Value( 'nonmcpactions', $this );
        return if $actions eq 'deliver';
    }
    else {
        # It must be spam as it's not ham
        if ( $this->{ishighmcp} ) {
            $actions =
              Baruwa::Scanner::Config::Value( 'highscoremcpactions', $this );
        }
        else {
            $actions = Baruwa::Scanner::Config::Value( 'mcpactions', $this );
        }
    }

    # Find all the bits in quotes, with their spaces
    $actionscopy = $actions;

    #print STDERR "Actions = \'$actions\'\n";
    while ( $actions =~ s/\"([^\"]+)\"// ) {
        $actionkey = $1;
        push @extraheaders, $actionkey;
        Baruwa::Scanner::Log::WarnLog(
            "Syntax error in \"header\" action in MCP "
              . "actions, missing \":\" in %s",
            $actionkey
        ) unless $actionkey =~ /:/;
    }
    @{ $this->{extramcpheaders} } = @extraheaders;
    $actions = lc($actions);
    $actions =~ s/^\s*//;
    $actions =~ s/\s*$//;
    $actions =~ s/\s+/ /g;

    #print STDERR "Actions after = \'$actions\'\n";
    #print STDERR "Extra headers are \"" . join(',',@extraheaders) . "\"\n";

    Baruwa::Scanner::Log::WarnLog( 'Syntax error: missing " in MCP actions %s',
        $actionscopy )
      if $actions =~ /\"/;

    $actions =~ tr/,//d;    # Remove all commas in case they put any in
    @actions = split( " ", $actions );

    # The default action if they haven't specified anything is to
    # deliver spam like normal mail.
    return unless @actions;

    # If they have just specified a filename, then something is wrong
    if ( $#actions == 0 && $actions[0] =~ /\// ) {
        Baruwa::Scanner::Log::WarnLog(
            'Your MCP actions "%s" looks like a filename.'
              . ' If this is a ruleset filename, it must end in .rule or .rules',
            $actions[0]
        );
        $actions[0] = 'deliver';
    }

    foreach $action (@actions) {

        # Allow for store-mcp, store-nonspam, etc.
        $action =~ s/^store\W(\w+).*$/store-$1/;

        $actions{$action} = 1;

        #print STDERR "Message: HandleSpam action is $action\n";
        if ( $action =~ /\@/ ) {

            #print STDERR "Message " . $this->{id} . " : HandleSpam() adding " .
            #             "$action to archiveplaces\n";
            push @{ $this->{archiveplaces} }, $action;
            $actions{'forward'} = 1;
        }
    }

    # Split this job into 2.
    # 1) The message is being delivered to at least 1 address,
    # 2) The message is not being delivered to anyone.
    # The extra addresses for forward it to have already been added.
    if ( $actions{'deliver'} || $actions{'forward'} ) {
        #
        # Message is going to original recipient and/or extra recipients
        #

        Baruwa::Scanner::Log::InfoLog( "MCP Actions: message %s actions are %s",
            $this->{id}, join( ',', keys %actions ) )
          if $HamSpam eq 'mcp' && Baruwa::Scanner::Config::Value('logmcp');

        # Delete action is over-ridden as we are sending it somewhere
        delete $actions{'delete'};

        # Delete the original recipient if they are only forwarding it
        $this->{mcpdelivering} = 1;
        if ( !$actions{'deliver'} ) {
            $global::MS->{mta}->DeleteRecipients($this);
            $this->{mcpdelivering} = 0;
        }

        # Message still exists, so it will be delivered to its new recipients
    }
    else {
        #
        # Message is not going to be delivered anywhere
        #

        Baruwa::Scanner::Log::InfoLog( "MCP Actions: message %s actions are %s",
            $this->{id}, join( ',', keys %actions ) )
          if $HamSpam eq 'mcp' && Baruwa::Scanner::Config::Value('logmcp');

        # Mark the message as deleted, so it won't get delivered
        #$this->{deleted} = 1;
        $this->{dontdeliver} =
          1;    # Don't clean or deliver this message, just drop
         # Mark this message as not being delivered by MCP, for later spam filtering
        $this->{mcpdelivering} = 0;
    }

    # All delivery will now happen correctly.

    # Bounce a message back to the sender if they want that
    if ( $actions{'bounce'} ) {
        if ( $HamSpam eq 'nonmcp' ) {
            Baruwa::Scanner::Log::WarnLog("Does not make sense to bounce non-mcp");
        }
        else {
            $this->HandleMCPBounce();
        }
    }

    # Notify the recipient if they want that
    if ( $actions{'notify'} ) {
        if ( $HamSpam eq 'nonmcp' ) {
            Baruwa::Scanner::Log::WarnLog(
                "Does not make sense to notify recipient about non-mcp");
        }
        else {
            $this->HandleMCPNotify();
        }
    }

    # Store it if they want that
    my @stores;
    push @stores, $HamSpam  if $actions{'store'};
    push @stores, 'nonmcp'  if $actions{'store-nonmcp'};
    push @stores, 'mcp'     if $actions{'store-mcp'};
    push @stores, 'nonspam' if $actions{'store-nonspam'};
    push @stores, 'spam'    if $actions{'store-spam'};
    $this->{ismcp} = 1 if $actions{'store-mcp'};

    foreach my $store (@stores) {
        my ( $dir, $dir2, $spamdir, $uid, $gid, $changeowner );
        $dir = Baruwa::Scanner::Config::Value( 'quarantinedir', $this );

        #$dir2 = $dir . '/' .  Baruwa::Scanner::Quarantine::TodayDir();
        $dir2        = $dir . '/' . $this->{datenumber};
        $spamdir     = $dir2 . '/' . $store;
        $uid         = $global::MS->{quar}->{uid};
        $gid         = $global::MS->{quar}->{gid};
        $changeowner = $global::MS->{quar}->{changeowner};
        umask $global::MS->{quar}->{dirumask};
        unless ( -d $dir ) {
            mkdir $dir, 0777;
            chown $uid, $gid, $dir if $changeowner;
        }
        unless ( -d $dir2 ) {
            mkdir $dir2, 0777;
            chown $uid, $gid, $dir2 if $changeowner;
        }
        unless ( -d $spamdir ) {
            mkdir $spamdir, 0777;
            chown $uid, $gid, $spamdir if $changeowner;
        }

        #print STDERR "Storing spam to $spamdir/" . $this->{id} . "\n";
        umask $global::MS->{quar}->{fileumask};
        my @paths =
          $this->{store}->CopyEntireMessage( $this, $spamdir, $this->{id} );

        # Remember where we have stored the mcp in an archive, so we never
        # archive infected messages.
        push @{ $this->{spamarchive} }, @paths;
        chown $uid, $gid, "$spamdir/" . $this->{id};    # Harmless if this fails
    }
    umask 0077;                                         # Safety net

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
sub HandleMCPBounce {
    my $this = shift;

    my ( $from,     $to,   $subject,   $date,     $spamreport,      $hostname );
    my ( $emailmsg, $line, $messagefh, $filename, $localpostmaster, $id );
    my ($postmastername);

    $from = $this->{from};

    # Don't ever send a message to "" or "<>"
    return if $from eq "" || $from eq "<>";

    # Do we want to send the sender a warning at all?
    # If nosenderprecedence is set to non-blank and contains this
    # message precedence header, then just return.
    my ( @preclist, $prec, $precedence, $header );
    @preclist =
      split( " ",
        lc( Baruwa::Scanner::Config::Value( 'nosenderprecedence', $this ) ) );
    $precedence = "";
    foreach $header ( @{ $this->{headers} } ) {
        $precedence = lc($1) if $header =~ /^precedence:\s+(\S+)/i;
    }
    if ( @preclist && $precedence ne "" ) {
        foreach $prec (@preclist) {
            if ( $precedence eq $prec ) {
                Baruwa::Scanner::Log::InfoLog( "Skipping sender of precedence %s",
                    $precedence );
                return;
            }
        }
    }

    # Setup other variables they can use in the message template
    $id              = $this->{id};
    $to              = join( ', ', @{ $this->{to} } );
    $localpostmaster = Baruwa::Scanner::Config::Value( 'localpostmaster', $this );
    $postmastername = Baruwa::Scanner::Config::LanguageValue( $this, 'baruwa' );
    $hostname = Baruwa::Scanner::Config::Value( 'hostname', $this );
    $subject = $this->{subject};
    $date       = $this->{datestring};    # scalar localtime;
    $spamreport = $this->{mcpreport};

    # Delete everything in brackets after the SA report, if it exists
    $spamreport =~ s/(spamassassin)[^(]*\([^)]*\)/$1/i;

    # Work out which of the 3 spam reports to send them.
    $filename = "";

    if ( $this->{issamcp} ) {
        $filename = Baruwa::Scanner::Config::Value( 'sendersamcpreport', $this );
        Baruwa::Scanner::Log::NoticeLog( "MCP Actions: (SpamAssassin) Bounce to %s",
            $from )
          if Baruwa::Scanner::Config::Value('logmcp');
    }

    $messagefh = new FileHandle;
    $messagefh->open($filename)
      or Baruwa::Scanner::Log::WarnLog( "Cannot open message file %s, %s",
        $filename, $! );
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

    if ( Baruwa::Scanner::Config::Value( 'bouncemcpasattachment', $this ) ) {
        $this->HandleMCPBounceAttachment($emailmsg);
    }
    else {
        # Send the message to the spam sender, but ensure the envelope
        # sender address is "<>" so that it can't be bounced.
        $global::MS->{mta}->SendMessageString( $this, $emailmsg, '<>' )
          or Baruwa::Scanner::Log::WarnLog( "Could not send sender MCP bounce, %s",
            $! );
    }
}

# Like encapsulating and sending a message to the recipient, take the
# passed text as the text and headers of an email message and attach
# the original message as an rfc/822 attachment.
sub HandleMCPBounceAttachment {
    my ( $this, $plaintext ) = @_;

    my $parser      = MIME::Parser->new;
    my $explodeinto = $global::MS->{work}->{dir} . '/' . $this->{id};

    #print STDERR "Extracting MCP bounce message into $explodeinto\n";
    my $filer = MIME::Parser::FileInto->new($explodeinto);
    $parser->filer($filer);

    my $bounce = eval { $parser->parse_data( \$plaintext ) };
    if ( !$bounce ) {
        Baruwa::Scanner::Log::WarnLog( "Cannot parse MCP bounce report, %s", $! );
        return;
    }

    #print STDERR "Successfully parsed bounce report\n";

    # Now make it multipart and push the report into a child
    $bounce->make_multipart('report');

    # Now turn the original message into a string and attach it
    my (@original);

    #my $original = $this->{entity}->stringify;
    @original = $global::MS->{mta}->OriginalMsgHeaders( $this, "\n" );
    push( @original, "\n" );
    $this->{store}->ReadBody( \@original,
        Baruwa::Scanner::Config::Value('maxspamassassinsize') );

    $bounce->add_part(
        MIME::Entity->build(
            Type        => 'message/rfc822',
            Disposition => 'attachment',
            Top         => 0,
            'X-Mailer'  => undef,
            Data        => \@original
        )
    );

    # Stringify the message and send it -- this could be VERY large!
    # Prune all the dead branches off the tree
    PruneEntityTree($bounce);
    my $bouncetext = $bounce->stringify;

    #print STDERR "Spam bounce message is this:\n$bouncetext";
    if ($bouncetext) {
        $global::MS->{mta}->SendMessageString( $this, $bouncetext, '<>' )
          or Baruwa::Scanner::Log::WarnLog(
            "Could not send sender MCP bounce attachment, %s", $! );
    }
    else {
        Baruwa::Scanner::Log::WarnLog(
            "Failed to create sender MCP bounce attachment, %s", $! );
    }
}

# We want to send a message to the recipient saying that their spam
# mail has not been delivered.
# Send a message to the recipients which has the local postmaster as
# the sender.
sub HandleMCPNotify {
    my $this = shift;

    my (
        $from,     $to,  $subject, $date, $spamreport,
        $hostname, $day, $month,   $year
    );
    my ( $emailmsg, $line, $messagefh, $filename, $localpostmaster, $id );
    my ($postmastername);

    $from = $this->{from};

    # Don't ever send a message to "" or "<>"
    return if $from eq "" || $from eq "<>";

    # Do we want to send the sender a warning at all?
    # If nosenderprecedence is set to non-blank and contains this
    # message precedence header, then just return.
    my ( @preclist, $prec, $precedence, $header );
    @preclist =
      split( " ",
        lc( Baruwa::Scanner::Config::Value( 'nosenderprecedence', $this ) ) );
    $precedence = "";
    foreach $header ( @{ $this->{headers} } ) {
        $precedence = lc($1) if $header =~ /^precedence:\s+(\S+)/i;
    }
    if ( @preclist && $precedence ne "" ) {
        foreach $prec (@preclist) {
            if ( $precedence eq $prec ) {
                Baruwa::Scanner::Log::InfoLog( "Skipping sender of precedence %s",
                    $precedence );
                return;
            }
        }
    }

    # Setup other variables they can use in the message template
    $id = $this->{id};
    $localpostmaster = Baruwa::Scanner::Config::Value( 'localpostmaster', $this );
    $postmastername = Baruwa::Scanner::Config::LanguageValue( $this, 'baruwa' );
    $hostname = Baruwa::Scanner::Config::Value( 'hostname', $this );
    $subject = $this->{subject};
    $date       = $this->{datestring};    # scalar localtime;
    $spamreport = $this->{mcpreport};

    my $datenumber = $this->{datenumber};

    my (%tolist);
    foreach $to ( @{ $this->{to} } ) {
        $tolist{$to} = 1;
    }
    $to = join( ', ', sort keys %tolist );

    # Delete everything in brackets after the SA report, if it exists
    $spamreport =~ s/(spamassassin)[^(]*\([^)]*\)/$1/i;

    # Work out which of the 3 spam reports to send them.
    $filename = Baruwa::Scanner::Config::Value( 'recipientmcpreport', $this );
    Baruwa::Scanner::Log::InfoLog( "MCP Actions: Notify %s", $to )
      if Baruwa::Scanner::Config::Value('logmcp');

    $messagefh = new FileHandle;
    $messagefh->open($filename)
      or Baruwa::Scanner::Log::WarnLog( "Cannot open message file %s, %s",
        $filename, $! );
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
    #print STDERR "Sending notify:\n$emailmsg\nEnd notify.\n";
    $global::MS->{mta}->SendMessageString( $this, $emailmsg, $localpostmaster )
      or Baruwa::Scanner::Log::WarnLog( "Could not send recipient mcp notify, %s",
        $! );
}

1;

