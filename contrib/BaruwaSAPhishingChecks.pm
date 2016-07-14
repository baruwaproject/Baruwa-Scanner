package Mail::SpamAssassin::Plugin::BaruwaSAPhishingChecks;

my $VERSION = 0.1;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Timeout;
use strict;
use warnings;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

use Sys::Syslog qw(:DEFAULT setlogsock);
use constant HAS_SPF => eval { local $SIG{'__DIE__'}; require Mail::SPF; };

sub dbg {
    my $scanner = shift;
    return Mail::SpamAssassin::Logger::dbg("BaruwaSAPhishingChecks: $scanner");
}

sub new {
    my ( $class, $mailsa ) = @_;
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless( $self, $class );
    if ( $mailsa->{local_tests_only} || !HAS_SPF ) {
        $self->{disabled} = 1;
    }
    else {
        $self->{disabled} = 0;
    }

    $self->register_eval_rule('baruwa_check_spf');

    return $self;
}

sub baruwa_check_spf {
    my ( $self, $scanner ) = @_;

    return if $self->{disabled};

    my $from = $scanner->get('From:addr');
    if ( $from ne '' ) {
        if ( $from =~ /(?:fnb\.co\.za|absa\.co\.za|standardbank\.co\.za|nedbank\.co\.za)/i ){
            dbg("checking $from");
            $self->{spf_server} = Mail::SPF::Server->new(
                hostname     => $scanner->get_tag('HOSTNAME'),
                dns_resolver => $self->{main}->{resolver}
            );
            my $lasthop = $scanner->{relays_external}->[0];
            if ( !defined $lasthop ) {
                dbg("skipping checks, no suitable relay for spf use found");
                return;
            }

            my $ip       = $lasthop->{ip};
            my $identity = $from;
            my $request;
            eval {
                $request = Mail::SPF::Request->new(
                    scope         => 'mfrom',
                    identity      => $identity,
                    ip_address    => $ip,
                    helo_identity => 'unknown'
                );
                1;
            } or do {
                dbg("skipping checks, cannot create Mail::SPF::Request");
                return;
            };
            my ( $result, $comment, $text, $err );
            my $timeout = $scanner->{conf}->{spf_timeout};

            my $timer = Mail::SpamAssassin::Timeout->new(
                { secs => $timeout, deadline => $scanner->{master_deadline} } );
            $err = $timer->run_and_catch(
                sub {
                    my $query = $self->{spf_server}->process($request);

                    $result  = $query->code;
                    $comment = $query->authority_explanation if $query->can("authority_explanation");
                    $text = $query->text;
                }
            );

            if ($err) {
                chomp $err;
                dbg("spf: lookup failed: $err\n");
                return 0;
            }

            $result  ||= 'timeout';
            $comment ||= '';
            $comment =~ s/\s+/ /gs;
            $text ||= '';
            $text =~ s/\s+/ /gs;
            dbg("query for $from/$ip: result: $result, comment: $comment, text: $text");
            unless ( $result eq 'pass' || $result eq 'timeout') {
                dbg('SA Bank phishing found');
                return 1;
            }
        }
        else {
            dbg("skipping checks, $from not a South african bank domain");
        }
    } else {
        dbg("skipping checks, From: is blank");
    }

    return 0;
}

1;
