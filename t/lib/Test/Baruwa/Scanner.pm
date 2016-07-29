package
    # hide from PAUSE
    Test::Baruwa::Scanner;

use strict;
use warnings;
use FindBin '$Bin';
use Exporter qw/import/;

our @EXPORT = qw/create_config/;

sub create_config {
    my ($from, $to, $path) = @_;
    open(FROM, '<', $from) or die "Could not open $from\n";
    open(TO, '>', $to) or die "Could not open $to\n";
    while (<FROM>) {
        unless (/PATH/) {
            print TO;
            next;
        }
        s/PATH/$path/;
        print TO;
    }
    close(FROM);
    close(TO);
}
