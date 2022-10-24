#!/usr/bin/perl;
#

use strict;
use warnings;
use FindBin;
use Data::Dumper;

use lib "$FindBin::Bin";
use My::PcapNG qw(read_whole_file read_return_individual_blocks);

&main;

sub main {
    print "I'm in main...\n";
    &EXAMPLE_read_return_individual_blocks($ARGV[0]);
}

sub EXAMPLE_read_return_individual_blocks {
    my $file=shift;
    open(my $fh,$file);
    binmode($fh);
    until (eof($fh)) {
        my $location=tell($fh);
        my $block=read_return_individual_blocks($fh,$location);
        print "I got $block\n";
        print Dumper $block;
    }
    close($fh);
}

sub EXAMPLE_read_whole_file {
    my $file=shift;
    my $blocks=read_whole_file($file);

    foreach my $key (sort {$a<=>$b} keys %{$blocks}) {
        print "My Block Number: $key - Type: $$blocks{$key}{'block_type_name'}\n";
                print Dumper $$blocks{$key};
    }
}
