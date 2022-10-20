package My::PcapNG;

#This is a module to handle the reading of pcapng files

use strict;
use warnings;

use Exporter qw(import);
use Data::Dumper;

our @EXPORT_OK =qw(read_whole_file read_return_individual_blocks);

my %defined_blocks = (
    168627466   => \&read_section_header_block,
    1           => \&read_interface_description_block,
    5           => \&read_interface_statistics_block,
    6           => \&read_enhanced_packet_block, 
);

my %option_blocks = (
    168627466 => {
        0   => "opt_endofopt",
        1   => "opt_comment",
        2   => "shb_hardware",
        3   => "shb_os",
        4   => "shb_userappl",
    },
    1   =>  {
        1   =>  "if_comment",
        2   =>  "if_name",
        3   =>  "if_description",
        4   =>  "if_IPv4addr",
        5   =>  "if_IPv6addr",
        6   =>  "if_MACaddr",
        7   =>  "if_EUIaddr",
        8   =>  "if_speed",
        9   =>  "if_tsresol",
        10  =>  "if_tzone",
        11  =>  "if_filter",
        12  =>  "if_os",
        13  =>  "if_fcslen",
        14  =>  "if_tsoffset",
        15  =>  "if_hardware",
        16  =>  "if_txspeed",
        17  =>  "if_rxspeed",
    },
    5   => {
        1   =>  "isb_comment",
        2   =>  "isb_starttime",
        3   =>  "isb_endtime",
        4   =>  "isb_ifrecv",
        5   =>  "isb_ifdrop",
        6   =>  "isb_filteraccept",
        7   =>  "isb_osdrop",
        8   =>  "isb_usrdeliv",
    },
    6   => {
        1   =>  "epb_comment",
        2   =>  "epb_flags",
        3   =>  "epb_hash",
        4   =>  "epb_dropcount",
        5   =>  "epb_packetid",
        6   =>  "epb_queue",
        7   =>  "epb_verdict",
    },
);

sub read_whole_file {
    my $file=shift;
    my $file_location=0;
    my %pcapng_file=();
    my $counter=0;
    open(my $fh,$file) or die "Could not open file: $!\n";
    binmode($fh);
    until (eof($fh)) {
        $counter++;
        my %block=();
        read($fh,my $block_type_and_length,8);
        my ($block_type,$block_length)=unpack("LL",$block_type_and_length);
        read($fh,my $block_data,$block_length-8);
        if (defined($defined_blocks{$block_type})) {
           $pcapng_file{$counter}=$defined_blocks{$block_type}(\$block_length,\$block_data);
        }
        else {
            print "$block_type -- I have no idea what this is, it doesn't match a block description that I have!!!\n";
        }
    }
    close($fh);
    return \%pcapng_file;
}

sub read_return_individual_blocks {
    my $fh=shift;
    my $location=shift;
    seek($fh,$location,00);
    read($fh,my $block_type_and_length,8);
    my ($block_type,$block_length)=unpack("LL",$block_type_and_length);
    read($fh,my $block_data,$block_length-8);
    if (defined($defined_blocks{$block_type})) {
       my $block=$defined_blocks{$block_type}(\$block_length,\$block_data);
       return $block;
    }
    else {
        print "$block_type -- I have no idea what this is, it doesn't match a block description that I have!!!\n";
    }
}

sub read_interface_statistics_block {
    my ($block_length,$block_data)=@_;
    my $block_location=0;
    my %block=();
    my $block_code=5;
    $block{'block_type_integer'}=5;
    $block{'block_type_name'}="Interface Statistics Block";
    $block{'block_interface_id'}=unpack("L",substr($$block_data,$block_location,4));
    $block{'block_timestamp_high'}=unpack("L",substr($$block_data,$block_location+4,4));
    $block{'block_timestamp_low'}=unpack("L",substr($$block_data,$block_location+8,4));
    $block_location+=12;
    if ($block_location < $$block_length) {
        $block{'block_options'}=&get_options($block_data,$block_location,$block_length,$block_code);
    }
    return \%block;
}

sub read_enhanced_packet_block {
    my ($block_length,$block_data)=@_;
    my $block_location=0;
    my %block=();
    my $block_code=6;
    $block{'block_type_integer'}=6;
    $block{'block_type_name'}="Enhanced Packet Block";
    $block{'block_interface_id'}=unpack("L",substr($$block_data,$block_location,4));
    $block{'block_timestamp_high'}=unpack("L",substr($$block_data,$block_location+4,4));
    $block{'block_timestamp_low'}=unpack("L",substr($$block_data,$block_location+8,4));
    $block{'block_captured_packet_length'}=unpack("L",substr($$block_data,$block_location+12,4));
    $block{'block_original_packet_length'}=unpack("L",substr($$block_data,$block_location+16,4));
    $block{'block_packet_data'}=substr($$block_data,$block_location+20,$block{'block_original_packet_length'});
    my $padding=(4-($block{'block_captured_packet_length'}%4))%4;
    $block_location=20+$block{'block_captured_packet_length'}+$padding;
    my $my_end_value=unpack("L",substr($$block_data,$block_location,4));
    if ($my_end_value == $$block_length) {
        return \%block;
    }
    else {
        #else ($block_location < $$block_length) {
        $block{'block_options'}=&get_options($block_data,$block_location,$block_length,$block_code);
        return \%block;
    }
    #    print Dumper %block;
}

sub read_interface_description_block {
    my ($block_length,$block_data)=@_;
    my $block_location=0;
    my %block=();
    my $block_code=1;
    $block{'block_type_integer'}=1;
    $block{'block_type_name'}="Interface Description Block";
    $block{'block_total_length'}=$$block_length;
    $block{'block_link_type'}=unpack("S",substr($$block_data,$block_location,2)); 
    $block{'block_reserved'}=unpack("H*",substr($$block_data,$block_location+2,2)); 
    $block{'SnapLen'}=unpack("L",substr($$block_data,$block_location+4,4));
    $block_location+=8;
    if ($block_location < $$block_length) {
        #    print "Block location is $block_location and block length is: $$block_length\n";
        $block{'block_options'}=&get_options($block_data,$block_location,$block_length,$block_code);
    }
    #print Dumper %block;
    return \%block;
}

sub read_section_header_block {
    my ($block_length,$block_data)=@_;
    my $block_location=0;
    my %block=();
    my $block_code=168627466;
    $block{'block_type_integer'}=168627466;
    $block{'block_type_name'}="Section Header Block";
    $block{'block_total_length'}=$$block_length;
    $block{'block_data_byte_order_magic'}=unpack("H*",substr($$block_data,$block_location,4));
    $block{'block_data_major_version'}=unpack("S",substr($$block_data,$block_location+4,2));
    $block{'block_data_minor_version'}=unpack("S",substr($$block_data,$block_location+6,2));
    $block{'block_data_section_length'}=unpack("q",substr($$block_data,$block_location+8,8));
    $block_location=16;
    if ($block{'block_data_section_length'}==-1) {
        $block{'block_options'}=&get_options($block_data,$block_location,$block_length,$block_code);
    }
    #print Dumper %block;
    return \%block;
}

sub get_options {
    my ($block_data,$block_location,$block_length,$block_code)=@_;
    my $code=100000;
    my %options=();
    if ($block_location <= ($$block_length-4)) {
        until ($block_location >= ($$block_length-4) or $code == 0) {
            $code=unpack("S",substr($$block_data,$block_location,2));
            my $length=unpack("S",substr($$block_data,$block_location+2,2));
            my $value=substr($$block_data,$block_location+4,$length);
            my $padding=(4-($length%4))%4;
            $block_location+=($padding+2+2+$length);
            if ($code > 0) {
                $options{$option_blocks{$block_code}{$code}}=$value;
            }
        }
    }
    return \%options;
}
