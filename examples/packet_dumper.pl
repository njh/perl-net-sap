#!/usr/bin/perl
#
# This example script reads packets
# and prints the contents of the packets 
# using Data::Dumper.
#

use Net::SAP;
use Data::Dumper;
use strict;


my $sap = Net::SAP->new( 'ipv6-global' );
die "Failed to create Net::SAP" unless ($sap);

while(1) {
	my $packet = $sap->receive();

	print Dumper( $packet )."\n";
}

$sap->close();

