
use strict;
use Test;


# use a BEGIN block so we print our plan before Net::SAP is loaded
BEGIN { plan tests => 3 }

# load Net::SAP
use Net::SAP;




# Helpful notes.  All note-lines must start with a "#".
print "# Testing XS address conversion functions.\n";



# test converting IPv4 address to binary and back
my $ipv4_in = '1.2.3.4';

my $ipv4_bin = Net::SAP::_xs_str_to_ipaddr( 'ipv4', $ipv4_in );
my $ipv4_out = Net::SAP::_xs_ipaddr_to_str( 'ipv4', $ipv4_bin );


# Success if in = out
ok( $ipv4_in, $ipv4_out );





# test converting IPv6 address to binary and back
my $ipv6_in = '2001:1630:1508:1981:2030:9300:1234:9999';

my $ipv6_bin = Net::SAP::_xs_str_to_ipaddr( 'ipv6', $ipv6_in );
my $ipv6_out = Net::SAP::_xs_ipaddr_to_str( 'ipv6', $ipv6_bin );


# Success if in = out
ok( $ipv6_in, $ipv6_out );




# test to see if we can detect our IP address

my $ipv6_origin = Net::SAP::_xs_origin_addr( 'ipv6' );
my $ipv4_origin = Net::SAP::_xs_origin_addr( 'ipv4' );

# Need one or the other
ok( defined $ipv4_origin or defined $ipv4_origin );



exit;

