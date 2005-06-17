package Net::SAP;

################
#
# SAP: Session Announcement Protocol (rfc2974)
#
# Nicholas Humfrey
# njh@ecs.soton.ac.uk
#

use strict;
use XSLoader;
use Carp;

use Net::SAP::Packet;

use vars qw/$VERSION $PORT/;

$VERSION="0.08";
$PORT=9875;



# User friendly names for multicast groups
my %groups = (
	'ipv4'=>		'224.2.127.254',
	'ipv4-global'=>	'224.2.127.254',
	'ipv6-node'=>	'FF01::2:7FFE',
	'ipv6-link'=>	'FF02::2:7FFE',
	'ipv6-site'=>	'FF05::2:7FFE',
	'ipv6-org'=>	'FF08::2:7FFE',
	'ipv6-global'=>	'FF0E::2:7FFE',
);
	

XSLoader::load('Net::SAP', $VERSION);



sub new {
    my $class = shift;
    my ($group) = @_;
    
    
	# Work out the multicast group to use
    croak "Missing group parameter" unless defined $group;
    if (exists $groups{$group}) {
    	$group = $groups{$group};
    }


	# Store parameters
    my $self = {
    	'group'	=> $group,
    	'port'	=> $PORT,
    	'hops'	=> 127,
    };
    
    
    # Create Multicast Socket using C code
    $self->{'sock'} = _xs_socket_create(
    	$self->{'group'},
    	$self->{'port'},
    	$self->{'hops'},
    );
    return undef unless (defined $self->{'sock'});
    
    
    # Store the Socket family we ended up using
    $self->{'family'} = _xs_socket_family( $self->{'sock'} );
    

    bless $self, $class;
	return $self;
}


#
# Returns the multicast group the socket is bound to
#
sub group {
	my $self = shift;
	return $self->{'group'};
}

#
# Blocks until a valid SAP packet is received
#
sub receive {
	my $self = shift;
	my $sap_packet = undef;
	
	
	while(!defined $sap_packet) {
	
		# Recieve a packet	
		my $packet = _xs_socket_recv( $self->{'sock'} );
		next unless (defined $packet);
		next unless (exists $packet->{'data'});
		
		# Create new packet object from the data we recieved
		$sap_packet = new Net::SAP::Packet( $packet->{'data'} );
		next unless (defined $sap_packet);
		
		# Correct the origin on Stupid packets !
		if ($sap_packet->origin_address() eq '0.0.0.0' or
			$sap_packet->origin_address() eq '1.2.3.4' )
		{
			$sap_packet->origin_address( $packet->{'from'} );
		}
	}

	return $sap_packet;
}


sub send {
	my $self = shift;
	my ($packet) = @_;
	
	croak "Missing data to send." unless defined $packet;


	# If it isn't a packet object, turn it into one	
	if (ref $packet eq 'Net::SDP') {
		my $data = $packet->generate();
		$packet = new Net::SAP::Packet();
		$packet->payload( $data );
	}
	elsif (ref $packet ne 'Net::SAP::Packet') {
		my $data = $packet;
		$packet = new Net::SAP::Packet();
		$packet->payload( $data );
	}


	# Set the origin address, if there isn't one set
	if ($packet->origin_address() eq '') {
	
		$packet->origin_address_type( $self->{'family'} );
	
		$packet->origin_address( 
			_xs_origin_addr( $self->{'family'} )
		);
	}
	
	# Assemble and send the packet
	my $data = $packet->generate();
	if (!defined $data) {
		warn "Failed to create binary packet.";
		return -1;
	} elsif (length $data > 1024) {
		warn "Packet is more than 1024 bytes, not sending.";
		return -1;
	} else {
		return _xs_socket_send( $self->{'sock'}, $data );
	}
}


sub close {
	my $self=shift;
	
	# Close the multicast socket
	_xs_socket_close( $self->{'sock'} );
	
	undef $self->{'sock'};
}


sub DESTROY {
    my $self=shift;
    
    if (exists $self->{'sock'} and defined $self->{'sock'}) {
    	$self->close();
    }
}


1;

__END__

=pod

=head1 NAME

Net::SAP - Session Announcement Protocol (rfc2974)

=head1 SYNOPSIS

  use Net::SAP;

  my $sap = Net::SAP->new( 'ipv6-global' );

  my $packet = $sap->receive();

  $sap->close();


=head1 DESCRIPTION

Net::SAP allows receiving and sending of SAP (RFC2974) 
multicast packets over IPv4 and IPv6.

=head2 METHODS

=over 4

=item $sap = Net::SAP->new( $group )

The new() method is the constructor for the C<Net::SAP> class.
You must specify the SAP multicast group you want to join:

	ipv4
	ipv6-node
	ipv6-link
	ipv6-site
	ipv6-org
	ipv6-global

Alternatively you may pass the address of the multicast group 
directly. When the C<Net::SAP> object is created, it joins the 
multicast group, ready to start receiving or sending packets.


=item $packet = $sap->receive()

This method blocks until a valid SAP packet has been received.
The packet is parsed, decompressed and returned as a 
C<Net::SAP::Packet> object.


=item $sap->send( $data )

This method sends out SAP packet on the multicast group that the
C<Net::SAP> object to bound to. The $data parameter can either be 
a C<Net::SAP::Packet> object, a C<Net::SDP> object or raw SDP data.

Passing a C<Net::SAP::Packet> object gives the greatest control 
over what is sent. Otherwise default values will be used.

If no origin_address has been set, then it is set to the IP address 
of the first network interface.

Packets greater than 1024 bytes will not be sent. This method 
returns 0 if packet was sent successfully.


=item $group = $sap->group()

Returns the address of the multicast group that the socket is bound to.


=item $sap->close()

Leave the SAP multicast group and close the socket.

=back

=head1 TODO

=over

=item add method of choosing the multicast interface to use

=item ensure that only public v4 addresses are used as origin

=item Packet decryption and validation

=item Improve test script ?

=item Move some XS functions to Net::SAP::Packet ?

=back

=head1 SEE ALSO

L<Net::SAP::Packet>, L<Net::SDP>, perl(1)

L<http://www.ietf.org/rfc/rfc2974.txt>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-net-sap@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.  I will be notified, and then you will automatically
be notified of progress on your bug as I make changes.

=head1 AUTHOR

Nicholas Humfrey, njh@ecs.soton.ac.uk

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004,2005 University of Southampton

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.005 or,
at your option, any later version of Perl 5 you may have available.

=cut
