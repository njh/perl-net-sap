
use strict;
use Test;


# use a BEGIN block so we print our plan before Net::SAP is loaded
BEGIN { plan tests => 3 }

# load Net::SAP
use Net::SAP;


# Helpful notes.  All note-lines must start with a "#".
print "# I'm testing Net::SAP version $Net::SAP::VERSION\n";

# Module has loaded sucessfully 
ok(1);



# Now try creating a new Net::SAP object
my $sap = Net::SAP->new('ipv4');

ok( $sap );



# Close the socket
$sap->close();

ok(1);


exit;

