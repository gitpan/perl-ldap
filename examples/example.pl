#!/usr/local/bin/nperl

use lib '.';
use blib qw(../ber);
use Net::LDAP;
use IO::Select;

#ldap.switchboard.com
#ldap.whowhere.com
#ldap.infospace.com
#ldap.four11.com
#ldap.bigfoot.com

$ldap = Net::LDAP->new('ldap.switchboard.com',
		DN => "",
		Password => "",
		Port => 389,
		Debug => 3,
	) or
	die $@;

for $filter (
	'(sn=Barr)',
	'(!(cn=Tim Howes))',
	'(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))',
	'(o=univ*of*mich*)',
	) {

    print "*" x 72,"\n",$filter,"\n","*" x 72,"\n";

    $mesg = $ldap->search(
		base   => "c=US",
		filter => $filter
    ) or die $@;

    map { $_->dump } $mesg->all_entries;

}
