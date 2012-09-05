#!/usr/bin/perl -w

use Net::LDAP;

my $ldap = Net::LDAP->new('ldapi://', debug => 15)  or  die "$@";
my $mesg = $ldap->start_tls(verify => 'require',
			    sslserver => 'localhost',
			    cafile => '/etc/ssl/certs/ADPM-cacert.pem');
die $mesg->error  if ($mesg->code);

# EOF
