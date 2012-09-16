#!/usr/bin/perl -w

use Socket;
use Net::LDAPS;
use Data::Dumper;

my $ldap = Net::LDAP->new($ARGV[0]);
#my $mesg = $ldap->bind(dn=>'cn=admin,o=EDV', password => 'secret');
print "====== LDAP =======\n".Dumper($ldap)."\n";

my $sock = $ldap->{net_ldap_socket};

#my $sockproto = $sock->protocol;
#print "===== sockproto =====\n".Dumper($sockproto)."\n";
#
#my $socktype = $sock->socktype;
#print "===== socktype =====\n".Dumper($socktype)."\n";
#
#my $sockdomain = $sock->sockdomain;
#print "===== sockdomain =====\n".Dumper($sockdomain)."\n";
#
my $peername = $ldap->{net_ldap_socket}->peername;
print "===== peername =====\n".Dumper($peername)."\n";

my $peeraddr = $ldap->{net_ldap_socket}->peeraddr;
print "===== peeraddr =====\n".Dumper($peeraddr)."\n";

if (Socket->can('getnameinfo') && Socket->can('getaddrinfo')) {
  my ($err,$host,$path) = Socket::getnameinfo($ldap->{net_ldap_socket}->peername, &Socket::AI_CANONNAME);
  print Dumper($err,$host,$path);
  my @addrs;

  ($err, @addrs) = Socket::getaddrinfo($host, 389, { flags => &Socket::AI_CANONNAME } )
    unless ($err);
  print Dumper(@addrs);
  map { $ldap->{net_ldap_host} = $_->{canonname}  if ($_->{canonname}) }  @addrs
    unless ($err);

  print $ldap->{net_ldap_host}."\n";
}
#my $sockname = $sock->sockname;
#print "===== sockname =====\n".Dumper($sockname)."\n";
#
#if ($sock->can('peeraddr')) {
#  my $peeraddr = $sock->peeraddr;
#  print "===== peeraddr =====\n".Dumper($peeraddr)."\n";
#
#  my @addrinfo = getaddrinfo($ldap->{net_ldap_host}, $ldap->{net_ldap_port}, { flags => AI_CANONNAME } );
#  print "===== addrinfo($ldap->{net_ldap_host}) =====\n".Dumper(\@addrinfo)."\n";
#}
#else {
#}
