# Copyright (c) 1999-2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control;

use Net::LDAP::Constant qw(/^LDAP_CONTROL/);

$VERSION = "0.01";

my %Registry = (
  LDAP_CONTROL_SORTREQUEST, 'Net::LDAP::Control::sort',
  LDAP_CONTROL_VLVREQUEST,  'Net::LDAP::Control::vlvrequest',

  #LDAP_CONTROL_MANAGEDSAIT      
  #LDAP_CONTROL_SORTRESPONSE     
  #LDAP_CONTROL_PERSISTENTSEARCH 
  #LDAP_CONTROL_ENTRYCHANGE      
  #LDAP_CONTROL_VLVRESPONSE      
  #
  #LDAP_CONTROL_PWEXPIRED        
  #LDAP_CONTROL_PWEXPIRING       
  #
  #LDAP_CONTROL_REFERRALS        
);

my %Registry_r = reverse %Registry;

sub register {
  my($class,$oid) = @_;
  $Registry{$oid} = $class;
  $Registry_r{$class} = $oid;
}

sub new {
  my $self = shift;
  my $pkg  = ref($self) || $self;
  my $oid = shift if @_ & 1;
  my %args = @_;

  $args{'type'} ||= $oid || $Registry_r{$pkg} || '';

  unless ($args{'type'} =~ /^\d+(?:\.\d+)+$/) {
    $args{'error'} = 'Invalid OID';
    return bless \%args;
  }

  if ($pkg eq __PACKAGE__ && exists $Registry{$args{'type'}}) {
    $pkg = $Registry{$args{'type'}};
    eval "require ${pkg}";
  }

  my $obj = bless \%args, $pkg;
  
  $obj->init;
}

sub error { shift->{'error'} }
sub valid { ! exists shift->{'error'} }

sub init { shift }

sub decode {
  my($class,$data) = @_;
  my %hash;

  ( ref($data)
    ? $data
    : Net::LDAP::BER->new($data)
  )->decode(
    SEQUENCE => [
      STRING   => \($hash{'type'}),
      OPTIONAL => [
        BOOLEAN  => \($hash{'critical'}),
      ],
      OPTIONAL => [
        STRING => sub { \($hash{'value'}) }
      ],
    ]
  ) or return undef;

  $class = $Resgistry{$self->{'type'}}
    if ($class eq __PACKAGE__ && exists $Resgistry{$self->{'type'}});
  
  bless \%hash, $class;
}

sub type     { shift->{'type'} }
sub critical { shift->{'critical'} || 0 }
sub value    { shift->{'value'} || undef }

sub encode {
  my $self = shift;
  Net::LDAP::BER->new(
    SEQUENCE => [
      STRING   => $self->{'type'},
      OPTIONAL => [
        BOOLEAN  => $self->{'critical'},
      ],
      OPTIONAL => [
        STRING => $self->value
      ],
    ]
  );
}

1;
