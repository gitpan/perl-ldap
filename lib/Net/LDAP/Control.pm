# Copyright (c) 1997-8 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control;

use Net::LDAP::Constant qw(/^LDAP_CONTROL/);

$VERSION = "0.01";

my %Registry = (
  LDAP_CONTROL_SORTREQUEST, 'Net::LDAP::Control::sort',

  #LDAP_CONTROL_MANAGEDSAIT      
  #LDAP_CONTROL_SORTRESPONSE     
  #LDAP_CONTROL_PERSISTENTSEARCH 
  #LDAP_CONTROL_ENTRYCHANGE      
  #LDAP_CONTROL_VLVREQUEST       
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

  $args{'type'} ||= $oid || $Registry_r{$pkg};

  if ($pkg eq __PACKAGE__ && exists $Registry{$args{'type'}}) {
    $pkg = $Registry{$args{'type'}};
    eval "require ${pkg}";
  }

  my $obj = bless \%args, $pkg;
  
  $obj->init;

  $obj;
}

sub init {}

sub decode {
  my($class,$data) = @_;
  my $self = bless {}, $class;

  Net::LDAP::BER->new($data)->decode(
    SEQUENCE => [
      STRING   => \($self->{'type'}),
      OPTIONAL => [
        BOOLEAN  => \($self->{'critical'}),
      ],
      OPTIONAL => [
        STRING => sub { \($self->{'value'}) }
      ],
    ]
  ) or return undef;

  bless $self, $Resgistry{$self->{'type'}}
    if (exists $Resgistry{$self->{'type'}});
  
  $self;
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
