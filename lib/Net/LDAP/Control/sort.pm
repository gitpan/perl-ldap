# Copyright (c) 1997-8 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::sort;

require Net::LDAP::BER;

@ISA = qw(Net::LDAP::Control);

sub init {
  my($self,$args) = @_;
  my $sort = delete $self->{'sort'};
  my @sort = ();

  if ($sort) {
    $sort = [ split(/\s+/, $sort) ]
      unless ref($sort);

    @sort = map {
      /^(-?)([^:]+)(?::(.+))?/;
      [ $2, $3, $1 eq '-' ? 1 : undef]
    } @$sort;

  }

  $self->{'sort'} = \@sort;
  $self->value;
  1;
}

sub value {
  my $self = shift;
  
  my $ber = Net::LDAP::BER->new(
      SEQUENCE_OF => [ $self->{'sort'},
    SEQUENCE => [
        STRING => sub { $_[0]->[0] },
	OPTIONAL => [
	  SSS_MATCHRULE => sub { $_[0]->[1] }
	],
	OPTIONAL => [
	  SSS_REVERSE => sub { $_[0]->[2] }
	],
      ]
    ]
  ) or die $Convert::BER::ERROR;
  $self->{'value'} = $ber->buffer;
}

1;
