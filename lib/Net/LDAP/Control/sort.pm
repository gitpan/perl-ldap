# Copyright (c) 1999-2000 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Control::sort;

require Net::LDAP::BER;

@ISA = qw(Net::LDAP::Control);

sub init {
  my($self) = @_;

  $self->sort($self->{'sort'} || []);

  $self;
}

sub sort {
  my $self = shift;

  if (@_) {
    # @_ can either be a list, or a single item.
    # if a single item it can be a string, which needs
    # to be split on spaces, or a reference to a list
    #
    # Each element has three parts
    #  leading - (optional)
    #  an attribute name
    #  :match-rule (optional)

    my @sort = map {
      /^(-?)([^:]+)(?::(.+))?/;
      [ $2, $3, $1 eq '-' ? 1 : undef]
    } (@_ == 1 ? (ref($_[0]) ? @{$_[0]} : split(/\s+/, $_[0])) : @_)

    $self->{'sort'} = \@sort;
    $self->value; # encode it
  }

  return @{$self->{'sort'} || []};
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
