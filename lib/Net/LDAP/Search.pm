# Copyright (c) 1998 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Search;

use strict;
use vars qw(@ISA);
use Net::LDAP::Message;
use Net::LDAP::Entry;
use Net::LDAP::Filter;

@ISA = qw(Net::LDAP::Message);

sub first_entry { # compat
  my $self = shift;
  $self->entry(0);
}

sub next_entry { # compat
  my $self = shift;
  $self->entry($self->{'CurrentEntry'} + 1);
}

sub result_tag { 'RES_SEARCH_RESULT' }

sub decode {
  my $self = shift;
  my $data = shift;

  my $seq;

  if ($data->decode(RES_SEARCH_ENTRY => \$seq)) {
    my $entry = Net::LDAP::Entry->new;
    $entry->decode($seq);
    push(@{$self->{'Entries'}}, $entry);

    $self->{Callback}->($self,$entry)
      if (defined $self->{Callback});

    return $self;
  }
  elsif ($data->decode(RES_SEARCH_REF => \$seq)) {
    my $ref = Net::LDAP::Reference->new;
    $ref->decode($seq);
    push(@{$self->{'Reference'} ||= []}, $ref->references);

    $self->{Callback}->($self,$ref)
      if (defined $self->{Callback});

    return $self;
  }
  else {
    return $self->SUPER::decode($data);
  }
}

sub entry {
  my $self = shift;
  my $index = shift || 0; # avoid undef warning and default to first entry

  my $entries = $self->{'Entries'} ||= [];
  my $ldap = $self->parent;

  # There could be multiple response to a search request
  # but only the last will set {Code}
  until (exists $self->{Code} || @{$entries} > $index) {
    return
      unless $ldap->sync($self->mesg_id);
  }

  return
    unless (@{$entries} > $index);

  $self->{'CurrentEntry'} = $index; # compat

  return $entries->[$index];
}

sub all_entries { goto &entries } # compat

sub entries {
  my $self = shift;

  return ()
    unless $self->sync;

  @{$self->{'Entries'}}
}

sub sorted {
  my $self = shift;
  my @at;

  return unless $self->sync && ref($self->{'Entries'});
  return @{$self->{'Entries'}} unless @{$self->{'Entries'}} > 1;

  if (@_) {
    my $attr = shift;

    @at = map {
      my $x = $_->attribute($attr);
      $x ? lc(join("\001",@$x)) : "";
    } @{$self->{'Entries'}};
  }
  else {
    # Sort by dn:
    @at = map {
      my $x = $_->dn;
      $x =~ s/(^|,)\s*\w+=/\001/sog;
      lc($x)
    } @{$self->{'Entries'}};
  }

  my @order = sort { $at[$a] cmp $at[$b] } 0..$#at;

  @{$self->{'Entries'}}[@order];
}

sub references {
  my $self = shift;

  return ()
    unless $self->sync;

  @{$self->{'Reference'}}
}

package Net::LDAP::Reference;

sub new {
  my $pkg = shift;
  bless [],$pkg;
}

sub decode {
  my $self = shift;
  my $ber = shift;

  $ber->decode(
    STRING => $self
  ) or return;

  $self;
}

sub references {
  my $self = shift;

  @{$self}
}


1;
