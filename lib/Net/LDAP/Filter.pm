# Copyright (c) 1998-1999 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::Filter;

use Net::LDAP::BER;
use strict;
use vars qw($VERSION);

no strict 'subs';

$VERSION = "0.07";

sub new {
  my $self = shift;
  my $class = ref($self) || $self;
  
  my $me = bless [], $class;

  if (@_) {
    $me->parse(shift) or
      return undef;
  }
  $me;
}

my %filter_lookup = qw(
  &   FILTER_AND
  |   FILTER_OR
  !   FILTER_NOT
  =   FILTER_EQ
  =~  FILTER_APPROX
  ~=  FILTER_APPROX
  >=  FILTER_GE
  <=  FILTER_LE
  :=  FILTER_EXTENSIBLE
);

my %infix_lookup = qw(
  &   FILTER_AND
  and FILTER_AND
  AND FILTER_AND
  |   FILTER_OR
  or  FILTER_OR
  OR  FILTER_OR
  !   FILTER_NOT
  NOT FILTER_NOT
  not FILTER_NOT
);


sub parse {
  my $self   = shift;
  my $filter = shift;

  my @st = ();   # stack
  my $f = $self; # top level filter element
  my $filter_orig = $filter;

  @$f = ();

    $filter =~ s/^\s*//; 
  $filter = "(" . $filter . ")"
    unless $filter =~ /^\(/;

  while (length($filter)) {
    if ($filter =~ s/^\(\s*([&|!])\s*//) {
      my $n = [ ];  # new list to hold filter elements
      push(@$f,$filter_lookup{$1}, $n);
      push(@st,$f);  # push current list on the stack
      $f = $n;  
    }
    elsif ($filter =~ s/^\)\s*//o) {
      $f = pop @st;
    }
    elsif ($filter =~ s/^\(\s*([-;\d\w]+)=\*\)\s*//o) {
      push(@$f, FILTER_PRESENT => $1);
    }
    elsif ($filter =~ s/^\(\s*([-;.:\d\w]*[-;\d\w])\s*([:~<>]?=)\s*(([^()]|\\[()])*)\s*\)\s*//o) {
      my($attr,$op,$val) = ($1,$2,$3);
      if ($op eq ':=') {
        return # bad filter
	  unless $attr =~ /^([-;\d\w]*)(:dn)?(:([.\d]+))?/;
	my($type,$dn,$rule) = ($1,$2,$4);
        push(@$f, FILTER_EXTENSIBLE => [
			OPTIONAL => [ EXTENSIBLE_RULE => $rule ],
			OPTIONAL => [ EXTENSIBLE_TYPE => $type ],
			EXTENSIBLE_VALUE => $val,
			EXTENSIBLE_DN    => $dn
		  ]);
      }
      elsif ($op eq '=' && $val =~ /^(([^*]|\\\*)*)\*/o) {
        my $n = [];
        my $seenstar = 0;

        while ($val =~ s/^(([^*]|\\\*)*)\*//) {
          my $t = $seenstar++
                ? 'SUBSTR_ANY'
                : 'SUBSTR_INITIAL';
	  if (length $1 ) {
	    my $vv = $1;
	    $vv =~ s/\\([\da-fA-F]{2})/chr(hex($1))/sge;
            push(@$n,$t,$vv);
	  }
        }
	if (length $val) {
	  $val =~ s/\\([\da-fA-F]{2})/chr(hex($1))/sge;
          push(@$n,'SUBSTR_FINAL',$val);
	}

        push(@$f,
          FILTER_SUBSTRS => [
            STRING   => $attr,
            SEQUENCE => $n
          ]
        );
      }
      else {
	$val =~ s/\\([\da-fA-F]{2})/chr(hex($1))/sge;
        push(@$f,
          $filter_lookup{$op}, [
            STRING => $attr,
            STRING => $val
          ]
        );
      }
    }
    else {
      return; # "expecting !|& or attribute name at $filter ... "Bad filter string '$filter_orig'"
    }
    last unless @st;
  }

  return  #  " unablanced parenthisies near $filter "Bad filter string '$filter_orig'"
    if length $filter;

    $self;
  }
  
sub infix_parse {
  my $self   = shift;
  my $infix = shift;

  my @st = ();   # stack
  my $f = []; # top level filter element
  my $infix_orig = $infix;
  my $cop = '';   # current op

    my ($at, $op, $val);

  $infix = "(" . $infix . ")";
    
  while ( length($infix) ) {
    if ( $infix =~ s/^\(//o ) {  # open parenthesis
      my $n = [ ];  # new list to hold filter elements
      push(@$f, '', $n);  # fill op in when we know it
      push(@st,$f);      # push current list on the stack
      $f = $n;
      $cop = '';
    } elsif ( $infix =~ s/^\)//o ) { # close parenthesis
      $f = pop @st;
      if ( $cop eq '' )  {   # redundant ()
        if (defined $f->[1]) {
          $f = $f->[1];
        } else {  # error -- empty ()
          return;
        }
    }
    $cop = ${$st[-1]}[0] if @st;
  } elsif ( $infix =~ s/^([-;.\w:]*[^-;\w])\s*([:~<>]?=)\s*(['"]|[^() ]+)//o) {

    ($at, $op, $val) = ($1, $2, $3);
            
    if ($val eq "'" || $val eq '"' ) {  # handle quoted strings
      $infix =~ s/^([^$val]*)$val//;
      $val = $1;
      if (! defined $val) {   # error.. unmatched qoute
        return;
      }
    }
    if ($op eq '=' && $val =~ /^(([^*]|\\\*)*)\*/o) {  # match substrings
      my $n = [];
      my $seenstar = 0;

      while ($val =~ s/^(([^*]|\\\*)*)\*//) {
        my $t = $seenstar++
            ? 'SUBSTR_ANY'
            : 'SUBSTR_INITIAL';
        if (length $1) {
	  my $vv = $1;
	  $vv =~ s/\\([\da-fA-F]{2})/chr(hex($1))/sge;
          push(@$n,$t,$vv);
	}
      }
      if (length $val) {
        $val =~ s/\\([\da-fA-F]{2})/chr(hex($1))/sge;
        push(@$n,'SUBSTR_FINAL',$val)
      }

      push(@$f, 
           FILTER_SUBSTRS => [
                    STRING   => $at,
                    SEQUENCE => $n
                    ]
        );
      } else {
	$val =~ s/\\([\da-fA-F]{2})/chr(hex($1))/sge;
        push(@$f, $filter_lookup{$op}, [
                    STRING => $at,
                    STRING => $val
                        ]
                );
      }   
      if ($cop eq FILTER_NOT) {   # not is unary -- pop this element
        $f = pop @st;
        $cop = ${$st[-1]}[0];
      }
    } elsif (  $infix =~ s/^\s*(and|AND|or|OR|[|&])\s*// ) {
      ($op ) = $1;
      if (@$f == 0) {  # error .....
        print "Error -- condition must preceed $op\n";
        return;
      }
      if (($op = $infix_lookup{$op}) ne $cop ) {
        if ( $cop eq '' ) { # first element
          $cop = $op;
          ${$st[-1]}[0] = $op;
        } elsif ( $op eq FILTER_AND) { # AND has higher precedence than OR -- push on to stack
          my $n = [ ];  # new list to hold filter elements
          push (@$n, splice(@$f, -2));  
          push(@$f, FILTER_AND, $n);
          $cop = FILTER_AND;
          push(@st,$f);  # push current list on the stack
          $f = $n;  
        } else {  # lower precedence
          $f = pop @st;
          my $n = [];
          push(@$n, FILTER_OR, $f);
          push(@st, $n);
          $cop = FILTER_OR;
        }
      }  # else same op as before -- do nothing
    } elsif ( my ($op ) =  $infix =~ s/^\s*(not|NOT)\s+|\s*(!)\s*// ) {
      my $n = [ ];  # new list to hold filter elements
      push(@$f, FILTER_NOT, $n);  # fill op in when we know it
      push(@st,$f);      # push current list on the stack
      $f = $n;
      $cop = FILTER_NOT;
    } elsif ( $infix =  s/^(\w+)=\*\s*//o) {
      push(@$f, FILTER_PRESENT => $1);
    } else {   # error ....
            return;
    }
  }
  @$self = @$f;
}

sub ber {
  my $self = shift;
  my $ber = new Net::LDAP::BER();

  return # $self->associate( prior Error $ber )
    unless $ber->encode( @$self );

  $ber;
}

sub and {
  my $class = ref($_[0]) || shift;
  $class->binop('FILTER_AND' => @_);
}

sub or {
  my $class = ref($_[0]) || shift;
  $class->binop('FILTER_OR' => @_);
}

sub not {
  my $class = ref($_[0]) || shift;
  my $self = bless [ 'FILTER_NOT', shift], $class;
  $self;
}

sub equal {
  my $self = shift;
  my $class = ref($self) || $self;
  $class->cmpop('FILTER_EQ' => @_);
}

sub approx {
  my $self = shift;
  my $class = ref($self) || $self;
  $class->cmpop('FILTER_APPROX' => @_);
}

sub greater_or_equal {
  my $self = shift;
  my $class = ref($self) || $self;
  $class->cmpop('FILTER_GE' => @_);
}

sub less_or_equal {
  my $self = shift;
  my $class = ref($self) || $self;
  $class->cmpop('FILTER_LE' => @_);
}

sub binop {
  my $class = shift;
  my $op = shift;
  my $self = bless [ $op, []], $class;
  my $subop;
  foreach $subop (@_) {
    if ($subop->[0] eq $op) {
      push(@{$self->[1]}, @{$subop->[1]});
    }
    else {
      push(@{$self->[1]}, @$subop);
    }
  }
  $self;
}

sub cmpop {
  my $class = shift;
  my $op = shift;
  my $attr = shift;
  my $arg = shift;

  my $self;

  if ($arg eq '*') {
    $self = [ FILTER_PRESENT => $attr ];
  }
  elsif ($op eq 'FILTER_EQ' && $arg =~ /^(([^*]|\\\*)*)\*/o) {
    my $n = [];
    my $seenstar = 0;

    while ($arg =~ s/^(([^*]|\\\*)*)\*//) {
      my $t = $seenstar++
            ? 'SUBSTR_ANY'
            : 'SUBSTR_INITIAL';
      push(@$n,$t,$1)
        if length $1;
    }
    push(@$n,'SUBSTR_FINAL',$arg)
      if length $arg;

    $self = [
      FILTER_SUBSTRS => [
        STRING   => $attr,
        SEQUENCE => $n
      ]
    ];
  }
  else {
    $self = [
      $op, [
        STRING => $attr,
        STRING => $arg
      ]
    ];
  }

  bless $self, $class;
}

sub print {  #for debugging ...
  my $self = shift;
  no strict 'refs'; # select may return a GLOB name
  my $fh = @_ ? shift : select;

  print $fh $self->as_string,"\n";
}

sub as_string {
  my $self = shift;
  _string(@$self);
}

my %prefix = qw(
    FILTER_AND    &
    FILTER_OR     |
    FILTER_NOT    !
);

sub _string {    # prints things of the form (<op> (<list>) ... )
  my @self = @_;
  my $i;
  my $str = "";

  for ($i=0; $i <= $#self; $i+=2) {  # List of ( operator, list ... )
    if ($prefix{$self[$i]}) {  
      $str .= "( $prefix{$self[$i]}" . _string(@{$self[$i+1]}) . ")";
    } else {
      $str .= _string_infix($self[$i], $self[$i+1]);
    }
  }
  $str;
}

my %infix = qw(
    FILTER_EQ        =
    FILTER_APPROX    =~
    FILTER_GE        >=
    FILTER_LE        <=
);

sub _string_infix {    #  prints infix items of the form ( <attrib> <op> <val> )
  my ( $tag, $items) = @_;
  my $str = "";

  if ($tag eq FILTER_SUBSTRS) {
    $str = "( $items->[1] = ";
    my $substrs = $items->[3];
    my $substr;
    $str .= '*' if $substrs->[0] ne SUBSTR_INITIAL;
    for( $substr=0; $substr < $#{$substrs}; $substr += 2) {
      my $tmp = $substrs->[$substr+1];
      $tmp =~ s/([\\\(\)\*\0])/sprintf("\\%02x",ord($1))/sge;
      $str .= "$tmp";
      if ( $substrs->[$substr] ne SUBSTR_FINAL ) {
        $str .= '*' ;
      } else {
        $str .= ' '
      }
    }
    $str .= ")";
  } elsif ($tag eq FILTER_EXTENSIBLE) {
    my($rule,$type,$val,$dn) = ($items->[1][1],$items->[3][1],$items->[5],$items->[7]);
    $val =~ s/([\\\(\)\*\0])/sprintf("\\%02x",ord($1))/sge;
    $str .= "("
            . ($type ? $type : "")
	    . ($dn   ? ":dn" : "")
	    . ($rule ? ":$rule" : "")
	    . ":= $val)";
  } elsif ($tag eq FILTER_PRESENT) {
    $str .= "($items=*) ";
  }else {
    my $tmp = $items->[3];
    $tmp =~ s/([\\\(\)\*\0])/sprintf("\\%02x",ord($1))/sge;
    $str .= "($items->[1] $infix{$tag} $tmp) ";
  }
  $str;
}

1;
