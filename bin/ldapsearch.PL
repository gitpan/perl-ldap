# -*- perl -*-

use Config;
use File::Basename qw(&basename &dirname);
use Cwd;

# This forces PL files to create target in same directory as PL file.
# This is so that make depend always knows where to find PL derivatives.
my $origdir = cwd;
chdir dirname($0);
my $script = basename($0, '.PL');
$script .= '.com' if $^O eq 'VMS';

unlink($script);
open OUT, ">$script" or die "open for writing $script: $!";

print OUT <<"!GROK!THIS!";
$Config{startperl}
    eval 'exec $Config{perlpath} -S \$0 \${1+"\$@"}'
	if \$running_under_some_shell;
!GROK!THIS!

# In the following, perl variables are not expanded during extraction.

print OUT <<'!NO!SUBS!';

# Clone of umich ldapsearch program
#
# Written by Chris Ridd <c.ridd@isode.com>

use strict;
use Carp;
use Net::LDAP;
use vars qw($opt_n $opt_v $opt_t $opt_u $opt_A $opt_B $opt_L $opt_R $opt_d
	    $opt_F $opt_S $opt_f $opt_b $opt_b $opt_s $opt_a $opt_l $opt_z
	    $opt_D $opt_w $opt_h $opt_p $opt_3);
use Getopt::Std;

# Enums
my %scopes = ( 'base' => 0, 'one' => 1, 'sub' => '2' );
my %derefs = ( 'never' => 0, 'search' => 1, 'find' => 2, 'always' => 3 );

	   
#my $usage = <<EOF
#Usage: $0 [options] filter [attributes...]
#where:
#    filter      RFC-1558 compliant LDAP search filter
#    attributes  whitespace-separated list of attributes to retrieve
#                (if no attribute list is given, all are retrieved)
#options:
#    -n          show what would be done but don\'t actually search
#    -v          run in verbose mode (diagnostics to standard output)
#    -t          write values to files in /tmp
#    -u          include User Friendly entry names in the output
#    -A          retrieve attribute names only (no values)
#    -B          do not suppress printing of non-ASCII values
#    -L          print entries in LDIF format (-B is implied)
#    -R          do not automatically follow referrals
#    -d level    set LDAP debugging level to \'level\'
#    -F sep      print `sep' instead of \'=\' between attribute names and values
#    -S attr     sort the results by attribute \'attr\'
#    -f file     perform sequence of searches listed in \'file\'
#    -b basedn   base dn for search
#    -s scope    one of base, one, or sub (search scope)
#    -a deref    one of never, always, search, or find (alias dereferencing)
#    -l time lim time limit (in seconds) for search
#    -z size lim size limit (in entries) for search
#    -D binddn   bind dn
#    -w passwd   bind passwd (for simple authentication)
#    -h host     ldap server
#    -p port     port on ldap server
#    -3          connect using LDAPv3, otherwise use LDAPv2
#EOF
#  ;

die <<__USAGE__
Usage: $0 [options] filter [attributes...]
where:
    filter      RFC 2254 compliant LDAP search filter
    attributes  whitespace-separated list of attributes to retrieve
                (if no attribute list is given, all are retrieved)
options:
    -n          show what would be done but don\'t actually search
    -v          run in verbose mode (diagnostics to standard output)
*   -t          write values to files in /tmp
*   -u          include User Friendly entry names in the output
    -A          retrieve attribute names only (no values)
*   -B          do not suppress printing of non-ASCII values
    -L          print entries in LDIF format (-B is implied)
    -R          do not automatically follow referrals
    -d level    set LDAP debugging level to \'level\'
    -F sep      print `sep' instead of \'=\' between attribute names and values
*   -S attr     sort the results by attribute \'attr\'
*   -f file     perform sequence of searches listed in \'file\'
    -b basedn   base dn for search
    -s scope    one of base, one, or sub (search scope)
    -a deref    one of never, always, search, or find (alias dereferencing)
    -l time lim time limit (in seconds) for search
    -z size lim size limit (in entries) for search
    -D binddn   bind dn
    -w passwd   bind passwd (for simple authentication)
    -h host     ldap server
    -p port     port on ldap server
    -3          connect using LDAPv3, otherwise use LDAPv2
__USAGE__
  unless @ARGV;

getopts('nvtuABLRd:F:S:f:b:s:a:l:z:D:w:h:p:3');

$opt_h = 'nameflow.dante.net' unless $opt_h;
$opt_F = '=' unless $opt_F;

die "unknown scope $opt_s" if $opt_s && !defined($scopes{$opt_s});
die "unknown deref $opt_a" if $opt_a && !defined($derefs{$opt_a});

my $filter = shift || die "missing filter";

my $ldap;

# We are expecting to get back referrals from the search. Each referral may
# lead to more referrals being returned, etc etc.
#
# So we handle this by looping through a list of referrals, popping the top
# one each time, but possibly adding extra ones inside the loop.
#
# The loop body does the open, bind, search, unbind and close.
#
# The authentication offered to any particular server is not offered to any
# other server, unless the referral indicates it should. This prevents you
# revealing your password (etc) to random servers.

my $initial = "ldap://$opt_h" . ($opt_p ? ":$opt_p" : "") . "/" . mangle($opt_b);

$initial .= '?'; # No attrs
$initial .= '?'; # No scope
$initial .= '?'; # No filter
$initial .= '?bindname=' . mangle($opt_D) if $opt_D;
$initial .= '?bindpassword=' . mangle($opt_w) if $opt_w;

my @referrals = ($initial);

my $first_record = 1;

while (@referrals) {
    my $url = pop @referrals;
    my ($host,$port,$ref) = $url =~ /ldap:\/\/([^\/:]+):?(\d*)\/(.*)/i;
    my ($newbase,$newattrs,$newscope,$newfilter,@exts) = split '\?', $ref;
    my %openargs;
    my %bindargs;
    my %searchargs;
    map {
	;
      EXTENSION: {
	    /!?bindname=(.*)/ and
	      $bindargs{dn} = demangle($1), last EXTENSION;
	    /!?bindpassword=(.*)/ and
	      $bindargs{password} = demangle($1), last EXTENSION;
	}
    } @exts;

    $openargs{port} = $port if $port;
    $openargs{debug} = $opt_d if $opt_d;

    if ($opt_n || $opt_v) {
	my @t = ("'$host'");
	map { push @t, "$_ => '$openargs{$_}'"; } keys(%openargs);
	print "open(", join(", ", @t), ")\n";
    };

    unless ($opt_n) {
	$ldap = new Net::LDAP($host,
			      %openargs) or die $@;
    }

#
# Bind as the desired version, falling back if required to v2
#

    my $bind_version = ($opt_3 ? 3 : 2);

    if ($bind_version == 3) {
	if ($opt_n || $opt_v) {
	    print "bind(";
	    map { print "$_ => \'$bindargs{$_}\', " } keys(%bindargs);
	    print "version => 3)\n";
	}
	unless ($opt_n) {
	    $ldap->bind(%bindargs,
			version => 3) or $bind_version = 2;
	}
    }

    if ($bind_version == 2) {
	if ($opt_n || $opt_v) {
	    print "bind(";
	    map { print "$_ => \'$bindargs{$_}\', " } keys(%bindargs);
	    print "version => 2)\n";
	}
	unless ($opt_n) {
	    $ldap->bind(%bindargs,
			version => 2) or die $@;
	}
    }

    # Set search arguments
    $searchargs{base} = $opt_b if $opt_b;
    $searchargs{base} = demangle($newbase) if $newbase;
    $searchargs{scope} = $opt_s if $opt_s;
    $searchargs{scope} = $newscope if $newscope;
    $searchargs{scope} = $scopes{$searchargs{scope}} if $searchargs{scope};
    $searchargs{deref} = $derefs{$opt_a} if $opt_a;
    $searchargs{sizelimit} = $opt_z if $opt_z;
    $searchargs{timelimit} = $opt_l if $opt_l;
    $searchargs{typesonly} = 1 if $opt_t; # typesOnly
    $searchargs{filter} = $filter;
    $searchargs{attrs} = [ @ARGV ];

    if ($opt_n || $opt_v) {
	my @t;
	# Works poorly for attrs array
	map { push @t, "$_ => '$searchargs{$_}'"; } keys(%searchargs);
	print "search(", join(", ", @t), ")\n";
    }

    unless ($opt_n) {
	my $results = $ldap->search(%searchargs) or die $@;

	map {
	    if ($first_record) {
		print "version: 1\n" if ($opt_L);
		$first_record = 0;
	    } else {
		print "\n";
	    }
	    if ($opt_L) {
		my @t = $_->ldif;
		pop @t;
		print @t;
	    } else {
		my $entry = *$_;
		print "$$entry\n";
		my ($attr,$val);
		while (($attr,$val) = each %{$entry}) {
		    map {
			print "$attr$opt_F$_\n";
		    } @{$val};
		}
	    }
	} $results->all_entries;

	my @refs = $results->referral;
	if ($opt_v && @refs) {
	    map { print "Referral to: $_\n" } @refs;
	}
	push @referrals, @refs unless $opt_R;
	my @conts = $results->all_references;
	if ($opt_v && @conts) {
	    map { print "Continue at: $_\n" } @conts;
	}
        push @referrals, @conts unless $opt_R;
    }
    
    if ($opt_n || $opt_v) {
	print "unbind()\n";
    }
    unless ($opt_n) {
	$ldap->unbind() or die $@;
    }

#    if ($opt_n) {
#	print "destroy()\n";
#    } else {
#	$ldap->destroy() or die $@;
#    }
}

# Some routines to perform URL mangling and demangling

sub mangle($) {
    my $v = shift;
    
    $v =~ s/ /\+/g;
    $v =~ s/([,=\?])/sprintf("%%%2x",ord($1))/eig;
    return $v;
}

sub demangle($) {
    my $v = shift;

    $v =~ s/\+/ /g;
    $v =~ s/%([\dA-f]{1,2})/pack("C",hex($1))/eig;
    return $v;
}
	     
!NO!SUBS!

close OUT or die "Can't close $script: $!";
chmod 0755, $script or die "Can't reset permissions for $script: $!\n";
exec("$Config{'eunicefix'} $script") if $Config{'eunicefix'} ne ':';
chdir $origdir;
