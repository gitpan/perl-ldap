#!perl

BEGIN {
  eval {
    require URI::URL;
    $pkg = "URI::URL";
  }
  or eval {
    require URI;
    $pkg = "URI";
  }
  or do {
    print "1..0\n";
    exit;
  };
}

print "1..5\n";

use URI::ldap;

$url = $pkg->new("ldap://host/dn=base?cn,sn?sub?objectClass=*");

print "not " unless $url->host eq "host";
print "ok 1\n";

print "not " unless $url->dn eq "dn=base";
print "ok 2\n";

print "not " unless join("-",$url->attributes) eq "cn-sn";
print "ok 3\n";

print "not " unless $url->scope eq "sub";
print "ok 4\n";

print "not " unless $url->filter eq "objectClass=*";
print "ok 5\n";

