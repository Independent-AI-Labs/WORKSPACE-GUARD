#!/usr/bin/env perl
use strict;
use warnings;

my ($user, $password) = @ARGV;
defined $user && defined $password or exit 1;
getpwnam($user) or exit 1;

my $hash = "";
open my $fh, '<', '/etc/shadow' or exit 1;
while (<$fh>) {
    chomp;
    my ($name, $candidate) = split /:/, $_, 3;
    if (defined $candidate && $name eq $user) {
        $hash = $candidate;
        last;
    }
}
close $fh;
exit 1 if !$hash || $hash =~ /^[!*]+$/;
exit((crypt($password, $hash) eq $hash) ? 0 : 1);
