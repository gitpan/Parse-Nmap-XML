#!/usr/bin/perl


use strict;
use Parse::Nmap::XML;
use constant TEST_FILE => 'ex_1.xml';
use File::Spec;

my $FH = shift;
$FH ||= File::Spec->catfile(File::Spec->curdir(),'examples',TEST_FILE);
$FH ||= File::Spec->catfile(File::Spec->curdir(),    TEST_FILE)  unless(-e $FH);

my $p = new Parse::Nmap::XML;

print "\nUsing file: $FH\n\n";
$p->parsefile($FH);
print "Active Hosts Scanned:\n";
for my $ip ($p->get_host_list('up')){print "\t$ip\n";}
print "\n";
print "Inactive Hosts Scanned:\n";
for my $ip ($p->get_host_list('down')){print "\t$ip\n";}


