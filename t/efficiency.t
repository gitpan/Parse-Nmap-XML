#!/usr/bin/perl



use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 5;
use Parse::Nmap::XML;
use vars qw($t1 $t2);
use constant COUNT => 1;

use Time::HiRes qw(gettimeofday tv_interval);

use constant TEST_FILE =>'basic.xml';
use vars qw($host $p $FH $scaninfo @test %test $test);

$FH = File::Spec->catfile(cwd(),'t',TEST_FILE);
$FH = File::Spec->catfile(cwd(),    TEST_FILE)  unless(-e $FH);
$p = new Parse::Nmap::XML;


#BENCHMARK WITH NO FILTERS
$t1 = [gettimeofday];
$p->parsefile($FH);
$t1 = tv_interval($t1,[gettimeofday]);

#TESTING OF INFORMATION
is($p->get_scaninfo()->num_of_services(), '2046','Testing full tag');
is($p->get_scaninfo()->nmap_version(), '3.27','Testing start tag');

#SET UP FOR FILTERS
$p->clean();
$p->parse_filters({portinfo => 0,scaninfo => 0,uptime => 0});

#BENCHMARK WITH FILTERS
$t2 = [gettimeofday];
$p->parsefile($FH);
$t2 = tv_interval($t2,[gettimeofday]);

#TESTING OF INFORMATION
is($p->get_scaninfo(),undef,'Testing start tag /w filters');
is($p->get_scaninfo(),undef,'Testing full tag /w filters');

ok($t1 > $t2,"Percent Improvement: ".int($t1/$t2)."%");