#!/usr/bin/perl



use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More;
use Parse::Nmap::XML;
use vars qw($t1 $t2);
use constant COUNT => 10;
$|=1;

eval {require Time::HiRes;};

if($@){plan skip_all => 'Time::HiRes not installed for performance tests';}
else {plan tests => 5;}
use constant TEST_FILE =>'basic.xml';
use vars qw($host $p $FH $scaninfo @test %test $test);

$FH = File::Spec->catfile(cwd(),'t',TEST_FILE);
$FH = File::Spec->catfile(cwd(),    TEST_FILE)  unless(-e $FH);
$p = new Parse::Nmap::XML;


#BENCHMARK WITH NO FILTERS
$t1 = [Time::HiRes::gettimeofday()];
$p->parsefile($FH) for(0..COUNT);
$t1 = Time::HiRes::tv_interval($t1,[Time::HiRes::gettimeofday()]);

#TESTING OF INFORMATION
is($p->get_scaninfo()->num_of_services(), '2046','Testing full tag');
is($p->get_scaninfo()->nmap_version(), '3.27','Testing start tag');

#SET UP FOR FILTERS
$p->clean();
$p->parse_filters({portinfo => 0,scaninfo => 0,uptime => 0});

#BENCHMARK WITH FILTERS
$t2 = [Time::HiRes::gettimeofday()];
$p->parsefile($FH) for(0..COUNT);
$t2 = Time::HiRes::tv_interval($t2,[Time::HiRes::gettimeofday()]);

#TESTING OF INFORMATION
is($p->get_scaninfo(),undef,'Testing start tag /w filters');
is($p->get_scaninfo(),undef,'Testing full tag /w filters');
SKIP:
{
skip 'No performance improvement from filters',1 if($t1 == $t2 || $t2 == 0);
ok($t1 > $t2 || $t1 == $t2,"Improvement Ratio: ".int(($t1-$t2)/($t2))." times faster");
 print STDERR "\tFilter Improvement Ratio: ".int(($t1-$t2)/($t2))." times faster\n";
}
