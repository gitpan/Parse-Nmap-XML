#!/usr/bin/perl

use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 7;
use vars qw($host $p $FH $scaninfo @test %test $test);
use_ok('Parse::Nmap::XML');

$p = new Parse::Nmap::XML;
$scaninfo = new Parse::Nmap::XML::ScanInfo;
$host = new Parse::Nmap::XML::Host;

my @ScanInfo = qw(
num_of_services start_time finish_time nmap_version args scan_types
proto_of_scan_type
);

my @Host = qw(
uptime_lastboot uptime_seconds os_family os_port_used os_matches udp_service_name
tcp_service_name udp_ports tcp_ports hostnames addrtype addr status
);

my @Std = qw(
clean get_host_list get_host del_host get_host_objects filter_by_osfamily
filter_by_status get_scaninfo safe_parse safe_parsefile parse parsefile parse_filters
get_osfamily_list set_osfamily_list
);


isa_ok( $p , 'Parse::Nmap::XML');
isa_ok( $scaninfo,'Parse::Nmap::XML::ScanInfo');
isa_ok( $host,'Parse::Nmap::XML::Host');
can_ok($p,@Std);
can_ok($scaninfo,@ScanInfo);
can_ok($host,@Host);
