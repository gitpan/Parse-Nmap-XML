#!/usr/bin/perl



use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 63;
use Parse::Nmap::XML;
use constant FIRST => 0;
use constant SECOND => 1;
use constant THIRD => 2;
use constant HOST1 => '127.0.0.1';
use constant HOST2 => '127.0.0.2';
use constant HOST3 => '127.0.0.3';

use constant TEST_FILE =>'basic.xml';
use vars qw($host $p $FH $scaninfo @test %test $test);



$FH = File::Spec->catfile(cwd(),'t',TEST_FILE);
$FH = File::Spec->catfile(cwd(),    TEST_FILE)  unless(-e $FH);

$p = new Parse::Nmap::XML;

nmap_parse_filter_test();
nmap_parse_test();
nmap_parse_std_test();
nmap_parse_scaninfo_test();
nmap_parse_host_test();
nmap_parse_end_test();


sub nmap_parse_test {ok($p->parsefile($FH),'Parsing from nmap data: $FH');}

sub nmap_parse_end_test {
ok($p->clean(),'Testing clean() to clean memory');
ok(!$p->get_scaninfo(),'Testing clean() against scaninfo');
is(scalar $p->get_host_list(),0,'Testing clean() against host list');

}

sub nmap_parse_std_test {


%test = (solaris => [qw(solaris sparc sunos)],
            linux => [qw(linux mandrake redhat slackware)],
            unix => [qw(unix hp-ux hpux bsd immunix aix)],
            win  => [qw(win microsoft)],
	    mac => [qw(mac osx)],
	    switch => [qw(ethernet cisco netscout router switch)],
	    );

#OSFAMILY LIST
is_deeply($p->get_osfamily_list(),\%test, 'Testing default get_osfamily_list');
%test = (solaris => [qw(solaris sparc sunos)],linux => [qw(linux mandrake redhat slackware)]);
is_deeply($p->set_osfamily_list(\%test),\%test, 'Testing set_osfamily_list');
is_deeply($p->get_osfamily_list(),\%test, 'Testing get_osfamily_list for premanence of structure');

#GET HOST LIST
ok(eq_set([$p->get_host_list()],[HOST2,HOST1,HOST3]), 'Testing get_host_list for correct hosts from file');
ok(eq_set([$p->get_host_list('up')],[HOST2,HOST1]), 'Testing get_host_list for correct hosts with status = up');
ok(eq_set([$p->get_host_list('down')],[HOST3]), 'Testing get_host_list for correct hosts for with status = down');

#FILTER BY OSFAMILY
ok(eq_set([$p->filter_by_osfamily('solaris')],[HOST2]),'Testing single osfamily filter');
ok(eq_set([$p->filter_by_osfamily('solaris','linux')],[HOST2,HOST1]), 'Testing multiple osfamily filter');

#FILTER BY STATUS
ok(eq_set([$p->filter_by_status('up')],[HOST2,HOST1]),'Testing status filter - up');
ok(eq_set([$p->filter_by_status('down')],[HOST3]),'Testing status filter - down');
ok(eq_set([$p->filter_by_status()],[HOST2,HOST1]),'Testing status filter - default');

@test = sort {$a->addr() cmp $b->addr()} $p->get_host_objects();
is(scalar @test, 3,'Testing for number of host objects');

#ADDR TEST
is($test[FIRST]->addr(), HOST1,'Testing for host object 1');
is($test[SECOND]->addr(), HOST2,'Testing for host object 2');
is($test[THIRD]->addr(), HOST3,'Testing for host object 3');

ok($p->del_host(HOST2),'Testing del_host');
ok(!$p->get_host(HOST2),'Testing for permanent deletion from call');
ok(eq_set([$p->get_host_list('up')],[HOST1]),'Testing for permanent deletion from list');

}

sub nmap_parse_scaninfo_test {
isa_ok($scaninfo = $p->get_scaninfo(), 'Parse::Nmap::XML::ScanInfo');

#BASIC
is($scaninfo->nmap_version(),'3.27','Testing nmap version');
is($scaninfo->args(),'nmap -v -v -v -oX test.xml -O -sTUR -p 1-1023 localhost','Testing nmap arguments');

#NUM OF SERVICES
is($scaninfo->num_of_services(), (1023+1023), 'Testing total number of services');
is($scaninfo->num_of_services('connect'), 1023, 'Testing number of services for CONNECT');
is($scaninfo->num_of_services('udp'),1023, 'Testing number of services for UDP');

#SCAN TIME
is($scaninfo->start_time(),1057088883,'Testing scaninfo start time');
is($scaninfo->finish_time(),1057088900,'Testing scaninfo finish time');

#SCAN TYPES
is(scalar $scaninfo->scan_types() ,2, 'Testing number of scan types');
ok(eq_set( [$scaninfo->scan_types()], ['connect','udp']), 'Testing for correct scan types');

#PROTO OF SCAN TYPE
is($scaninfo->proto_of_scan_type('connect'), 'tcp','Testing "connect" protocol = tcp');
is($scaninfo->proto_of_scan_type('udp'), 'udp','Testing "udp" protocol = udp');
}


sub nmap_parse_host_test {
isa_ok($host = $p->get_host(HOST1),'Parse::Nmap::XML::Host');

#BASIC
is($host->status(), 'up', 'Testing if status = up');
is($host->addr(), HOST1, 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');

#HOSTNAMES
is($host->hostnames(), 1,'Testing for correct hostname count (void)');
is($host->hostnames(1), 'localhost.localdomain','Testing for correct hostname (1)');

#PORTS
is(scalar @{[$host->tcp_ports()]} , 6, 'Testing for tcp_ports()');
is(scalar @{[$host->udp_ports()]} , 2, 'Testing for udp_ports()');

#TCP AND UDP SERVICE NAMES
is($host->tcp_service_name('22'), 'ssh','Testing tcp_service_name(22) = sshd');
is($host->tcp_service_name('25'), 'smtp','Testing tcp_service_name(25) = smtp');
is($host->udp_service_name('111'), 'rpcbind', 'Testing udp_service_name(111) = rpcbind');

#OS MATCHES
is(scalar @{[$host->os_matches()]} , 1,'Testing os_matches()');
is(scalar $host->os_matches(),1,'Testing for correct OS');
is($host->os_matches(1), 'Linux Kernel 2.4.0 - 2.5.20','Testing for correct OS');

#OS CLASS
is_deeply([$host->os_class() ],['Linux','2.4.x','general purpose'],'Testing os_class() with no args');
is_deeply([$host->os_class(1)],['Linux','2.4.x','general purpose'],'Testing os_class() with arg 1');
is_deeply([$host->os_class(2)],['Linux','2.5.x','general purpose'],'Testing os_class() with arg 2');

#OSFAMILY
is($host->os_family(),'linux','Testing os_generic() = linux');

#OS PORT USED
is($host->os_port_used(), 22, 'Testing os_port_used() with no arguments');
is($host->os_port_used('open'), 22, 'Testing os_port_used() using "open"');
is($host->os_port_used('closed'), 1, 'Testing os_port_used() using "closed"');

#SEQUENCES
is_deeply([$host->tcpsequence()],['random positive increments','B742FEAF,B673A3F0,B6B42D41,B6C710A1,B6F23FC4,B72FA3A8',4336320],'Testing tcpsequence class,values,index');
is_deeply([$host->ipidsequence()],['All zeros','0,0,0,0,0,0'],'Testing ipidsequence class,values');
is_deeply([$host->tcptssequence()],['100HZ','30299,302A5,302B1,302BD,302C9,302D5'],'Testing tcptssequence class,values');

#UPTIME
is($host->uptime_seconds() , 1973, 'Testing uptime_seconds() : ');
is($host->uptime_lastboot() ,'Tue Jul  1 14:15:27 2003', 'Testing uptime_lastboot() : ');

}


sub nmap_parse_filter_test {


%test = (
	osfamily	=> 0,
	scaninfo	=> 0,
	only_active	=> 0,
	sequences 	=> 0,
	portinfo	=> 0,
	uptime		=> 0
	);

is_deeply($p->parse_filters(\%test),\%test,'Testing parse filter set');

%test = (
	osfamily 	=> 0,
	scaninfo	=> 1,
	only_active	=> 1,
	sequences 	=> 0,
	portinfo	=> 0,
	uptime		=> 0
	);

is_deeply($p->parse_filters({only_active=>1,scaninfo=>1}),\%test,'Testing for filter permanence');
%test = (
	osfamily 	=> 1,
	scaninfo	=> 1,
	only_active	=> 0,
	sequences 	=> 1,
	portinfo	=> 1,
	uptime		=> 1
	);

is_deeply($p->reset_filters(),\%test,'Testing reset_filters()');

}
