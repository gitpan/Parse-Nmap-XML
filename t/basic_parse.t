#!/usr/bin/perl



use strict;
use blib;
use Test::More tests => 60;
use constant TEST_FILE =>'basic.xml';
use vars qw($host $p $FH $scriptpath $scaninfo @test %test $test);
use_ok('Parse::Nmap::XML');
$scriptpath = $0;$scriptpath =~ s%[^/]+$%%;
$FH = $scriptpath.TEST_FILE;
if(! -e $FH){$FH='./test.xml';}

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

$p = new Parse::Nmap::XML;
$scaninfo = new Parse::Nmap::XML::ScanInfo;
$host = new Parse::Nmap::XML::Host;


nmap_parse_test();
nmap_parse_std_test();
nmap_parse_filter_test();
nmap_parse_host_test();
nmap_parse_scaninfo_test();
nmap_parse_end_test();


sub nmap_parse_test {
isa_ok( $p , 'Parse::Nmap::XML');
isa_ok( $scaninfo,'Parse::Nmap::XML::ScanInfo');
isa_ok( $host,'Parse::Nmap::XML::Host');
can_ok($p,@Std);
can_ok($scaninfo,@ScanInfo);
can_ok($host,@Host);
ok($p->parsefile($FH),'Parsing from nmap data: $FH');}

sub nmap_parse_end_test {
ok(!$p->clean(),'Testing clean() to clean memory');
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
is_deeply($p->get_osfamily_list(),\%test, 'Testing default get_osfamily_list');
%test = (solaris => [qw(solaris sparc sunos)],linux => [qw(linux mandrake redhat slackware)]);
is_deeply($p->set_osfamily_list(\%test),\%test, 'Testing set_osfamily_list');
is_deeply($p->get_osfamily_list(),\%test, 'Testing get_osfamily_list for premanence of structure');

ok(eq_set([$p->get_host_list()],['127.0.0.2','127.0.0.1','127.0.0.3']), 'Testing get_host_list for correct hosts from file');
ok(eq_set([$p->get_host_list('up')],['127.0.0.2','127.0.0.1']), 'Testing get_host_list for correct hosts with status = up');
ok(eq_set([$p->get_host_list('down')],['127.0.0.3']), 'Testing get_host_list for correct hosts for with status = down');

ok(eq_set([$p->filter_by_osfamily('solaris')],['127.0.0.2']),'Testing single osfamily filter');
ok(eq_set([$p->filter_by_osfamily('solaris','linux')],['127.0.0.2','127.0.0.1']), 'Testing multiple osfamily filter');

ok(eq_set([$p->filter_by_status('up')],['127.0.0.2','127.0.0.1']),'Testing status filter - up');
ok(eq_set([$p->filter_by_status('down')],['127.0.0.3']),'Testing status filter - down');
ok(eq_set([$p->filter_by_status()],['127.0.0.2','127.0.0.1']),'Testing status filter - default');

@test = sort {$a->addr() cmp $b->addr()} $p->get_host_objects();
is(scalar @test, 3,'Testing for number of host objects');

is($test[0]->addr(), '127.0.0.1','Testing for host object 1');
is($test[1]->addr(), '127.0.0.2','Testing for host object 2');
is($test[2]->addr(), '127.0.0.3','Testing for host object 3');

ok($p->del_host('127.0.0.2'),'Testing del_host');
ok(!$p->get_host('127.0.0.2'),'Testing for permanent deletion from call');
eq_set([$p->get_host_list('up')],['127.0.0.1'],'Testing for permanent deletion from list');

}

sub nmap_parse_scaninfo_test {
$scaninfo = $p->get_scaninfo();
is(ref($scaninfo), 'Parse::Nmap::XML::ScanInfo','Getting ScanInfo Object from get_scaninfo()');
is($scaninfo->num_of_services(), (1023+1023), 'Testing total number of services');
is($scaninfo->num_of_services('connect'), 1023, 'Testing number of services for CONNECT');
is($scaninfo->num_of_services('udp'),1023, 'Testing number of services for UDP');
is($scaninfo->start_time(),1057088883,'Testing scaninfo start time');
is($scaninfo->finish_time(),1057088900,'Testing scaninfo finish time');
is($scaninfo->nmap_version(),'3.27','Testing nmap version');
is($scaninfo->args(),'nmap -v -v -v -oX test.xml -O -sTUR -p 1-1023 localhost','Testing nmap arguments');
is(scalar $scaninfo->scan_types() ,2, 'Testing number of scan types');
eq_set( [$scaninfo->scan_types()], ['connect','udp'], 'Testing for correct scan types');
is($scaninfo->proto_of_scan_type('connect'), 'tcp','Testing "connect" protocol = tcp');
is($scaninfo->proto_of_scan_type('udp'), 'udp','Testing "udp" protocol = udp');
}


sub nmap_parse_host_test {
is(ref($host = $p->get_host('127.0.0.1')),'Parse::Nmap::XML::Host','Getting Host Object from get_host()');
is($host->status(), 'up', 'Testing if status = up');
is($host->addr(), '127.0.0.1', 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');
is($host->hostnames(), 1,'Testing for correct hostname count (void)');
is($host->hostnames(1), 'localhost.localdomain','Testing for correct hostname (1)');
is(scalar @{[$host->tcp_ports()]} , 6, 'Testing for tcp_ports()');
is(scalar @{[$host->udp_ports()]} , 2, 'Testing for udp_ports()');
is($host->tcp_service_name('22'), 'ssh','Testing tcp_service_name(22) = sshd');
is($host->tcp_service_name('25'), 'smtp','Testing tcp_service_name(25) = smtp');
is($host->udp_service_name('111'), 'rpcbind', 'Testing udp_service_name(111) = rpcbind');
is(scalar @{[$host->os_matches()]} , 1,'Testing os_matches()');
is(scalar $host->os_matches(),1,'Testing for correct OS');
is($host->os_matches(1), 'Linux Kernel 2.4.0 - 2.5.20','Testing for correct OS');
is($host->os_family(),'linux','Testing os_generic() = linux');
is($host->os_port_used(), '22', 'Testing os_port_used() = 22');
eq_set([$host->tcpsequence()],['random positive increments','B742FEAF,B673A3F0,B6B42D41,B6C710A1,B6F23FC4,B72FA3A8',4336320],'Testing tcpsequence class,values,index');
eq_set([$host->ipidsequence()],['All zeros','0,0,0,0,0,0'],'Testing ipidsequence class,values');
eq_set([$host->tcptssequence()],['100HZ','30299,302A5,302B1,302BD,302C9,302D5'],'Testing tcptssequence class,values');
is($host->uptime_seconds() , 1973, 'Testing uptime_seconds() : ');
is($host->uptime_lastboot() ,'Tue Jul  1 14:15:27 2003', 'Testing uptime_lastboot() : ');

}


sub nmap_parse_filter_test {


%test = (
	parse_osfamily 		=> 0,
	only_active 		=> 0,
	parse_sequences 	=> 0,
	parse_portinfo		=> 0,
	parse_uptime		=> 0
	);

is_deeply($p->parse_filters(\%test),\%test,'Testing parse filter set');

%test = (
	parse_osfamily 		=> 0,
	only_active 		=> 1,
	parse_sequences 	=> 0,
	parse_portinfo		=> 0,
	parse_uptime		=> 0
	);

is_deeply($p->parse_filters({only_active=>1}),\%test,'Testing for filter permanence');
%test = (
	parse_osfamily 		=> 1,
	only_active 		=> 0,
	parse_sequences 	=> 1,
	parse_portinfo		=> 1,
	parse_uptime		=> 1
	);

is_deeply($p->reset_filters(),\%test,'Testing reset_filters()');

}