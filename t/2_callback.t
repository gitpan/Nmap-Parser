#!/usr/bin/perl



use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 105;
use Nmap::Parser;
no warnings;
use constant FIRST =>  0;
use constant SECOND => 1;
use constant THIRD =>  2;
use constant HOST1 => '127.0.0.1';
use constant HOST2 => '127.0.0.2';
use constant HOST3 => '127.0.0.3';
use constant HOST4 => '127.0.0.4';
use constant HOST5 => '127.0.0.5';
use constant HOST6 => '127.0.0.6';

use constant TEST_FILE =>'nmap_results.xml';
use vars qw($p $FH @up @down $total_count $host);



$FH = File::Spec->catfile(cwd(),'t',TEST_FILE);
$FH = File::Spec->catfile(cwd(),    TEST_FILE)  unless(-e $FH);

$p = new Nmap::Parser;
isa_ok($p, 'Nmap::Parser');
ok($p->register_host_callback(\&my_callback),'Registering callback funciton');
is($p->reset_host_callback(),undef,'Reset host callback');
ok($p->register_host_callback(\&my_callback),'Registering callback funciton again');
ok($p->parsefile($FH),'Parsing from nmap data: $FH');
ok($p->parse_filters({scaninfo => 0}), 'Setting parse filter (no scaninfo)');

sub my_callback {
my $host = shift;
my $addr = $host->addr();
if($addr =~ /127\.0\.0\./){
$total_count++;}
if($host->status eq 'up'){push @up, $addr;}
elsif($host->status eq 'down'){push @down, $addr;}

if($host->addr() eq HOST1){nmap_parse_host_test_1();}
elsif($host->addr() eq HOST6){nmap_parse_host_test_6();}

}

#TESTING CALLBACK OUTPUT
ok(eq_set([@up], [HOST1,HOST2, HOST4, HOST5, HOST6]), 'Testing for correct up hosts');
ok(eq_set([@down], [HOST3]), 'Testing for correct down hosts');
is($total_count, 6, 'Testing for correct callback paramater passing');

#CHECKING FOR DELETION
my $test = $p->get_host(HOST1);
is($test , undef, 'Making sure hosts do not exists');
my @hosts = $p->get_host_objects();
is(scalar @hosts, 0 , 'Making sure objects were deleted after callback');



################################################################################
##									      ##
################################################################################
sub nmap_parse_host_test_1 {
print "\n\nTesting ".HOST1."\n";
isa_ok($host = $p->get_host(HOST1),'Nmap::Parser::Host');

#BASIC
is($host->status(), 'up', 'Testing if status = up');
is($host->addr(), HOST1, 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');
is($host->ipv4_addr(), HOST1, 'Testing to make sure IPv4 addr returned as default');
is($host->mac_addr(), '00:09:5B:3F:7D:5E' , 'Testing to make sure MAC addr returned');
is($host->mac_vendor(), 'Netgear' , 'Testing to make sure MAC vendor returned');

#HOSTNAMES
is($host->hostname(), 'localhost.localdomain','Testing basic hostname()');
is($host->hostnames(), 1,'Testing for correct hostname count (void)');
is($host->hostnames(1), 'localhost.localdomain','Testing for correct hostname (1)');

#PORTS
is($host->extraports_state(),'closed','Testing extraports_state');
is($host->extraports_count(),2038,'Testing extraports_count');

is(scalar @{[$host->tcp_ports()]} , 6, 'Testing for tcp_ports(6)');
is(scalar @{[$host->udp_ports()]} , 2, 'Testing for udp_ports(2)');

is($host->tcp_ports_count , 6, 'Testing for tcp_ports_count(6)');
is($host->udp_ports_count , 2, 'Testing for udp_ports_count(2)');


is_deeply([$host->tcp_ports()],[qw(22 25 80 111 443 631)],'Testing tcp ports found');
is_deeply([$host->udp_ports()],[qw(111 937)],'Testing udp ports found');
is_deeply([$host->tcp_ports('open')],[qw(80 111 443 631)],'Testing tcp ports "open"');
is_deeply([$host->tcp_ports('filtered')],[qw(22 25)],'Testing tcp ports "filtered"');
is_deeply([$host->udp_ports('open')],[qw(111)],'Testing udp ports "open"');
is_deeply([$host->udp_ports('closed')],[qw(937)],'Testing udp ports "closed"');



is($host->tcp_port_state('22'),'filtered','Testing tcp_ports(port_number) filtered');
is($host->udp_port_state('111'),'open','Testing udp_ports(port_number) open');
is($host->udp_port_state('9999'),'closed','Testing udp_ports(port_number) closed');



#TCP AND UDP SERVICE NAMES
is($host->tcp_service_name('22'), 'ssh','Testing tcp_service_name(22) = sshd');
is($host->tcp_service_name('25'), 'smtp','Testing tcp_service_name(25) = smtp');
is($host->udp_service_name('111'), 'rpcbind', 'Testing udp_service_name(111) = rpcbind');
#TEST tcp_service_proto,udp_service_proto,tcp_service_rpcnum,udp_service_rpcnum
is($host->tcp_service_proto('111'), 'rpc','Testing tcp_service_name(25) = smtp');

is($host->udp_service_proto('111'), 'rpc', 'Testing udp_service_proto(111)');
is($host->tcp_service_rpcnum('111'), 100000,'Testing tcp_service_rpcnum(111)');
is($host->udp_service_rpcnum('111'), 100000, 'Testing udp_service_rpcnum(111)');

#OS MATCHES
is(scalar @{[$host->os_matches()]} , 1,'Testing os_matches()');
is(scalar $host->os_matches(),1,'Testing for correct OS');
is($host->os_match, 'Linux Kernel 2.4.0 - 2.5.20','Testing os_match');
is($host->os_matches(1), 'Linux Kernel 2.4.0 - 2.5.20','Testing os_matches(1)');

#OS CLASS
is_deeply([$host->os_class(1)],['Linux','2.4.x','Linux','general purpose','100'],'Testing os_class() with arg 1');
is_deeply([$host->os_class(2)],['Solaris','8','Sun','general purpose','100'],'Testing os_class() with 2');
is($host->os_class(),2,'Testing total count of os_class tags');

#OSFAMILY
is($host->os_family(),'linux','Testing os_family() = linux');

#OS PORT USED
is($host->os_port_used(), 22, 'Testing os_port_used() with no arguments');
is($host->os_port_used('open'), 22, 'Testing os_port_used() using "open"');
is($host->os_port_used('closed'), 1, 'Testing os_port_used() using "closed"');

#SEQUENCES
is_deeply([$host->tcpsequence_class(), $host->tcpsequence_values(), $host->tcpsequence_index()],
          ['random positive increments','B742FEAF,B673A3F0,B6B42D41,B6C710A1,B6F23FC4,B72FA3A8',4336320],
          'Testing tcpsequence class,values,index');
is_deeply([$host->ipidsequence_class(),$host->ipidsequence_values()],['All zeros','0,0,0,0,0,0'],'Testing ipidsequence class,values');
is_deeply([$host->tcptssequence_class(), $host->tcptssequence_values()],['100HZ','30299,302A5,302B1,302BD,302C9,302D5'],'Testing tcptssequence class,values');

#UPTIME
is($host->uptime_seconds() , 1973, 'Testing uptime_seconds()');
is($host->uptime_lastboot() ,'Tue Jul  1 14:15:27 2003', 'Testing uptime_lastboot()');

}



################################################################################
##									      ##
################################################################################
sub nmap_parse_host_test_6 {
print "\n\nTesting ".HOST6."\n";
isa_ok($host = $p->get_host(HOST6),'Nmap::Parser::Host');

#BASIC
is($host->status(), 'up', 'Testing if status = up');
is($host->addr(), HOST6, 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');
is($host->hostname(), 'host7.net', 'Testing hostname');

is($host->tcp_service_extrainfo(111),'rpc #100000','Testing service info 111');
is($host->tcp_service_extrainfo(22),'protocol 1.99','Testing service info 22');
is($host->tcp_service_extrainfo(443),'(Red Hat Linux)','Testing service info 443');
is($host->tcp_service_extrainfo(6000),'access denied','Testing service info 6000');
is($host->tcp_service_extrainfo(80),'(Red Hat Linux)','Testing service info 80');

is($host->tcp_service_version(111),2,'Testing service name 111');
is($host->tcp_service_version(22),'3.5p1','Testing tcp service version 443');
is($host->tcp_service_version(443),'2.0.40','Testing tcp service version 443');
is($host->tcp_service_version(80),'2.0.40','Testing tcp service version 80');
is($host->tcp_service_version(6000),undef,'Testing tcp service version 6000');


is($host->tcp_service_product(22),'OpenSSH','Testing tcp service product: 22');
is($host->tcp_service_product(80),'Apache httpd','Testing tcp service product: 80');
is($host->tcp_service_product(443),'Apache httpd','Testing tcp service product: 443');


#OS MATCHES
is(scalar @{[$host->os_matches()]} , 9,'Testing os_matches()');
is(scalar $host->os_matches(),9,'Testing for correct OS');
is($host->os_matches(1), $host->os_match(),'Testing for correct OS 1');
is($host->os_matches(1), 'Redback SMS 1800/10000 router or Thomson TMC 390 cable modem','Testing for correct OS 1');
is($host->os_matches(2), 'Redback SMS 1800 router','Testing for correct OS 2');
is($host->os_matches(3), 'Fore ForeThought 7.1.0 ATM switch','Testing for correct OS 3');
is($host->os_matches(4), 'Xerox Docuprint N2125 network printer','Testing for correct OS 4');
is($host->os_matches(5), 'Redback SMS 1000-2000 DSL Router','Testing for correct OS 5');
is($host->os_matches(6), 'SonicWall SOHO firewall, Enterasys Matrix E1, or Accelerated Networks VoDSL, or Cisco 360 Access Point','Testing for correct OS 6');
is($host->os_matches(7), 'Alcatel 1000 DSL Router','Testing for correct OS 7');
is($host->os_matches(8), 'Sun RSC (Remote System Control card) v1.14 (in Solaris 2.7)','Testing for correct OS 8');
is($host->os_matches(9), 'Cisco 11151/Arrowpoint 150 load balancer, Neoware (was HDS) NetOS V. 2.0.1 or HP ENTRIA C3230A','Testing for correct OS 9');


#OS CLASS
is_deeply([$host->os_class(1) ],['AOS','','Redback','router','97'],'Testing os_class(1)');
is_deeply([$host->os_class(15)],['embedded','','3Com','WAP','88'],'Testing os_class(15)');

is($host->os_osfamily(1),'AOS','Testing os_osfamily');
is($host->os_vendor(1),'Redback','Testing os_vendor');
is($host->os_gen(1),undef,'Testing os_gen');
is($host->os_type(1),'router','Testing os_type');

is($host->os_osfamily(15),'embedded','Testing os_osfamily');
is($host->os_vendor(15),'3Com','Testing os_vendor');
is($host->os_gen(15),undef,'Testing os_gen');
is($host->os_type(15),'WAP','Testing os_type');


is($host->os_osfamily(20),'OpenBSD','Testing os_osfamily');
is($host->os_vendor(20),'OpenBSD','Testing os_vendor');
is($host->os_gen(20),'2.X','Testing os_gen');
is($host->os_type(20),'general purpose','Testing os_type');

is($host->os_class(),36,'Testing total count of os_class tags');

#OSFAMILY
is($host->os_family(),'solaris,switch','Testing os_family() = solaris,switch');

}