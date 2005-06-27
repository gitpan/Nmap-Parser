#!/usr/bin/perl


use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 84;
use vars qw(@PARSER @SESSION @HOST @OS @SERVICE);
use Nmap::Parser;


my $parser  = new Nmap::Parser;
my $session = new Nmap::Parser::Session;
my $host    = new Nmap::Parser::Host;
my $service = new Nmap::Parser::Host::Service;
my $os      = new Nmap::Parser::Host::OS;


isa_ok( $parser , 'Nmap::Parser');
isa_ok( $session,'Nmap::Parser::Session');
isa_ok( $host,'Nmap::Parser::Host');
isa_ok( $service,'Nmap::Parser::Host::Service');
isa_ok( $os,'Nmap::Parser::Host::OS');

for(sort @PARSER){can_ok($parser,$_);}
for(sort @SESSION){can_ok($session,$_);}
for(sort @HOST){can_ok($host,$_);}
for(sort @SERVICE){can_ok($service,$_);}
for(sort @OS){can_ok($os,$_);}



BEGIN {
    

@PARSER = qw(
all_hosts
callback
purge
del_host
get_host
get_ips
get_session
parse
parsefile
parsescan
ipv4_sort
);

@SESSION = qw(
finish_time
nmap_version
numservices
scan_args
scan_type_proto
scan_types
start_str
start_time
time_str
xml_version
);

@HOST = qw(
addr
addrtype
all_hostnames
extraports_count
extraports_state
hostname
ipidsequence_class
ipidsequence_values
ipv4_addr
ipv6_addr
mac_addr
mac_vendor
os_sig
status
tcp_closed_ports
tcp_filtered_ports
tcp_open_ports
tcp_port_count
tcp_port_state
tcp_ports
tcp_service
tcpsequence_class
tcpsequence_index
tcpsequence_values
tcptssequence_class
tcptssequence_values
udp_closed_ports
udp_filtered_ports
udp_open_ports
udp_port_count
udp_port_state
udp_ports
udp_service
uptime_lastboot
uptime_seconds
);

@SERVICE = qw(
confidence
extrainfo
method
name
owner
port
product
proto
rpcnum
tunnel
version
);

@OS = qw(
all_names
class_accuracy
class_count
name
name_accuracy
name_count
osfamily
osgen
portused_closed
portused_open
type
vendor
);
    
    
}