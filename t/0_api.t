#!/usr/bin/perl

use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 86;
use vars qw($host $p $FH $scaninfo @test %test $test);
use_ok('Nmap::Parser');
no warnings;
$p = new Nmap::Parser;
$scaninfo = new Nmap::Parser::ScanInfo;
$host = new Nmap::Parser::Host;

my @ScanInfo = qw(
args
finish_time
nmap_version
num_of_services
proto_of_scan_type
scan_types
start_time
xml_version
start_str
time_str
);

my @Host = qw(
addr
ipv4_addr
mac_addr
mac_vendor
addrtype
extraports_count
extraports_state
hostname
hostnames
ipidsequence_class
ipidsequence_values
os_accuracy
os_class
os_family
os_gen
os_match
os_matches
os_osfamily
os_port_used
os_type
os_vendor
status
tcp_port_state
tcp_ports
tcp_ports_count
tcp_service_confidence
tcp_service_extrainfo
tcp_service_method
tcp_service_name
tcp_service_owner
tcp_service_product
tcp_service_proto
tcp_service_rpcnum
tcp_service_tunnel
tcp_service_version
tcpsequence_class
tcpsequence_index
tcpsequence_values
tcptssequence_class
tcptssequence_values
udp_port_state
udp_ports
udp_ports_count
udp_service_confidence
udp_service_extrainfo
udp_service_method
udp_service_name
udp_service_owner
udp_service_product
udp_service_proto
udp_service_rpcnum
udp_service_tunnel
udp_service_version
uptime_lastboot
uptime_seconds
);

my @Std = qw(
clean
del_host
filter_by_osfamily
filter_by_status
get_host
get_host_list
get_host_objects
get_osfamily_list
get_scaninfo
parse
parse_filters
parsefile
parsescan
register_host_callback
reset_host_callback
set_osfamily_list
sort_ips
);


isa_ok( $p , 'Nmap::Parser');
isa_ok( $scaninfo,'Nmap::Parser::ScanInfo');
isa_ok( $host,'Nmap::Parser::Host');
for(sort @Std){can_ok($p,$_);}
for(sort @ScanInfo){can_ok($scaninfo,$_);}
for(sort @Host){can_ok($host,$_);}
