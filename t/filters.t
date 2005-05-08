#!/usr/bin/perl



use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More;
use Nmap::Parser;
no warnings;
use constant HOST1 => '127.0.0.1';
use constant HOST2 => '127.0.0.2';
use constant HOST3 => '127.0.0.3';
use constant HOST4 => '127.0.0.4';
use constant HOST5 => '127.0.0.5';
use constant HOST6 => '127.0.0.6';
use vars qw($t1 $t2);
use constant COUNT =>2 ;
$|=1;

eval {require Time::HiRes;};

if($@){plan skip_all => 'Time::HiRes not installed for performance tests';}
else {plan tests => 9;}
use constant TEST_FILE =>'nmap_results.xml';
use vars qw($host $p $FH $scaninfo @test %test $test);

$FH = File::Spec->catfile(cwd(),'t',TEST_FILE);
$FH = File::Spec->catfile(cwd(),    TEST_FILE)  unless(-e $FH);
$p = new Nmap::Parser;


#BENCHMARK WITH NO FILTERS
$t1 = [Time::HiRes::gettimeofday()];
$p->parsefile($FH) for(0..COUNT);
$t1 = Time::HiRes::tv_interval($t1,[Time::HiRes::gettimeofday()]);

#TESTING OF INFORMATION
is($p->get_scaninfo()->num_of_services(), '2046','Testing full tag');
is($p->get_scaninfo()->nmap_version(), '3.27','Testing start tag');
is($p->get_host(HOST1)->hostname, 'localhost.localdomain','Testing hostname tag');
isnt($p->get_host(HOST1)->tcp_port_state('111'),undef,'Testing ports no filters');
#SET UP FOR FILTERS
$p->clean();
$p->parse_filters({portinfo => 0,scaninfo => 0,uptime => 0, osinfo => 0 , osfamily => 0});

#BENCHMARK WITH FILTERS
$t2 = [Time::HiRes::gettimeofday()];
$p->parsefile($FH) for(0..COUNT);
$t2 = Time::HiRes::tv_interval($t2,[Time::HiRes::gettimeofday()]);

#TESTING OF INFORMATION THAT SHOULD NOT EXIST
is($p->get_scaninfo(),undef,'Testing start tag /w filters');
is($p->get_scaninfo(),undef,'Testing full tag /w filters');
is($p->get_host(HOST1)->hostname, 'localhost.localdomain','Testing hostname tag /w filters');
is($p->get_host(HOST1)->tcp_port_state('111'),'closed','Testing ports /w filters');

SKIP:
{
skip 'No performance improvement from filters',1 if($t1 == $t2 || $t2 == 0 || $t1 == 0);
ok($t1 > $t2 || $t1 == $t2,"Improvement Ratio: ".sprintf("%.2f",(($t1)/($t2)))." times faster");
# print STDERR "\tFilter Improvement Ratio: ".sprintf("%.2f",(($t1)*100/($t2)))."% faster\n" unless($t1 == $t2 || $t2 == 0 || $t1 == 0);
}
