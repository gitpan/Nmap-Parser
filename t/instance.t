#!/usr/bin/perl



use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 6;
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
use constant HOST7 => '127.0.0.7';

use constant BASE_FILE =>'base_image.xml';
use constant CURR_FILE =>'current_image.xml';

use vars qw($base $curr $BASE $CURR);

$BASE = File::Spec->catfile(cwd(),'t',BASE_FILE);
$BASE = File::Spec->catfile(cwd(),    BASE_FILE)  unless(-e $BASE);

$CURR = File::Spec->catfile(cwd(),'t',CURR_FILE);
$CURR = File::Spec->catfile(cwd(),    CURR_FILE)  unless(-e $CURR);


$curr = new Nmap::Parser;
$base = new Nmap::Parser;

isa_ok($curr, 'Nmap::Parser');
isa_ok($base, 'Nmap::Parser');

ok($curr->parsefile($CURR),'Parsing from nmap data current image file');
ok($base->parsefile($BASE),'Parsing from nmap data base image file');

my $host_curr = $curr->get_host(HOST1);
my $host_base = $base->get_host(HOST1);



my %port = ();
my @diff =  grep { $port{$_} < 2} (map {$port{$_}++; $_} ($host_curr->tcp_ports('open'),$host_base->tcp_ports('open')));


#making sure objects do not overwrite themselves
cmp_ok($host_curr->tcp_ports_count,'!=',$host_base->tcp_ports_count, 'Testing object instance difference');

is(scalar @diff, 1, "Testing port difference: ".(join '',@diff));
