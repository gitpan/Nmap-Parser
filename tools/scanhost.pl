#!/usr/bin/perl
#Anthony G. Persaud
#port_info.pl
#Description:
#	It takes in a nmap xml file and outputs onto STDOUT and a file the
#	all the ports that were scanned and found by nmap, their different
#	states and services -- all in a comma delimited output
#

#
#This program is free  software; you can redistribute  it and/or modify it under
#the terms of the  GNU General Public License  as published by the Free Software
#Foundation; either  version 2  of the  License, or  (at your  option) any later
#version.
#
#This program is distributed in the hope that it will be useful, but WITHOUT ANY
#WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
#PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# Changelog:
# APS 01/29/2004: Changed run_nmap_scan to use parsescan().
#		  $nmap_exe is set to default 'nmap' if find_exe returns empty
# APS 02/03/2004: Added ability to read IPs from a file
# APS 02/09/2004: Added filtering ability for only active hosts
#		  Added UDP scanning option
#
#
use strict;
use Nmap::Parser;
use Getopt::Long;
use File::Spec;
use Pod::Usage;
use vars qw(%G);
use constant CMD1 => '-sV -O --randomize_hosts';
use constant CMD2 => '-sV -O -F --randomize_hosts';
use constant CMD1_UDP => '-sVU -O --randomize_hosts';
use constant CMD2_UDP => '-sVU -O -F --randomize_hosts';

use constant TEST_FILE => 'example.xml';

Getopt::Long::Configure('bundling');


my $p = new Nmap::Parser;

print "\nscanhost.pl - ( http://npx.sourceforge.net )\n",
	('-'x50),"\n\n";

GetOptions(
		'help|h|?'		=> \$G{helpme},
		'F'		=> \$G{fast},
		'v+'		=> \$G{verbose},
		'i=s'		=> \$G{usefile},
		'L=s'		=> \$G{ipfile},
		'a'		=> \$G{only_active},
		'U'		=> \$G{with_UDP}
) or (pod2usage(-exitstatus => 0, -verbose => 2));

if($G{helpme} || (!$G{usefile} && scalar @ARGV == 0 && !$G{ipfile}))
	{pod2usage(-exitstatus => 0, -verbose => 2)}

if($G{only_active}){
	$p->parse_filters({only_active => 1});
	print "Running only_active filter\n" if($G{verbose});
	}

#Setup parser callback
$p->register_host_callback(\&host_handler);



#If using input file, then don't run nmap and use file
if($G{usefile} eq ''){$p = run_nmap_scan(@ARGV);
}
else {
	#use the input file
	print 'Using InputFile: '.$G{usefile}."\n" if($G{verbose} > 0);
	if(not -e $G{usefile})
	{print STDERR "ERROR: File $G{usefile} does not exists!\n"; exit;}
	$p->parsefile($G{usefile});
	}

#This host handler will get call for every host that is scanned (or found in the
#xml file)

sub host_handler {
my $host = shift;
print ' > '.$host->addr."\n";
print "\t[+] Status: (".uc($host->status).")\n";
if($host->status ne 'up'){goto END;}
	tab_print("Hostname(s)",$host->hostnames());
	tab_print("Operation System(s)",$host->os_matches());
	port_service_print($host);
	tab_print("Uptime Second(s)",($host->uptime_seconds()/3600)." days");
	tab_print("Last Rebooted",$host->uptime_lastboot());

END:
print "\n\n";
}


#Quick function to print witht tabs
sub tab_print {print "\t[+] $_[0] :\n";shift;for my $a (@_){print "\t\t$a\n";}}

sub port_service_print {
	my $host = shift;
	print "\t[+] TCP Ports :\n";
	for my $port ($host->tcp_ports('open')){
	printf("\t\t%-6s %-20s %s\n",
			$port,
			'('.$host->tcp_service_name($port).') ',
			$host->tcp_service_product($port).' '.
			$host->tcp_service_version($port)).' '.
			$host->tcp_service_extrainfo($port);
	}

	print "\t[+] UDP Ports :\n" if($host->udp_ports_count);
	for my $port ($host->udp_ports('open')){
	printf("\t\t%-6s %-20s %s\n",
			$port,
			'('.$host->udp_service_name($port).') ',
			$host->udp_service_product($port).' '.
			$host->udp_service_version($port)).' '.
			$host->udp_service_extrainfo($port);;
	}

}


################################################################################
##				Utility Functions			      ##
################################################################################

#quick function to find an executable in a given path
sub find_exe {


    my $exe_to_find = shift;
    $exe_to_find =~ s/\.exe//;
    local($_);
    local(*DIR);

    for my $dir (File::Spec->path()) {
        opendir(DIR,$dir) || next;
        my @files = (readdir(DIR));
        closedir(DIR);

        my $path;
        for my $file (@files) {
            $file =~ s/\.exe$//;
            next unless($file eq $exe_to_find);

            $path = File::Spec->catfile($dir,$file);
            next unless -r $path && (-x _ || -l _);

            return $path;
            last DIR;
        }
    }

}

sub run_nmap_scan {
my @ips =  @_;
my ($NMAP,$cmd);

	if($G{ipfile} && -e $G{ipfile})
		{push @ips ,read_ips_from_file($G{ipfile});
		if($G{verbose} > 0){
		print STDERR "\nIP file contains:\n";
		for(@ips){print STDERR "\t$_\n";}
		print "\n";}
		}
	elsif($G{ipfile} && !-e $G{ipfile})
		{warn "WARNING: IP file $G{ipfile} does not exist!\n";}


	if(!$G{with_UDP}){

	if($G{fast}){
	print "FastScan enabled\n" if($G{verbose} > 0 && $G{fast});
	$cmd = join ' ', (CMD2, @ips);
	}
	else {$cmd = join ' ', (CMD1, @ips);}

	}
	else {
	print "UDP Scan enabled\n" if($G{verbose} > 0);

	if($G{fast}){
	print "FastScan enabled\n" if($G{verbose} > 0);
	$cmd = join ' ', (CMD2_UDP, @ips);
	}
	else {$cmd = join ' ', (CMD1_UDP, @ips);}
	}



	my $nmap_exe = find_exe('nmap');
	if($nmap_exe eq '')
	{warn "ERROR: nmap executable not found in \$PATH\n";$nmap_exe = 'nmap';}

	print 'Running: '.$nmap_exe.' '.$cmd."\n" if($G{verbose} > 0);


	$p->parsescan($nmap_exe,$cmd);

return $p;
}

sub read_ips_from_file {
my $filename = shift;
my @ips;
open FILE, "$filename" || die "ERROR: Could not open $filename! \nERROR: $!";
for(<FILE>){
chomp; # no newline
s/#.*//; # no comments
s/^\s+//; # no leading white
s/\s+$//; # no trailing white
next unless length; # anything left?
push @ips , $_; #it might be a host name too, so don't expect only numbers
	}
close FILE;
return @ips;

}

__END__
=pod

=head1 NAME

scanhost - a scanning script to gather port and OS information from hosts

=head1 SYNOPSIS

 scanhost.pl [OPTS] <IP_ADDR> [<IP.ADDR> ...]

=head1 DESCRIPTION

This script uses the nmap security scanner with the Nmap::Parser module
in order to run quick scans against specific hosts, and gather all the
information that is required to know about that specific host which nmap can
figure out. This script can be used for quick audits against machines on the
network and an educational use for learning how to write scripts using the
Nmap::Parser module. B<This script uses the -sV output to get version
information of the services running on a machine. This requires nmap version
3.49+>

=head1 OPTIONS

These options are passed as command line parameters.

=over 4

=item B<-a>

This tells the script only to output the information for the hosts that found
in state active or status is 'up'.

=item B<-i nmapscan.xml>

Runs the script using the given xml file (which is nmap xml scan data) instead
of actually running a scan against the given set of hosts. This is useful if
you only have the xml data on a given machine, and not nmap.

=item B<--fast>

Runs a fast (-F) nmap scan against the host.

=item B<-h,--help,-?>

Shows this help information.

=item B<-L ips.txt>

Reads IP addresses from filename.txt to run a scan against. The IP addresses
should be in the target specification format explained below.

=item B<-U>

When running scans, (not using input xml files with -i), this includes scanning
for UDP ports. Note that enabling UDP ports scans increases the time required
for the scanning to finish.

=item B<-v>

This runs the script in verbose mode. The more times used, the more verbose
the script will be.

=back 4

=head1 TARGET SPECIFICATION

This documentation was taken from the nmap man page. The IP address inputs
to this scripts should be in the nmap target specification format.

The  simplest  case is listing single hostnames or IP addresses onthe command
line. If you want to scan a subnet of  IP addresses, you can append '/mask' to
the hostname or IP address. mask must be between 0 (scan the whole internet) and
 32 (scan the single host specified). Use /24 to scan a class 'C' address and
 /16 for a class 'B'.

You can use a more powerful notation which lets you specify an IP address
using lists/ranges for each element. Thus you can scan the whole class 'B'
network 128.210.*.* by specifying '128.210.*.*' or '128.210.0-255.0-255' or
even use the mask notation: '128.210.0.0/16'. These are all equivalent.
If you use asterisks ('*'), remember that most shells require you to escape
them with  back  slashes or protect them with quotes.

Another interesting thing to do is slice the Internet the other way.

Examples:

 scanhost.pl 127.0.0.1
 scanhost.pl target.example.com
 scanhost.pl target.example.com/24
 scanhost.pl 10.210.*.1-127
 scanhost.pl *.*.2.3-5
 scanhost.pl 10.[10-15].10.[2-254]


=head1 OUTPUT EXAMPLE

These are ONLY examples of how the output would look like.

 Scan Host
 --------------------------------------------------
 [>] 127.0.0.1
       [+] Status: (UP)
       [+] Hostname(s) :
               localhost.localdomain
       [+] Operation System(s) :
               Linux Kernel 2.4.0 - 2.5.20
       [+] TCP Ports : (service) [version]
               22     ssh                  OpenSSH 3.5p1
               25     smtp
               111    rpcbind
               443    https
               631    ipp
       [+] UDP Ports :
               111    rpcbind
               937    unknown



=head1 BUG REPORTS

Please submit any bugs to:
L<http://sourceforge.net/tracker/?group_id=97509&atid=618345>

=head1 SEE ALSO

L<Nmap::Parser>

The Nmap::Parser page can be found at: L<http://npx.sourceforge.net/>.
It contains the latest developments on the module. The nmap security scanner
homepage can be found at: L<http://www.insecure.org/nmap/>.

=head1 AUTHOR

 Anthony G Persaud <ironstar@iastate.edu>

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

L<http://www.opensource.org/licenses/gpl-license.php>

=cut
