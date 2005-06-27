#!/usr/bin/perl
#Anthony G. Persaud

use strict;
use Nmap::Parser 1.00;
use Getopt::Long;
use File::Spec;
use Pod::Usage;
use vars qw(%G);


$G{nmap_exe} = find_exe();

my $np = new Nmap::Parser;

print "\nscan.pl - ( http://www.nmapparser.com )\n",
	('-'x80),"\n\n";
        
        
GetOptions(
		'help|h|?'		=> \$G{helpme},
                'nmap=s'                => \$G{nmap}
) or (pod2usage(-exitstatus => 0, -verbose => 2));


if($G{nmap} eq '' ||  scalar @ARGV == 0)
	{pod2usage(-exitstatus => 0, -verbose => 2)}

print "Using nmap exe: ".$G{nmap}."\n\n";

$np->callback(\&host_handler);
$np->parsescan($G{nmap},'-sVU -O -F --randomize_hosts',@ARGV);



sub host_handler {
    my $host = shift;
    print ' > '.$host->ipv4_addr."\n";
    print "\t[+] Status: (".uc($host->status).")\n";
    if($host->status eq 'up'){
        my $os = $host->os_sig();
        tab_print("Hostname(s)",$host->all_hostnames());
	tab_print("Uptime",($host->uptime_seconds())." seconds") if($host->uptime_seconds());
	tab_print("Last Rebooted",$host->uptime_lastboot()) if($host->uptime_lastboot);
        tab_print("OS Signatures",$os->all_names());
        port_service_print($host);
    }
    
print "\n\n";

}

sub port_service_print {
        my $host = shift;
	print "\t[+] TCP Ports :\n" if($host->tcp_port_count);
	for my $port ($host->tcp_open_ports){
            my $svc = $host->tcp_service($port);
            
	printf("\t\t%-6s %-20s %s\n",
			$port,
			'('.$svc->name.') ',
			$svc->product.' '.
			$svc->version).' '.
			$svc->extrainfo;
	}

	print "\t[+] UDP Ports :\n" if($host->udp_port_count);
	for my $port ($host->udp_open_ports){
	    my $svc = $host->udp_service($port);
            
	printf("\t\t%-6s %-20s %s\n",
			$port,
			'('.$svc->name.') ',
			$svc->product.' '.
			$svc->version).' '.
			$svc->extrainfo;
	}
}

sub tab_print {
    my $title = shift;
    print "\t[+] $title :\n";
    for my $a (@_)
    {print "\t\t$a\n";}
    
}

sub find_exe {


    my $exe_to_find = 'nmap';
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

__END__
=pod

=head1 NAME

scan - a scanning script to gather port and OS information from hosts

=head1 SYNOPSIS

 scan.pl [--nmap <NMAP_EXE>] <IP_ADDR> [<IP.ADDR> ...]

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

=item B<--nmap>

The path to the nmap executable. This should be used if nmap is not on your path.

=item B<-h,--help,-?>

Shows this help information.

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

 scan.pl 127.0.0.1
 scan.pl target.example.com
 scan.pl target.example.com/24
 scan.pl 10.210.*.1-127
 scan.pl *.*.2.3-5
 scan.pl 10.[10-15].10.[2-254]


=head1 OUTPUT EXAMPLE

These are ONLY examples of how the output would look like. Not the specs to my machine

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



=head1 SUPPORT

=head2 Discussion Forum

If you have questions about how to use the module, or any of its features, you
can post messages to the Nmap::Parser module forum on CPAN::Forum.
L<http://www.cpanforum.com/dist/Nmap-Parser>

=head2 Bug Reports

Please submit any bugs to:
L<http://sourceforge.net/tracker/?group_id=97509&atid=618345>

B<Please make sure that you submit the xml-output file of the scan which you are having
trouble.> This can be done by running your scan with the I<-oX filename.xml> nmap switch.
Please remove any important IP addresses for security reasons.

=head2 Feature Requests

Please submit any requests to:
L<http://sourceforge.net/tracker/?atid=618348&group_id=97509&func=browse>

=head1 SEE ALSO

L<Nmap::Parser>

The Nmap::Parser page can be found at: L<http://www.nmapparser.com> or L<http://npx.sourceforge.net>.
It contains the latest developments on the module. The nmap security scanner
homepage can be found at: L<http://www.insecure.org/nmap/>.

=head1 AUTHOR

Anthony G Persaud <apersaud@gmail.com> L<http://www.anthonypersaud.com>

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