#!/usr/bin/perl
#Anthony G. Persaud
#sweep.pl
#Description:
#	It takes in a nmap xml file and prints a list of active and inactive
#	hosts.

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
# APS 02/05/2004: Added ability output active IP (up state) to a file
#
#
#
#
#
#



use strict;
use Nmap::Parser;
use constant TEST_FILE => 'example.xml';
use constant CMD1 => '-sP --randomize_hosts';
use File::Spec;
use Getopt::Long;
use Pod::Usage;
use vars qw(%G);
Getopt::Long::Configure('bundling');

my $p = new Nmap::Parser;

print "\nsweep.pl - ( http://www.nmapparser.com )\n",
	('-'x50),"\n\n";

GetOptions(
		'help|h|?'	=> \$G{helpme},
		'v+'		=> \$G{verbose},
		'i=s'		=> \$G{usefile},
		'L=s'		=> \$G{ipfile},
		'o=s'		=> \$G{output_active}
) or (pod2usage(-exitstatus => 0, -verbose => 2));

if($G{helpme} || (!$G{usefile} && scalar @ARGV == 0 && !$G{ipfile}))
	{pod2usage(-exitstatus => 0, -verbose => 2)}

if($G{usefile} eq ''){$p = run_nmap_scan(@ARGV);}
else {
	#use the input file
	print 'Using InputFile: '.$G{usefile}."\n" if($G{verbose} > 0);
	if(not -e $G{usefile})
	{print STDERR "ERROR: File $G{usefile} does not exists!\n"; exit;}
	$p->parsefile($G{usefile});
	}

if($G{output_active}){
	open OUTPUT ,">$G{output_active}" ||
	die "ERROR: Could open $G{output_active} for writing!\n$!\n";
}


print "Active Hosts Scanned:\n";
my (@ipa,@ipb);
for my $ip ( $p->get_host_list('up')){

	print "\t$ip\n";
	if($G{output_active}){
	print OUTPUT "$ip\n";
		}
	}

if($G{output_active}){close OUTPUT;}

print "\n";
#printing inactive hosts
print "Inactive Hosts Scanned:\n";
for my $ip ( $p->get_host_list('down')){print "\t$ip\n";}

if($G{output_active}){print "\nSaved output file: $G{output_active}\n";}

################################################################################
##				Utility Functions			      ##
################################################################################
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
            #  Should symbolic link be considered?  Helps me on cygwin but ...
            next unless -r $path && (-x _ || -l _);

            return $path;
           last DIR;
        }
    }

}


sub run_nmap_scan {
my @ips = @_;
my($NMAP,$cmd);

	if($G{ipfile} && -e $G{ipfile})
		{push @ips ,read_ips_from_file($G{ipfile});
		if($G{verbose} > 0){
		print STDERR "\nIP file contains:\n";
		for(@ips){print STDERR "\t$_\n";}
		print "\n";}
		}
	elsif($G{ipfile} && !-e $G{ipfile})
		{warn "WARNING: IP file $G{ipfile} does not exist!\n";}


	$cmd = join ' ', (CMD1, @ips);

	my $nmap_exe = find_exe('nmap');
	if($nmap_exe eq '')
	{warn "ERROR: nmap executable not found in \$PATH\n";
	$nmap_exe = 'nmap';}

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

sweep - scans multiple hosts to determine their network status

=head1 SYNOPSIS

 sweep.pl [OPTS] <IP_ADDR> [<IP.ADDR> ...]

=head1 DESCRIPTION

This script uses the nmap security scanner with the Nmap::Parser module
in order to run a quick PING sweep against specific hosts. It will then inform
of which hosts were active (up) and inactive (down).

=head1 OPTIONS

These options are passed as command line parameters.

=over 4

=item B<-i nmapscan.xml>

Runs the script using the given xml file (which is nmap xml scan data) instead
of actually running a scan against the given set of hosts. This is useful if
you only have the xml data on a given machine, and not nmap.

=item B<-h,--help,-?>

Shows this help information.

=item B<-L ips.txt>

Reads IP addresses from filename.txt to run a scan against. The IP addresses
should be in the target specification format explained below.

=item B<-o output.txt>

Saves the IP addresses found to be active (in state 'up') to a given file. This
file contains each of the active IP addresses found, one on each line. This is
useful if you wish to use the file with other programs or scripts.

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

 sweep.pl 127.0.0.1
 sweep.pl target.example.com
 sweep.pl target.example.com/24
 sweep.pl 10.210.*.1-127
 sweep.pl *.*.2.3-5
 sweep.pl 10.[10-15].10.[2-254]


=head1 OUTPUT EXAMPLE

These are ONLY examples of how the output would look like.

  Status Check
  -------------------------------------------

  Active Hosts Scanned:
          127.0.0.5
          127.0.0.6
          127.0.0.2
          127.0.0.1
          127.0.0.4

  Inactive Hosts Scanned:
          127.0.0.3
          192.168.0.1
          192.168.0.2
          192.168.2.4


The output of the file if using the '-o file.txt' option will look like (using
the IPs from the previous example):

 127.0.0.5
 127.0.0.6
 127.0.0.2
 127.0.0.1
 127.0.0.4


=head1 BUG REPORTS

Please submit any bugs to:
L<http://sourceforge.net/tracker/?group_id=97509&atid=618345>

=head1 SEE ALSO

L<Nmap::Parser>

The Nmap::Parser page can be found at: L<http://www.nmapparser.com>.
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
