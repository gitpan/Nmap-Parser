#!/usr/bin/perl

# nmap2csv: Converts nmap results from pseudo-XML into csv
# format to be imported into either Microsoft Excel or OpenOffice.
#
# Author: Sebastian Wolfgarten, <sebastian@wolfgarten.com>
# Date: 23/12/2003
#
# Version: 0.1
#
# Note: This program uses code which was originally written
# 	by Anthony G Persaud <ironstar@iastate.edu>.
#
# Changelog:
# SW  22/12/2003: Project started including basic functions
#                 (e.g. UDP/TCP scanning and converting to csv).
# APS 10/01/2003: Added find_exe function because there was a problem under
#		  different nmap executable locations. Added print statements
#                 and changed cmd for the nmap scans to work better (faster).
#                 Took out the uid checking, since it causes problems running on
#                 other OSs such as cygwin.
#
# Overall coding time: About two hours
# (Yes, I know the code is not very sophisticated but it works *g*)

use Getopt::Std;
use Nmap::Parser;
our $VERSION  = '0.2';

### How to use nmap2csv?

$usage = "
	nmap2cvs.pl v$VERSION - (C) 2003 by Sebastian Wolfgarten, <sebastian\@wolfgarten.com>
	--------------------------------------------------------------------------------

	This software runs a TCP or UDP nmap scan against the target host and generates a nice
	.csv file which could easily be imported into Excel or OpenOffice. It was written in a
	hurry but it should work. Feel free to submit bugs or suggestions :-)

	Usage: $0 [OPTIONS]

	Currently the following options are available:

	-h            : What do you think is this?
	-o outputfile : Write to outputfile (file will be in .csv-format)
	-t UDP/TCP    : Run either a TCP or UDP against the target
	-z target     : Specify the host you want to scan

	Example (TCP scan): $0 -o example_com.csv -t TCP -z www.example.com
	Example (UCP scan): $0 -o example_com_udp.csv -t UDP -z www.example.com

	The output will proably look like this:

	127.0.0.1,22,open,tcp,ssh,OpenSSH,3.7.1p2,protocol 1.99,Linux Kernel 2.4.0 - 2.5.20
		 ,111,open,tcp,rpcbind,,2,rpc #100000,Linux Kernel 2.4.0 - 2.5.20
		 ,139,open,tcp,netbios-ssn,Samba smbd,,workgroup: WORKGROUP,Linux Kernel 2.4.0 - 2.5.20
		 ,817,open,tcp,mountd,,1-3,rpc #100005,Linux Kernel 2.4.0 - 2.5.20
		 ,3306,open,tcp,mysql,MySQL,4.0.16,,Linux Kernel 2.4.0 - 2.5.20
		 ,6000,open,tcp,X11,,,access denied,Linux Kernel 2.4.0 - 2.5.20
		 ,32779,open,tcp,status,,1,rpc #100024,Linux Kernel 2.4.0 - 2.5.20

	Nice, eh? Remember to import this data as pure text into Excel or OpenOffice :-)

";

### Main part


getopt("ho:t:z:");

if ($opt_h) {

	print $usage;

};

# Which nmap commands should I use to perform either TCP or UDP scans?
# Adjust it to your requirements.
my $nmap_path = find_exe("nmap") || 'nmap';
$nmap_cmd_TCP = "$nmap_path -v -sS -sVVV -O -p1-65535 -oX $opt_z.xml ";
$nmap_cmd_UDP = "$nmap_path -v -sU -sVVV -O -p1-65535 -oX $opt_z-udp.xml ";

if (!$opt_o or !$opt_t or !$opt_z) { die $usage;} else {

	if ($opt_t eq TCP) {

		print "Starting nmap TCP scan...this may take a while.\n";
		print "$nmap_cmd_TCP\n";
		system("$nmap_cmd_TCP $opt_z");

		# Create new Nmap parser object and pass temporary file
		# to parser.
		my $nmap_result_file = new Nmap::Parser;
		$nmap_result_file->parsefile("$opt_z.xml");
		my $OUT = $opt_o;

		# Start writing to results to the outputfile
		open (OUT,'>'.$OUT) || die "Could not open output file: $OUT\n!";

		print "\nAusgabedatei: $OUT\n\n";

		for my $host ($nmap_result_file->get_host_objects()) {

			my $i = 1;

			for my $port ($host->tcp_ports()) {

				if ($i == 1) {

	    				# Start writing to csv file,
					# first line will also contain the
					# IP address of the remote system
	    				print OUT $host->addr().',';

				} else {

					# If it's not the first line
					# just don't print the IP adress
	    				print OUT ''.',';

				}

				# Keep on printing the results out
				print OUT $port.','.
				$host->tcp_port_state($port).','.
	    			'tcp,'.
	    			$host->tcp_service_name($port).','.
	    			$host->tcp_service_product($port).','.
	    			$host->tcp_service_version($port).','.
	    			$host->tcp_service_extrainfo($port).','.
	    			$host->os_match()."\n";

				# stdout should always include the IP address
				# of the remote host.
				print STDOUT $host->addr().','.
	    			$port.','.
	    			$host->tcp_port_state($port).','.
	    			'tcp,'.
	    			$host->tcp_service_name($port).','.
	    			$host->tcp_service_product($port).','.
	    			$host->tcp_service_version($port).','.
	    			$host->tcp_service_extrainfo($port).','.
	    			$host->os_match()."\n";

				$i = 0;

			}

		}

		close OUT;
		print "\nOutput file generated: $OUT\n\n";
		exit;

	}

	if ($opt_t eq UDP) {

		print "Starting nmap UDP scan...this may take a long time.\n";
		print "$nmap_cmd_TCP\n";
		system("$nmap_cmd_UDP $opt_z");

		# Create new Nmap parser object and pass temporary file
		# to parser.
		my $nmap_result_file = new Nmap::Parser;
		$nmap_result_file->parsefile("$opt_z-udp.xml");
		my $OUT = $opt_o;

		# Start writing to results to the outputfile
		open (OUT,'>'.$OUT) || die "Could not open output file: $OUT\n!";

		print "\nAusgabedatei: $OUT\n\n";

		for my $host ($nmap_result_file->get_host_objects()) {

			my $i = 1;

			for my $port ($host->udp_ports()) {

				if ($i == 1) {

	    				# Start writing to csv file,
					# first line will also contain the
					# IP address of the remote system
	    				print OUT $host->addr().',';

				} else {

					# If it's not the first line
					# just don't print the IP adress
	    				print OUT ''.',';

				}

				# Keep on printing the results out
				print OUT $port.','.
				$host->udp_port_state($port).','.
	    			'udp,'.
	    			$host->udp_service_name($port).','.
	    			$host->udp_service_product($port).','.
	    			$host->udp_service_version($port).','.
	    			$host->udp_service_extrainfo($port).','.
	    			$host->os_match()."\n";

				# stdout should always include the IP address
				# of the remote host.
				print STDOUT $host->addr().','.
	    			$port.','.
	    			$host->udp_port_state($port).','.
	    			'udp,'.
	    			$host->udp_service_name($port).','.
	    			$host->udp_service_product($port).','.
	    			$host->udp_service_version($port).','.
	    			$host->udp_service_extrainfo($port).','.
	    			$host->os_match()."\n";

				$i = 0;

			}

		}

		close OUT;
		print "\nOutput file generated: $OUT\n\n";
		exit;

	}


};

#finds the executable in the path
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

__END__

=pod

=head1 NAME

nmap2csv - converts nmap results into csv format to be imported into a spreadsheet program

=head1 SYNOPSIS

 nmap2csv -o example_com.csv -t TCP -z www.example.com
 nmap2csv -o example_com_udp.csv -t UDP -z www.example.com

=head1 DESCRIPTION

This software runs a TCP or UDP nmap scan against the target host and generates a nice
.csv file which could easily be imported into Excel or OpenOffice. It was written in a
hurry but it should work. Feel free to submit bugs or suggestions :-)

=head1 OPTIONS

These options are passes as command line parameters.

 -h            : What do you think is this?
 -o outputfile : Write to outputfile (file will be in .csv-format)
 -t UDP/TCP    : Run either a TCP or UDP against the target
 -z target     : Specify the host you want to scan


=head1 OUTPUT EXAMPLE

The output will proably look like this:

 	127.0.0.1,22,open,tcp,ssh,OpenSSH,3.7.1p2,protocol 1.99,Linux Kernel 2.4.0 - 2.5.20
 		 ,111,open,tcp,rpcbind,,2,rpc #100000,Linux Kernel 2.4.0 - 2.5.20
 		 ,139,open,tcp,netbios-ssn,Samba smbd,,workgroup: WORKGROUP,Linux Kernel 2.4.0 - 2.5.20
 		 ,817,open,tcp,mountd,,1-3,rpc #100005,Linux Kernel 2.4.0 - 2.5.20
 		 ,3306,open,tcp,mysql,MySQL,4.0.16,,Linux Kernel 2.4.0 - 2.5.20
 		 ,6000,open,tcp,X11,,,access denied,Linux Kernel 2.4.0 - 2.5.20
 		 ,32779,open,tcp,status,,1,rpc #100024,Linux Kernel 2.4.0 - 2.5.20

Nice, eh? Remember to import this data as pure text into Excel or OpenOffice :-)


=head1 BUG REPORTS

Please submit any bugs to:
L<http://sourceforge.net/tracker/?group_id=97509&atid=618345>

=head1 SEE ALSO

L<Nmap::Parser>

The Nmap::Parser page can be found at: L<http://npx.sourceforge.net/>. It
contains the latest developments on the module.

=head1 AUTHOR

 Sebastian Wolfgarten, <sebastian@wolfgarten.com>

=cut
