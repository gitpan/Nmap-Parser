package Nmap::Parser::XML;

################################################################################
##			Nmap::Parser::XML				      ##
################################################################################

use strict;
require 5.004;
use XML::Twig;
use vars qw($S %H %OS_LIST %F $DEBUG %R $NMAP_EXE);

our $VERSION = '0.74';

sub new {

my ($class,$self) = shift;
$class = ref($class) || $class;

$$self{twig}  = new XML::Twig(
	start_tag_handlers 	=>
			{nmaprun => \&_nmaprun_hdlr},

	twig_roots 		=> {
		scaninfo => \&_scaninfo_hdlr,
		finished => \&_finished_hdlr,
		host 	 => \&_host_hdlr,
				},
	ignore_elts 	=> {
		addport 	=> 1,
		}

		);

#Default Filter Values
reset_filters();

%OS_LIST = (
	linux 	=> [qw(linux mandrake redhat slackware)],
	mac 	=> [qw(mac osx)],
	solaris => [qw(solaris sparc sun)],
	switch 	=> [qw(ethernet cisco netscout router switch bridge)],
	unix 	=> [qw(unix hp-ux hpux bsd immunix aix)],
	wap     => [qw(wireless wap)],
	win  	=> [qw(win microsoft workgroup)]
	    );

bless ($self,$class);
return $self;
}

################################################################################
##			PRE-PARSE METHODS				      ##
################################################################################

sub set_osfamily_list {
my $self = shift;my $list = shift;
%OS_LIST = %{$list};return \%OS_LIST;
}

sub get_osfamily_list {return \%OS_LIST;}

sub parse_filters {
my $self = shift;
my $filters = shift;
my $state;
grep {$F{lc($_)} = $filters->{$_} } keys %$filters;

$$self{twig}->setIgnoreEltsHandlers({
	'addport'	=> 1,
	'extraports'	=> ($F{extraports} ? undef : 1),
	'ports' 	=> ($F{portinfo} ? undef : 1),
	'tcpsequence' 	=> ($F{sequences} ? undef : 1),
	'ipidsequence' 	=> ($F{sequences} ? undef : 1),
	'tcptssequence' => ($F{sequences} ? undef : 1),
	'os'		=> ($F{osinfo} ? undef : 1),
	'uptime' 	=> ($F{uptime} ? undef : 1),
	'scaninfo' 	=> ($F{scaninfo} ? undef : 1),
	'finished' 	=> ($F{scaninfo} ? undef : 1),
	});

return \%F;

}

sub reset_filters {
%F = (
	osfamily 	=> 1,
	osinfo		=> 1,
	scaninfo	=> 1,
	only_active 	=> 0,
	sequences 	=> 1,
	portinfo	=> 1,
	uptime		=> 1,
	extraports	=> 1,
	);


$_[0]->{twig}->setIgnoreEltsHandlers({
	addport 	=> 1,
	}) if(ref($_[0]) eq __PACKAGE__);


return \%F;

}


sub register_host_callback {
	my $self = shift;
	$R{host_callback_ref} = shift;
	if(ref($R{host_callback_ref}) eq 'CODE'){$R{host_callback_register} = 1;}
	else {
	die 'The callback parameter does not seem to be a code reference!';
	$R{host_callback_register} = undef;}
	return $R{host_callback_register};
	}

sub reset_host_callback {$R{host_callback_ref} = $R{host_callback_register}=undef;}

################################################################################
##			PARSE METHODS					      ##
################################################################################
#Safe parse and parsefile will return $@ which will contain the error
#that occured if the parsing failed (it might be empty when no error occurred)
sub parse {
	my $self = shift;
	%H =();$S = undef;
	$self->{twig}->safe_parse(@_);
	if($@){die $@;}
	return $self;
}
sub parsefile {
	my $self = shift;
	%H=();$S = undef;
	$self->{twig}->safe_parsefile(@_);
	if($@){die $@;}
	return $self;
}
sub parsescan {
my $self = shift;
my $nmap = shift;
my $args = shift; #get command for nmap scan
my @ips = @_;

my $FH;
if($args =~ /-o(?:X|N|G)/){die "NPX: Cannot pass option '-oX', '-oN' or '-oG' to parscan()";}
my $cmd = "$nmap $args -v -v -v -oX - ".(join ' ',@ips);
open $FH, "$cmd |" || die "NPX: Could not perform nmap scan: $!";
$self->parse($FH);
close $FH;
return $self;
}


sub clean {%H = ();$S = undef;$_[0]->{twig}->purge;return $_[0];}

################################################################################
##			POST-PARSE METHODS				      ##
################################################################################

sub get_host_list {my $status = lc($_[1]);
if($status eq 'up' || $status eq 'down')
{return (grep {($H{$_}{status} eq $status)}( sort_ips(keys %H) ))};
return  sort_ips(keys %H);
}

sub sort_ips {
if(ref($_[0]) eq __PACKAGE__){shift;}
return (sort {
	my @ipa = split('\.',$a);
	my @ipb = split('\.',$b);
		$ipa[0] <=> $ipb[0] ||
		$ipa[1] <=> $ipb[1] ||
		$ipa[2] <=> $ipb[2] ||
		$ipa[3] <=> $ipb[3]
	} @_);
}

sub get_host {shift if(ref($_[0]) eq __PACKAGE__);return $H{$_[0]};}
sub del_host {shift if(ref($_[0]) eq __PACKAGE__);delete $H{$_[0]};}
sub get_host_objects {return values (%H);}

sub filter_by_osfamily {
my $self = shift;
my @keywords = @_;
my @os_matched_ips = ();
for my $addr (keys %H)
{
	my $os = $H{$addr}{os}{osfamily_names};
	next unless(defined($os) && ($os ne '') );
	if(scalar (grep {defined($_) &&  ($os =~ m/$_/)} @keywords))
	{push @os_matched_ips, $addr;}

}
return sort_ips(@os_matched_ips);

}

sub filter_by_status {
my $self= shift;
my $status = lc(shift);
$status = 'up' if($status ne 'up' && $status ne 'down');
return (grep {$H{$_}{status} eq $status} (sort_ips(keys %H)) );
}


sub get_scaninfo {return $S;}


################################################################################
##			PRIVATE TWIG HANDLERS				      ##
################################################################################

sub _scaninfo_hdlr {
my ($twig,$scan) = @_;
my ($type,$proto,$num) = ($scan->{'att'}->{'type'},$scan->{'att'}->{'protocol'},
$scan->{'att'}->{'numservices'});
if(defined($type)){$S->{type}{$type} = $proto;$S->{numservices}{$type} = $num;}
$twig->purge;}


sub _nmaprun_hdlr {#Last tag in an nmap output
my ($twig,$host) = @_;
unless($F{scaninfo}){return;}
$S->{start_time} = $host->{'att'}->{'start'};
$S->{nmap_version} = $host->{'att'}->{'version'};
$S->{xml_version} = $host->{'att'}->{'xmloutputversion'};
$S->{args} = $host->{'att'}->{'args'};
$S = Nmap::Parser::XML::ScanInfo->new($S);

$twig->purge;
}


sub _finished_hdlr {my ($twig,$host) = @_;$S->{finish_time} =
$host->{'att'}->{'time'};$twig->purge;}


sub _host_hdlr {
# handlers are always called with those 2 arguments
my($twig, $host)= @_;
my ($addr,$tmp);
    if(not defined($host)){return undef;}
    # get the element text
    $tmp        = $host->first_child('address');
    if(not defined $tmp){return undef;}
    $addr = $tmp->{'att'}->{'addr'};
    if(!defined($addr) || $addr eq ''){return undef;}
    $H{$addr}{addr} = $addr;
    $H{$addr}{addrtype} = $tmp->{'att'}->{'addrtype'};
    $tmp = $host->first_child('hostnames');
    @{$H{$addr}{hostnames}} = _hostnames_hdlr($tmp,$addr)
    		if(defined ($tmp = $host->first_child('hostnames')));
    $H{$addr}{status} = $host->first_child('status')->att('state');
    if($H{$addr}{status} eq 'down')
    {	$twig->purge;
	if($F{only_active}){delete $H{$addr};}
    	else { $H{$addr} = Nmap::Parser::XML::Host->new($H{$addr});}
    }
    else {

	    $H{$addr}{ports} = _port_hdlr($host,$addr) if($F{portinfo});
	    $H{$addr}{os} = _os_hdlr($host,$addr);
	    $H{$addr}{uptime} = _uptime_hdlr($host,$addr) if($F{uptime});

    	if($F{sequences})
	{
	    $H{$addr}{tcpsequence} = _tcpsequence($host,$addr);
	    $H{$addr}{ipidsequence} = _ipidsequence($host,$addr);
	    $H{$addr}{tcptssequence} = _tcptssequence($host,$addr);
	}

    	$H{$addr} = Nmap::Parser::XML::Host->new($H{$addr});
    }

    if($R{host_callback_register})
    { &{$R{host_callback_ref}}($H{$addr}); delete $H{$addr};}
# purges the twig
    $twig->purge;

}

sub _port_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my ($host,$addr) = (shift,shift);
my ($tmp,@list);
$tmp = $host->first_child('ports');
unless(defined $tmp){return undef;}

#EXTRAPORTS STUFF
my $extraports = $tmp->first_child('extraports');
if(defined $extraports && $extraports ne ''){
$H{$addr}{ports}{extraports}{state} = $extraports->{'att'}->{'state'};
$H{$addr}{ports}{extraports}{count} = $extraports->{'att'}->{'count'};
}

#PORT STUFF
@list= $tmp->children('port');
for my $p (@list){
my $proto = $p->{'att'}->{'protocol'};
my $portid = $p->{'att'}->{'portid'};
if(defined($proto && $portid)){$H{$addr}{ports}{$proto}{$portid} = _service_hdlr($host,$addr,$p);}
my $state = $p->first_child('state');
if(defined($state) && $state ne '')
{$H{$addr}{ports}{$proto}{$portid}{'state'} = $state->{'att'}->{'state'} || 'closed';}

}

return $H{$addr}{ports};
}



sub _service_hdlr {
my ($host,$addr,$p) = @_;
my $tmp;
my $s = $p->first_child('service[@name]');
$tmp->{service_name} = 'unknown';

if(defined $s){
$tmp->{service_proto} = '';
$tmp->{service_name} = $s->{'att'}->{'name'};
$tmp->{service_version} = $s->{'att'}->{'version'};
$tmp->{service_product} = $s->{'att'}->{'product'};
$tmp->{service_extrainfo} = $s->{'att'}->{'extrainfo'};
$tmp->{service_proto} = $s->{'att'}->{'proto'};
$tmp->{service_rpcnum} = $s->{'att'}->{'rpcnum'};
}

return $tmp;

}

sub _os_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my ($host,$addr) = (shift,shift);
my ($tmp,@list);
if(defined(my $os_list = $host->first_child('os'))){
    $tmp = $os_list->first_child("portused[\@state='open']");
    $H{$addr}{os}{portused}{'open'} = $tmp->{'att'}->{'portid'} if(defined $tmp);
    $tmp = $os_list->first_child("portused[\@state='closed']");
    $H{$addr}{os}{portused}{'closed'} = $tmp->{'att'}->{'portid'} if(defined $tmp);


    for my $o ($os_list->children('osmatch')){push @list, $o->{'att'}->{'name'};  }
    @{$H{$addr}{os}{names}} = @list;

    $H{$addr}{os}{osfamily_names} = _match_os(@list) if($F{osfamily} && $F{osinfo});

    @list = ();
    for my $o ($os_list->children('osclass'))
    {push @list, [$o->{'att'}->{'osfamily'},$o->{'att'}->{'osgen'},$o->{'att'}->{'vendor'},$o->{'att'}->{'type'}];}
    @{$H{$addr}{os}{osclass}} = @list;

    }

    return $H{$addr}{os};

}


sub _uptime_hdlr {
my ($host,$addr) = (shift,shift);
my $uptime = $host->first_child('uptime');
my $hash;
if(defined $uptime){
	$hash->{seconds} = $uptime->{'att'}->{'seconds'};
	$hash->{lastboot} = $uptime->{'att'}->{'lastboot'};
}
return $hash;
}


sub _hostnames_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my $hostnames = shift;
my $addr = shift;
my @names;
for my $n ($hostnames->children('hostname')) {push @names, $n->{'att'}->{'name'};}
return @names if(wantarray);
return \@names;

}

sub _tcpsequence {
my ($host,$addr) = (shift,shift);
my $seq = $host->first_child('tcpsequence');
unless($seq){return undef;}

return [$seq->{'att'}->{'class'},$seq->{'att'}->{'values'},$seq->{'att'}->{'index'}];

}

sub _ipidsequence {
my ($host,$addr) = (shift,shift);
my $seq = $host->first_child('ipidsequence');
unless($seq){return undef;}
return [$seq->{'att'}->{'class'},$seq->{'att'}->{'values'}];

}


sub _tcptssequence {
my ($host,$addr) = (shift,shift);
my $seq = $host->first_child('tcptssequence');
unless($seq){return undef;}
return [$seq->{'att'}->{'class'},$seq->{'att'}->{'values'}];
}

#This is for Nmap::Parser::XML's osfamily match filter
sub _match_os {

shift if(ref($_[0]) eq __PACKAGE__);
my $os_string = lc(join '', @_);
$os_string =~ s/\s|\n//g;
my @matches;
unless(keys %OS_LIST){return undef;}
for my $os_family (keys %OS_LIST){
	my @keywords = @{$OS_LIST{$os_family}};
	for my $keyword (@keywords){
		if($os_string =~ /$keyword/){
			push @matches, $os_family;}
	}


}

#it will join all the matches with commas ex (mac,unix,win)
if(scalar @matches){return (join ',', sort keys %{ {map {$_,1} @matches} } );}
return 'other';

}


################################################################################
##			Nmap::Parser::XML::ScanInfo			      ##
################################################################################

package Nmap::Parser::XML::ScanInfo;

sub new {
my $class = shift;
$class = ref($class) || $class;
my $self =  shift || {};
bless ($self,$class);
return $self;
}

sub num_of_services {
$_[1] ||='';
return if(ref($_[0]->{numservices}) ne 'HASH');
if($_[1] ne ''){return $_[0]->{numservices}{$_[1]};}
else {my $total = 0;for (values %{$_[0]->{numservices}}){$total +=$_;}
return $total;}
}
sub finish_time {return $_[0]->{finish_time};}
sub nmap_version {return $_[0]->{nmap_version};}
sub xml_version {return $_[0]->{xml_version};}
sub args {return $_[0]->{args};}
sub start_time {return $_[0]->{start_time};}
sub scan_types {ref($_[0]->{type}) eq 'HASH' ?
			return (keys %{$_[0]->{type}}) :
			return;}
sub proto_of_scan_type {$_[1] ? $_[0]->{type}{$_[1]} : undef;}


################################################################################
##			Nmap::Parser::XML::Host				      ##
################################################################################

package Nmap::Parser::XML::Host;
use constant OSFAMILY 		=> 0;
use constant OSGEN		=> 1;
use constant OSVENDOR		=> 2;
use constant OSTYPE		=> 3;
use constant CLASS		=> 0;
use constant VALUES		=> 1;
use constant INDEX		=> 2;

sub new {
my ($class,$self) = (shift);
$class = ref($class) || $class;
$self = shift || {};
bless ($self,$class);
return $self;
}

sub status {return $_[0]->{status};}
sub addr {return $_[0]->{addr};}
sub addrtype {return $_[0]->{addrtype};}
#returns the first hostname
sub hostname  { exists($_[0]->{hostnames}) ? return ${$_[0]->{hostnames}}[0] :
					     return undef;   }
sub hostnames {
	if(! exists $_[0]->{hostnames}){return undef;}

	($_[1]) ? 	return @{$_[0]->{hostnames}}[ $_[1] - 1] :
				return @{$_[0]->{hostnames}};}

sub extraports_state {return $_[0]->{ports}{extraports}{state};}
sub extraports_count {return $_[0]->{ports}{extraports}{count};}


sub _get_ports {
my $proto = pop;
my $param = lc($_[1]);
#Error Checking - if the person used port filters, then return undef
return if($Nmap::Parser::XML::F{portinfo} == 0);
return unless(ref($_[0]->{ports}{$proto}) eq 'HASH');

if($param eq 'closed' || $param eq 'filtered' || $param eq 'open')
{
	my @matched_ports;
	for my $p (keys %{ $_[0]->{'ports'}{$proto}   })
	{	if($_[0]->{ports}{$proto}{$p}{state} eq $param)
			{push @matched_ports, $p;}
	}
	return sort {$a <=> $b} @matched_ports;
}
else {return sort {$a <=> $b} (keys %{$_[0]->{ports}{$proto}})}

}

sub _get_port_state {
my $proto = pop;
my $param = lc($_[1]);
 return undef if($Nmap::Parser::XML::F{portinfo} == 0);

if($proto ne 'tcp' && $proto ne 'udp'){return undef;}
	if(exists ${$_[0]}{ports}{$proto}{$param})
		{return $_[0]->{ports}{$proto}{$param}{state};}
	else {return 'closed';}
}

#changed this to use _get_ports since it was similar code
sub tcp_ports { return _get_ports(@_,'tcp');}
sub udp_ports { return _get_ports(@_,'udp');}

#Make sure its exists, if not it will die
sub tcp_ports_count {(ref($_[0]->{ports}{tcp}) eq 'HASH') ?
			return scalar(keys %{$_[0]->{ports}{tcp}}) :
			return 0;}

sub udp_ports_count {(ref($_[0]->{ports}{udp}) eq 'HASH') ?
			return scalar(keys %{$_[0]->{ports}{udp}}) :
			return 0;}

sub tcp_port_state {return _get_port_state(@_,'tcp');}
sub udp_port_state {return _get_port_state(@_,'udp');}

sub tcp_service_name {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_name} :  undef;}
sub udp_service_name {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_name} :  undef;}

sub tcp_service_proto {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_proto} :  undef;}
sub udp_service_proto {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_proto} :  undef;}

sub tcp_service_rpcnum {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_rpcnum} :  undef;}
sub udp_service_rpcnum {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_rpcnum} :  undef;}

sub tcp_service_version {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_version} :  undef;}
sub udp_service_version {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_version} :  undef;}

sub tcp_service_product {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_product} :  undef;}
sub udp_service_product {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_product} :  undef;}

sub tcp_service_extrainfo {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_extrainfo} :  undef;}
sub udp_service_extrainfo {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_extrainfo} :  undef;}

sub os_match {ref($_[0]->{os}{names}) eq 'ARRAY' ? ${$_[0]->{os}{names}}[0] : undef;}
sub os_matches {
if(! exists $_[0]->{os}{names}){return undef;}
	($_[1]) ? 	return @{$_[0]->{os}{names}}[ $_[1] - 1 ] :
				return (@{$_[0]->{os}{names}});}

sub os_port_used {
$_[1] ||= 'open';
if(lc($_[1]) eq 'closed'){return $_[0]->{os}{portused}{'closed'};}
elsif(lc($_[1]) eq 'open'){  return $_[0]->{os}{portused}{'open'};}
}

sub os_family {return ($_[0]->{os}{osfamily_names});}

sub os_class {
	$_[1] ||='';
return if(ref($_[0]->{os}{osclass}) ne 'ARRAY');
if($_[1] eq ''){return scalar @{$_[0]->{os}{osclass}};}
elsif($_[1] ne ''){return @{@{$_[0]->{os}{osclass}}[$_[1] - 1]};}
	}

sub os_vendor {
return if(ref($_[0]->{os}{osclass}) ne 'ARRAY');
if($_[1] > 0){return ${$_[0]->{os}{osclass}}[ $_[1] - 1 ][OSVENDOR]}
else {return ${$_[0]->{os}{osclass}}[0][OSVENDOR] }
}

sub os_gen {
return if(ref($_[0]->{os}{osclass}) ne 'ARRAY');
if($_[1] > 0){return ${$_[0]->{os}{osclass}}[ $_[1] - 1 ][OSGEN]}
else {return ${$_[0]->{os}{osclass}}[0][OSGEN] }
	}

sub os_osfamily {

return if(ref($_[0]->{os}{osclass}) ne 'ARRAY');
if($_[1] > 0){return ${$_[0]->{os}{osclass}}[ $_[1] - 1 ][OSFAMILY]}
else {return ${$_[0]->{os}{osclass}}[0][OSFAMILY] }
	}

sub os_type {
return if(ref($_[0]->{os}{osclass}) ne 'ARRAY');
if($_[1] > 0){return ${$_[0]->{os}{osclass}}[ $_[1] - 1 ][OSTYPE]}
else {return ${$_[0]->{os}{osclass}}[0][OSTYPE] }
	}

sub tcpsequence {return @{$_[0]->{tcpsequence}}    if(ref($_[0]->{tcpsequence}) eq 'ARRAY');}
sub tcpsequence_class {(ref($_[0]->{tcpsequence}) eq 'ARRAY') ? ${$_[0]->{tcpsequence}}[CLASS] :  undef;}
sub tcpsequence_values {(ref($_[0]->{tcpsequence}) eq 'ARRAY') ? ${$_[0]->{tcpsequence}}[VALUES] :  undef;}
sub tcpsequence_index {(ref($_[0]->{tcpsequence}) eq 'ARRAY') ?  ${$_[0]->{tcpsequence}}[INDEX] :  undef;}

sub ipidsequence {return @{$_[0]->{ipidsequence}}  if(ref($_[0]->{ipidsequence}) eq 'ARRAY');}
sub ipidsequence_class {(ref($_[0]->{tcpsequence}) eq 'ARRAY') ?  ${$_[0]->{ipidsequence}}[CLASS] :  undef;}
sub ipidsequence_values {(ref($_[0]->{tcpsequence}) eq 'ARRAY') ? ${$_[0]->{ipidsequence}}[VALUES] :  undef;}


sub tcptssequence {return @{$_[0]->{tcptssequence}} if(ref($_[0]->{tcptssequence}) eq 'ARRAY');}
sub tcptssequence_class {(ref($_[0]->{tcpsequence}) eq 'ARRAY') ?  ${$_[0]->{tcptssequence}}[CLASS] :  undef;}
sub tcptssequence_values {(ref($_[0]->{tcpsequence}) eq 'ARRAY') ? ${$_[0]->{tcptssequence}}[VALUES] :  undef;}

sub uptime_seconds {return $_[0]->{uptime}{seconds};}
sub uptime_lastboot {return $_[0]->{uptime}{lastboot};}

1;

__END__

=pod

=head1 NAME

Nmap::Parser::XML - nmap parser for xml scan data using perl.

=head1 DESCRIPTION

This is the old module that performed the parsing for the Nmap data. It has
now been replaced with the newer module L<Nmap::Parser>. For full documentation
see L<Nmap::Parser> module.

This module is still available for legacy scripts still running Nmap::Parser::XML.
If you are using this old module, please just replace the requirement to
L<Nmap::Parser>.

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

=begin html

<p>
<a href="http://sourceforge.net/projects/npx"><img src="http://sourceforge.net/sflogo.php?group_id=97509&type=5" align='left' alt="SourceForge.net Logo" border="0" /></a>
</p>

=end html

=cut
