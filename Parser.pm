package Nmap::Parser;

################################################################################
##			Nmap::Parser				      ##
################################################################################

use strict;
require 5.004;
use XML::Twig;
use Storable qw(dclone);
use vars qw($DEBUG $G $NMAP_EXE $VERSION);

$VERSION = '0.80';

sub new {

my ($class,$self) = shift;
$class = ref($class) || $class;

$self->{twig}  = new XML::Twig(
	start_tag_handlers 	=>
			{nmaprun => \&_nmaprun_hdlr
                         },

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

%{$self->{os_list}} = (
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
%{$self->{os_list}} = %{$list};return $self->{os_list};
}

sub get_osfamily_list {my $self = shift; return $self->{os_list};}

sub parse_filters {
my $self = shift;
my $filters = shift;
my $state;
grep {$G->{FILTERS}{lc($_)} = $filters->{$_} } keys %$filters;

$self->{twig}->setIgnoreEltsHandlers({
	'addport'	=> 1,
	'extraports'	=> ($G->{FILTERS}{extraports} ? undef : 1),
	'ports' 	=> ($G->{FILTERS}{portinfo} ? undef : 1),
	'tcpsequence' 	=> ($G->{FILTERS}{sequences} ? undef : 1),
	'ipidsequence' 	=> ($G->{FILTERS}{sequences} ? undef : 1),
	'tcptssequence' => ($G->{FILTERS}{sequences} ? undef : 1),
	'os'		=> ($G->{FILTERS}{osinfo} ? undef : 1),
	'uptime' 	=> ($G->{FILTERS}{uptime} ? undef : 1),
	'scaninfo' 	=> ($G->{FILTERS}{scaninfo} ? undef : 1),
	'finished' 	=> ($G->{FILTERS}{scaninfo} ? undef : 1)
        });

return $G->{FILTERS};

}

sub reset_filters {
my $self = shift;
%{$G->{FILTERS}} = (
	osfamily 	=> 1,
	osinfo		=> 1,
	scaninfo	=> 1,
	only_active 	=> 0,
	sequences 	=> 1,
	portinfo	=> 1,
	uptime		=> 1,
	extraports	=> 1,
	);


$self->{twig}->setIgnoreEltsHandlers({
	addport 	=> 1,
	}) if($self->{twig});


return $G->{FILTERS};

}


sub register_host_callback {
	my $self = shift;
	$self->{callback}{host_callback_ref} = shift;
	if(ref($self->{callback}{host_callback_ref}) eq 'CODE'){$self->{callback}{host_callback_register} = 1;}
	else {
	die 'The callback parameter does not seem to be a code reference!';
	$self->{callback}{host_callback_register} = undef;}
	return $self->{callback}{host_callback_register};
	}

sub reset_host_callback {my $self = shift;$self->{callback}{host_callback_ref} = $self->{callback}{host_callback_register}=undef;}

################################################################################
##			PARSE METHODS					      ##
################################################################################
#Safe parse and parsefile will return $@ which will contain the error
#that occured if the parsing failed (it might be empty when no error occurred)

sub _init_vars {
my $self = shift;
$G->{OS_LIST} = $self->{os_list};
$G->{HOSTS_DATA} = undef;
$G->{SCAN_INFO} = undef;
$G->{CALLBACK} = $self->{callback};
return $self;
}

sub _clean_vars {
my $self = shift;
$self->{hosts_data} = dclone($G->{HOSTS_DATA}) if($G->{HOSTS_DATA});
$self->{scan_info} = dclone($G->{SCAN_INFO}) if($G->{SCAN_INFO});
$self->{filters}  = $G->{FILTERS};
$G = undef;
$G->{FILTERS} = $self->{filters};
return $self;
}

sub parse {
	my $self = shift;
	$self->_init_vars;
	$self->{twig}->safe_parse(@_);
	if($@){die $@;}
	$self->_clean_vars;
	return $self;
}
sub parsefile {
	my $self = shift;
	$self->_init_vars();
	$self->{twig}->safe_parsefile(@_);
	if($@){die $@;}
	$self->_clean_vars;
	return $self;
}

sub parsescan {
my $self = shift;
my $nmap = shift;
my $args = shift; #get command for nmap scan
my @ips = @_;


my $FH;
if($args =~ /-o(?:X|N|G)/){die "Nmap-Parser: Cannot pass option '-oX', '-oN' or '-oG' to parsecan()";}
my $cmd = "$nmap $args -v -v -v -oX - ".(join ' ',@ips);
open $FH, "$cmd |" || die "Nmap-Parser: Could not perform nmap scan - $!";

$self->_init_vars;
$self->parse($FH);
close $FH;
$self->_clean_vars;
return $self;
}


sub clean {
    my $self = shift;
    $self->{scan_info} = $self->{hosts_data} = undef;
    #$self->{twig}->purge;
    return $self;
    }

################################################################################
##			POST-PARSE METHODS				      ##
################################################################################

sub get_host_list {
my $self = shift;    
my $status = lc(shift);
if($status eq 'up' || $status eq 'down')
{return (grep {($self->{hosts_data}{$_}{status} eq $status)}( sort_ips(keys %{$self->{hosts_data}}) ))};
return  sort_ips(keys %{$self->{hosts_data}});
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

sub get_host {
    my ($self,$ip) = (@_);
return (defined $self->{hosts_data}{$ip} ? dclone($self->{hosts_data}{$ip}) : undef);
	}
sub del_host {my ($self,$ip) = (@_); delete $self->{hosts_data}{$ip};}
sub get_host_objects {my $self = shift; return values (%{$self->{hosts_data}});}

sub filter_by_osfamily {
my $self = shift;
my @keywords = @_;
my @os_matched_ips = ();
for my $addr (keys %{$self->{hosts_data}})
{
	my $os = $self->{hosts_data}{$addr}{os}{osfamily_names};
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
return (grep {$self->{hosts_data}{$_}{status} eq $status} (sort_ips(keys %{$self->{hosts_data}})) );
}


sub get_scaninfo {my $self = shift; return $self->{scan_info};}


################################################################################
##			PRIVATE TWIG HANDLERS				      ##
################################################################################
#parses nmaprun starting tag
sub _nmaprun_hdlr {#Last tag in an nmap output
my ($twig,$host) = @_;
unless($G->{FILTERS}{scaninfo}){return;}
$G->{SCAN_INFO}{start_time} = $host->{'att'}->{'start'};
$G->{SCAN_INFO}{nmap_version} = $host->{'att'}->{'version'};
$G->{SCAN_INFO}{startstr} = $host->{'att'}->{'startstr'};
$G->{SCAN_INFO}{xml_version} = $host->{'att'}->{'xmloutputversion'};
$G->{SCAN_INFO}{args} = $host->{'att'}->{'args'};
$G->{SCAN_INFO} = Nmap::Parser::ScanInfo->new($G->{SCAN_INFO});

$twig->purge;
}


#parses scaninfo tag
sub _scaninfo_hdlr {
my ($twig,$scan) = @_;
my ($type,$proto,$num) = ($scan->{'att'}->{'type'},$scan->{'att'}->{'protocol'},
$scan->{'att'}->{'numservices'});
if(defined($type)){$G->{SCAN_INFO}{type}{$type} = $proto;$G->{SCAN_INFO}{numservices}{$type} = $num;}
$twig->purge;}

#last tag (finished)
sub _finished_hdlr {my ($twig,$host) = @_;

$G->{SCAN_INFO}{finish_time} = $host->{'att'}->{'time'};
$G->{SCAN_INFO}{timestr} = $host->{'att'}->{'timestr'};

$twig->purge;}


#Parses all host information tag
sub _host_hdlr {
# handlers are always called with those 2 arguments
my($twig, $host)= @_;
my ($addr,$tmp,$addr_hash);
    if(not defined($host)){return undef;}
    # get the element text
    $addr_hash = _addr_hdlr($host);
    $addr = $addr_hash->{'ipv4'}; #use ipv4 as identifier
    $G->{HOSTS_DATA}{$addr}{addrs} = $addr_hash;
    if(!defined($addr) || $addr eq ''){return undef;}

    $tmp = $host->first_child('hostnames');
    @{$G->{HOSTS_DATA}{$addr}{hostnames}} = _hostnames_hdlr($tmp,$addr)
    		if(defined ($tmp = $host->first_child('hostnames')));
    $G->{HOSTS_DATA}{$addr}{status} = $host->first_child('status')->att('state');
    if($G->{HOSTS_DATA}{$addr}{status} eq 'down')
    {	$twig->purge;
	if($G->{FILTERS}{only_active}){delete $G->{HOSTS_DATA}{$addr};}
    	else { $G->{HOSTS_DATA}{$addr} = Nmap::Parser::Host->new($G->{HOSTS_DATA}{$addr});}
    }
    else {

	    $G->{HOSTS_DATA}{$addr}{ports} = _port_hdlr($host,$addr) if($G->{FILTERS}{portinfo});
	    $G->{HOSTS_DATA}{$addr}{os} = _os_hdlr($host,$addr);
	    $G->{HOSTS_DATA}{$addr}{uptime} = _uptime_hdlr($host,$addr) if($G->{FILTERS}{uptime});

    	if($G->{FILTERS}{sequences})
	{
	    $G->{HOSTS_DATA}{$addr}{tcpsequence} = _tcpsequence($host,$addr);
	    $G->{HOSTS_DATA}{$addr}{ipidsequence} = _ipidsequence($host,$addr);
	    $G->{HOSTS_DATA}{$addr}{tcptssequence} = _tcptssequence($host,$addr);
	}

    	$G->{HOSTS_DATA}{$addr} = Nmap::Parser::Host->new($G->{HOSTS_DATA}{$addr});
    }

    if($G->{CALLBACK}{host_callback_register})
    { &{$G->{CALLBACK}{host_callback_ref}}($G->{HOSTS_DATA}{$addr}); delete $G->{HOSTS_DATA}{$addr};}
# purges the twig
    $twig->purge;

}

sub _addr_hdlr {
my $host = shift;
my %addr_hash = ();
my @addrs = $host->children('address');

	for my $addr (@addrs){
		if(lc($addr->{'att'}->{'addrtype'}) eq 'mac')
		{
		#we'll assume for now, only 1 MAC address per system
		$addr_hash{'mac'}{'addr'} = $addr->{'att'}->{'addr'};
		$addr_hash{'mac'}{'vendor'} = $addr->{'att'}->{'vendor'};
		}
		elsif(lc($addr->{'att'}->{'addrtype'}) eq 'ipv4') {
		$addr_hash{'ipv4'} = $addr->{'att'}->{'addr'};
		}

	}

return \%addr_hash;

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
$G->{HOSTS_DATA}{$addr}{ports}{extraports}{state} = $extraports->{'att'}->{'state'};
$G->{HOSTS_DATA}{$addr}{ports}{extraports}{count} = $extraports->{'att'}->{'count'};
}

#PORT STUFF
@list= $tmp->children('port');
for my $p (@list){
my $proto = $p->{'att'}->{'protocol'};
my $portid = $p->{'att'}->{'portid'};
if(defined($proto && $portid)){$G->{HOSTS_DATA}{$addr}{ports}{$proto}{$portid} = _service_hdlr($host,$addr,$p);}
my $state = $p->first_child('state');
if(defined($state) && $state ne '')
{$G->{HOSTS_DATA}{$addr}{ports}{$proto}{$portid}{'state'} = $state->{'att'}->{'state'} || 'closed';}
#Added owner information (ident)
my $owner = $p->first_child('owner');
if(defined($owner) && $owner ne '')
{$G->{HOSTS_DATA}{$addr}{ports}{$proto}{$portid}{'owner'} = $owner->{'att'}->{'name'} || '';}

}

return $G->{HOSTS_DATA}{$addr}{ports};
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
$tmp->{service_tunnel} = $s->{'att'}->{'tunnel'};
$tmp->{service_method} = $s->{'att'}->{'method'};
$tmp->{service_confidence} = $s->{'att'}->{'conf'};
}

return $tmp;

}

sub _os_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my ($host,$addr) = (shift,shift);
my ($tmp,@list);
if(defined(my $os_list = $host->first_child('os'))){
    $tmp = $os_list->first_child("portused[\@state='open']");
    $G->{HOSTS_DATA}{$addr}{os}{portused}{'open'} = $tmp->{'att'}->{'portid'} if(defined $tmp);
    $tmp = $os_list->first_child("portused[\@state='closed']");
    $G->{HOSTS_DATA}{$addr}{os}{portused}{'closed'} = $tmp->{'att'}->{'portid'} if(defined $tmp);


    for my $o ($os_list->children('osmatch')){push @list, $o->{'att'}->{'name'};  }
    @{$G->{HOSTS_DATA}{$addr}{os}{names}} = @list;

    $G->{HOSTS_DATA}{$addr}{os}{osfamily_names} = _match_os(@list) if($G->{FILTERS}{osfamily} && $G->{FILTERS}{osinfo});

    @list = ();
    for my $o ($os_list->children('osclass'))
    {push @list, [$o->{'att'}->{'osfamily'},$o->{'att'}->{'osgen'},$o->{'att'}->{'vendor'},$o->{'att'}->{'type'},$o->{'att'}->{'accuracy'}];}
    @{$G->{HOSTS_DATA}{$addr}{os}{osclass}} = @list;

    }

    return $G->{HOSTS_DATA}{$addr}{os};

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

#This is for Nmap::Parser's osfamily match filter
sub _match_os {

shift if(ref($_[0]) eq __PACKAGE__);
my $os_string = lc(join '', @_);
$os_string =~ s/\s|\n//g;
my @matches;
unless(keys %{$G->{OS_LIST}}){return undef;}
for my $os_family (keys %{$G->{OS_LIST}}){
	my @keywords = @{$G->{OS_LIST}{$os_family}};
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
##			Nmap::Parser::ScanInfo			              ##
################################################################################

package Nmap::Parser::ScanInfo;

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
sub start_time {return $_[0]->{start_time};}
sub start_str {return $_[0]->{startstr};}

sub finish_time {return $_[0]->{finish_time};}
sub time_str {return $_[0]->{timestr};}

sub nmap_version {return $_[0]->{nmap_version};}
sub xml_version {return $_[0]->{xml_version};}
sub args {return $_[0]->{args};}
sub scan_types {ref($_[0]->{type}) eq 'HASH' ?
			return (keys %{$_[0]->{type}}) :
			return;}
sub proto_of_scan_type {$_[1] ? $_[0]->{type}{$_[1]} : undef;}


################################################################################
##			Nmap::Parser::Host				      ##
################################################################################

package Nmap::Parser::Host;
use constant OSFAMILY 		=> 0;
use constant OSGEN		=> 1;
use constant OSVENDOR		=> 2;
use constant OSTYPE		=> 3;
use constant OSACCURACY		=> 4;
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
sub addr {return $_[0]->{addrs}{'ipv4'};}
sub addrtype { return 'ipv4' if(defined $_[0]->{addrs}{'ipv4'} );}
sub ipv4_addr {return $_[0]->{addrs}{'ipv4'};}
sub mac_addr {return $_[0]->{addrs}{'mac'}{'addr'};}
sub mac_vendor {return $_[0]->{addrs}{'mac'}{'vendor'};}

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
my $self = shift;
my $proto = pop; #param might be empty, so this goes first
my $param = lc(shift);    

#if($Nmap::Parser::G->{FILTERS}{portinfo} == 0){return undef;}

#Error Checking - if the person used port filters, then return undef

return unless(ref($self->{ports}{$proto}) eq 'HASH');

#the port parameter can be set to either any of these also 'open|filtered'
#can count as 'open' and 'fileterd'. Therefore I need to use a regex from now on
if($param =~ /[ofc](?:pen|ilter|losed)/i  )
{
	my @matched_ports;
	for my $p (keys %{ $self->{'ports'}{$proto}   })
	{	if($self->{ports}{$proto}{$p}{state} =~ /\Q$param\E/) #escape metacharacters ('|', for example in: open|filtered)
			{push @matched_ports, $p;}
	}
	return sort {$a <=> $b} @matched_ports;
}
else {return sort {$a <=> $b} (keys %{$self->{ports}{$proto}})}

}

sub _get_port_state {
my $self = shift;
my $proto = pop; #param might be empty, so this goes first
my $param = lc(shift);    

#if($Nmap::Parser::G->{FILTERS}{portinfo} == 0){return undef;}

if($proto ne 'tcp' && $proto ne 'udp'){return undef;}

if(exists $self->{ports}{$proto}{$param}){return $self->{ports}{$proto}{$param}{state};}
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

sub tcp_service_owner {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{owner} :  undef;}
sub udp_service_owner {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{owner} :  undef;}

sub tcp_service_version {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_version} :  undef;}
sub udp_service_version {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_version} :  undef;}

sub tcp_service_product {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_product} :  undef;}
sub udp_service_product {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_product} :  undef;}

sub tcp_service_extrainfo {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_extrainfo} :  undef;}
sub udp_service_extrainfo {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_extrainfo} :  undef;}

sub tcp_service_tunnel {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_tunnel} :  undef;}
sub udp_service_tunnel {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_tunnel} :  undef;}

sub tcp_service_method {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_method} :  undef;}
sub udp_service_method {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_method} :  undef;}

sub tcp_service_confidence {$_[1] ne '' ?  $_[0]->{ports}{tcp}{$_[1]}{service_confidence} :  undef;}
sub udp_service_confidence {$_[1] ne '' ?  $_[0]->{ports}{udp}{$_[1]}{service_confidence} :  undef;}


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

sub os_accuracy {
return if(ref($_[0]->{os}{osclass}) ne 'ARRAY');
if($_[1] > 0){return ${$_[0]->{os}{osclass}}[ $_[1] - 1 ][OSACCURACY]}
else{return ${$_[0]->{os}{osclass}}[0][OSACCURACY] }
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

Nmap::Parser - parse nmap scan data with perl

=head1 SYNOPSIS

  use Nmap::Parser;
  my $np = new Nmap::Parser;

  $nmap_exe = '/usr/bin/nmap';

  $np->register_host_callback(\&my_callback)

  $np->parsescan($nmap_exe,'-sT -p1-1023', @ips);

  # or just parse an existing output file
  # $np->parsefile('nmap_output.xml') #using filenames
  #parsescan() is useful for real-time scanning and information gathering
  #while parsefile() is used more for offline analysis of nmap outputs.

 sub my_callback {
   my $host_obj = shift; #see documentation for methods
   my $address = $host_obj->ipv4_addr;
   my $hostname = $host_obj->hostname;
   #.. see documentation for all methods ...

   }

=head1 DESCRIPTION

This perl module is here to ease the pain of developing scripts or collecting
network information from nmap scans. Nmap::Parser does its task by parsing the
information in the output of an nmap scan by using the xml-formatted output.
An nmap parser for xml scan data using perl. Nmap Parser is a PERL module that
makes developing security and audit tools using nmap and perl easier.

This is an stand-alone output parser for nmap outputs. This uses the
XML::Twig library which is fast and memory efficient. This module can perform an
nmap scan and parse the output (automagically) using parsescan(). It can parse a
nmap xml file, or it can take a filehandle that is piped from a current nmap running
scan using '-oX -' switch (but you might as well use parsescan() ). This module
was developed to speedup network security tool development when using nmap.

This module is meant to be a balance of easy of use and efficiency.
I have added filtering capabilities to incrase parsing speed and save memory
usage for parsing large nmap scan files. If you need more information from an
nmap output that is not available in the release, please send your request.

=head2 OVERVIEW

Using this module is very simple. (hopefully).

=over 4

=item I<Set your Options>

You first set any filters you want on the information you will parse. This
is optional, but if you wish the parser to be more efficient, don't parse
information you don't need. Other options (os_family) can be
set also. (See Pre-Parse methods)

Example, if you only want to retain the information of the hosts that nmap
found to be up (active), then set the filter:

 $np->parse_filters({only_active => 1});

Usually you won't have much information about hosts that are down from nmap
anyways.

=item I<Run the parser>

Parse the info. You use $np->parse(), $np->parsefile() or even $np->parsescan(),
to parse the nmap information. This information is parsed and constructed internally.
parsefile() expects an nmap-xml-output formatted file as the input. parsescan()
on the other hand requires the nmap executable, command line options, and the list
of IP addresses. It will run the scan, and automatically call parse() on the output.
Usually parsefile() will be used for offline analysis while parsescan() will be used
on the real-time network scanning and information gathering.

=item I<Get the Scan Info>

Use the $si = $np->get_scaninfo() to obtain the
Nmap::Parser::ScanInfo object. Then you can call any of the
ScanInfo methods on this object to retrieve the information. See
Nmap::Parser::ScanInfo below.

=item I<Get the Host Info>

Use the $np->get_host($addr) to obtain the Nmap::Parser::Host object of
the current address. Using this object you can call any methods in the
Nmap::Parser::Host object to retrieve the information that nmap obtained
from this scan.

 $np->get_host($ip_addr);

You can use any of the other methods to filter or obtain
different lists.

 	#returns all ip addresses that were scanned
 $np->get_host_list()

 	#returns all ip addresses that have osfamily = $os
 $np->filter_by_osfamily($os)
	 #See get_os_list() and set_os_list()
	 #etc. (see other methods)

	#returns all host objects from the information parsed.
	#All are Nmap::Parser::Host objects
 $np->get_host_objects()


=item I<Clean up>

This is semi-optional. When files are not that long, this is optional.
If you are in a situation with memory constraints and are dealing with large
nmap xml-output files, this little effort helps. After you are done with everything, you should do a $np->clean()
to free up the memory used by maintaining the scan and hosts information
from the scan. A much more efficient way to do is, once you are done using a
host object, delete it. B<If you use the register_host_callback method, you do
not have to worry about memory since the host object gets deleted after the function
returns.>

 		#Getting all IP addresses parsed
 for my $host ($np->get_host_list())
 	{	#Getting the host object for that address
	my $h = $np->get_host($host);
		#Calling methods on that object
	print "Addr: $host  OS: ".$h->os_match()."\n";
	$np->del_host($host); #frees memory
	}

	#Or when you are done with everything use $np->clean()
Or you could skip the $np->del_host(), and after you are done, perform a
$np->clean() which resets all the internal trees. Of course there are much
better ways to clean-up (using perl idioms).

=back

=head1 METHODS

=head2 Pre-Parsing Methods

=over 4

=item B<new()>

Creates a new Nmap::Parser object with default handlers and default
osfamily list. In this document the current Nmap::Parser object will be
referred as B<$np>.

 my $np = new Nmap::Parser; #NPX = Nmap Parser XML for those curious

=item B<set_osfamily_list($hashref)>

Decides what is the osfamily name of the given system.

Takes in a hash refernce that referes to pairs of osfamily names to their
keyword list. Shown here is the default. Calling this method will overwrite the
whole list, not append to it. Use C<get_osfamily_list()> first to get the current
listing.

  $np->set_osfamily_list({
	linux 	=> [qw(linux mandrake redhat slackware)],
	mac 	=> [qw(mac osx)],
	solaris => [qw(solaris sparc sun)],
	switch 	=> [qw(ethernet cisco netscout router switch bridge)],
	unix 	=> [qw(unix hp-ux hpux bsd immunix aix)],
	wap     => [qw(wireless wap)],
	win  	=> [qw(win microsoft workgroup)]
	    });

example: osfamily_name = solaris if the os string being matched
matches (solaris, sparc or sunos) keywords

The reason for having this seprately that relying on the 'osclass' tag in the
xml output is that the 'osclass' tag is not generated all the time. Usually
new versions of nmap will generate the 'osclass' tags. These will be available
through the Nmap::Parser::Host methods. (See below).

=item B<get_osfamily_list()>

Returns a hashre containing the current osfaimly names (keys) and
an arrayref pointing to the list of corresponding keywords (values).
See C<set_osfamily_list()> for an example.

=item B<parse_filters($hashref)>

This function takes a hash reference that will set the corresponding filters
when parsing the xml information. All filter names passed will be treated
as case-insensitive. I<NOTE: This version of the parser will ignore the 'addport'
tag in the xml file. If you feel the need for this tag. Send your feedback>

 $np->parse_filters({
 	osfamily 	=> 1, #same as any variation. Ex: osfaMiLy
 	only_active	=> 0,  #same here
 	portinfo	=> 1,
 		});

=item I<EXTRAPORTS>

If set to true, (the default), it will parse the extraports tag.

=item I<ONLY_ACTIVE>

If set to true, it will ignore hosts that nmap found to be in state 'down'.
If set to perl-wise false, it will parse all the hosts. This is the default.
Note that if you do not place this filter, it will parse and store (in memory)
hosts that do not have much information. So calling a Nmap::Parser::Host
method on one of these hosts that were 'down', will return undef.

=item I<OSFAMILY>

If set to true, (the default), it will match the OS guessed by nmap with a
osfamily name that is given in the OS list. See set_osfamily_list(). If
false, it will disable this matching (less memory usage, faster parsing).

=item I<OSINFO>

Enabled by default. If set to true it will parse any OS information found (osclass and
osmatch tags). Otherwise, it will ignore these tags (less memory usage, faster parsing).

=item I<PORTINFO>

If set to true, parses the port information. (You usually want this enabled).
Enabled by default.

=item I<SCANINFO>

If set to true, parses the scan information. This includes the 'scaninfo',
'nmaprun' and 'finished' tags. This is set to true by default. If you don't
care about the scan information of the file, then turn this off to enhance speed
and memory usage.

=item I<SEQUENCES>

If set to true, parses the tcpsequence, ipidsequence and tcptssequence
information. Enabled by default.

=item I<UPTIME>

If set to true, parses the uptime information (lastboot, uptime-seconds..etc).
Enabled by default.

=item B<reset_filters()>

Resets the value of the filters to the default values:

 osfamily 	=> 1
 scaninfo	=> 1
 only_active 	=> 0
 sequences 	=> 1
 portinfo	=> 1
 scaninfo	=> 1
 uptime		=> 1
 extraports	=> 1
 osinfo		=> 1


=item B<register_host_callback>

Sets a callback function, (which will be called) whenever a host is found. The
callback defined will receive as arguments the current Nmap::Parser::Host
that was just parsed. After the callback returns (back to Nmap::Parser to
keep on parsing other hosts), that current host will be deleted (so you don't
have to delete it yourself). This saves a lot of memory since after you perform
the actions you wish to perform on the Nmap::Parser::Host object you
currently have, it gets deleted from the tree.

 $np->register_host_callback(\&host_handler);

 sub host_handler {
 my $host_obj = shift; #an instance of Nmap::Parser::Host (for current)

 ... do stuff with $host_obj ... (see Nmap::Parser::Host doc)

 return; # $host_obj will be deleted (similar to del_host()) method

 }

This method of parsing and analyzing each host is good for batch processing:
maybe updating a database of hosts. Sometimes, the classic method might be better
if you are trying to compare two hosts (for example, what ports two computers have in common).


=item B<reset_host_callback>

Resets the host callback function, and does normal parsing.

=back

=head2 Parse Methods

=over 4

=item B<parse($source [, opt =E<gt> opt_value [...]])>

This method is inherited from XML::Parser.  The $source parameter should
either be a string containing the whole XML document, or it should be
an open C<IO::Handle> (filehandle). Constructor options to C<XML::Parser::Expat>
given as keyword-value pairs may follow the $source parameter. These override,
for this call, any options or attributes passed through from the XML::Parser
instance.

A die call is thrown if a parse error occurs. This method wraps the parsing
in an "eval" block. $@ contains the error message on failure. I<NOTE: that the
parsing still stops as soon as an error is detected, there is no way to keep
going after an error.>

If you get an error or your program dies due to parsing, please check that the
xml information is compliant. If you are using parsescan() or an open filehandle
, make sure that the nmap scan that you are performing is successful in returning
xml information. (Sometimes using loopback addresses causes nmap to fail).

=item B<parsescan($nmap_exe, $args , @ips)>

This method takes as arguments the path to  the nmap executable (it could just
be 'nmap' too), nmap command line options and a list of IP addresses. It
then runs an nmap scan that is piped directly into the Nmap::Parser parser.
This enables you to perform an nmap scan against a series of hosts and
automatically have the Nmap::Parser module parse it.

 #Example:
 my @ips = qw(127.0.0.1 10.1.1.1);
 $nmap_exe = '/usr/bin/nmap';
 $p->parsescan($nmap_exe,'-sT -p1-1023', @ips);
 #   ... then do stuff with Nmap::Parser object

 my $host_obj = $p->get_host("127.0.0.1");
 #   ... and so on and so forth ...

I<Note: You cannot have one of the nmap options to be '-oX', '-oN' or 'oG'. Your
program will die if you try and pass any of these options because it decides the
type of output nmap will generate. The IP addresses can be nmap-formatted
addresses (see nmap(1)>

If you get an error or your program dies due to parsing, please check that the
xml information is compliant. If you are using parsescan() or an open filehandle
, make sure that the nmap scan that you are performing is successful in returning
xml information. (Sometimes using loopback addresses causes nmap to fail).

=item B<parsefile($filename [, opt =E<gt> opt_value [...]])>

This method is inherited from XML::Parser. This is the same as parse() except
that it takes in a  filename that it will OPEN and parse. The file is closed no
matter how C<parsefile()> returns.

A die call is thrown if a parse error occurs. This method wraps the parsing
in an "eval" block. $@ contains the error message on failure. I<NOTE: that the
parsing still stops as soon as an error is detected, there is no way to keep
going after an error.>

If you get an error or your program dies due to parsing, please check that the
xml information is compliant.

=item B<clean()>

Frees up memory by cleaning the current tree hashes and purging the current
information in the XML::Twig object. Returns the Nmap::Parser object.

=back

=head2 Post-Parse Methods

=over 4

=item B<get_host_list([$status])>

Returns all the ip addresses that were run in the nmap scan.
$status is optional and can be either 'up' or 'down'. If $status is
given, then only IP addresses that have that corresponding state will
be returned. Example: setting $status = 'up', then will return all IP
addresses that were found to be up. (network talk for active)

=item B<get_host($ip_addr)>

Returns the complete host object of the corresponding IP address.

=item B<del_host($ip_addr)>

Deletes the corresponding host object from the main tree. (Frees up
memory of unwanted host structures).

=item B<get_host_objects()>

Returns all the host objects of all the IP addresses that nmap had run against.
See L<Nmap::Parser::Host>.

=item B<filter_by_osfamily(@osfamily_names)>

This returns all the IP addresses that have match any of the keywords in
@osfamily_names that is set in their osfamily_names field. See os_list()
for example on osfamily_name. This makes it easier to sift through the
lists of IP if you are trying to split up IP addresses
depending on platform (window and unix machines for example).

=item B<filter_by_status($status)>

This returns an array of hosts addresses that are in the $status state.
$status can be either 'up' or 'down'. Default is 'up'.

=item B<get_scaninfo()>

Returns the current Nmap::Parser::ScanInfo.
Methods can be called on this object to retrieve information
about the parsed scan. See L<Nmap::Parser::ScanInfo> below.

=item B<sort_ips(@ips)>

Given an array of IP addresses, it returns an array of IP addresses which is
correctly sorted according to the network address. An example would be that
10.99.99.99 would come before 10.100.99.99. It takes each quad from an IP
address and compares it to corresponding quad number on the other IP address.
(So 99 would come before 100).


Methods can be called on this object to retrieve information
about the parsed scan. See L<Nmap::Parser::ScanInfo> below.


=back

=head2 Nmap::Parser::ScanInfo

The scaninfo object. This package contains methods to easily access
all the parameters and values of the Nmap scan information ran by the
currently parsed xml file or filehandle.

 $si = $np->get_scaninfo();
 print 	'Nmap Version: '.$si->nmap_version()."\n",
 	'Num of Scan Types: '.(join ',', $si->scan_types() )."\n",
 	'Total time: '.($si->finish_time() - $si->start_time()).' seconds';
 	#... you get the idea...

=over 4

=item B<num_of_services([$scan_type])>;

If given a corresponding scan type, it returns the number of services
that was scan by nmap for that scan type. If $scan_type is omitted,
then num_of_services() returns the total number of services scan by all
scan_types.

=item B<start_time()>

Returns the start time of the nmap scan. This is given in UNIX time_t notation.

=item B<start_str()>

Returns the human readable calendar time format of when a scan started

=item B<finish_time()>

Returns the finish time of the nmap scan. This is given in UNIX time_t notation.

=item B<time_str()>

Returns the human readable calendar time format of when a scan finished.

=item B<nmap_version()>

Returns the version of nmap that ran.

=item B<xml_version()>

Returns the xml-output version of nmap-xml information.

=item B<args()>

Returns the command line parameters that were run with nmap

=item B<scan_types()>

Returns an array containing the names of the scan types that were selected.

=item B<proto_of_scan_type($scan_type)>

Returns the protocol of the specific scan type.

=back

=head2 Nmap::Parser::Host

The host object. This package contains methods to easily access the information
of a host that was scanned.

  $host_obj = Nmap::Parser->get_host($ip_addr);
   #Now I can get information about this host whose ip = $ip_addr
   print
  'Hostname: '.$host_obj->hostnames(1),"\n",
  'Address:  '.$host_obj->addr()."\n",
  'OS match: '.$host_obj->os_match()."\n",
  'Last Reboot: '.($host_obj->uptime_lastboot,"\n";
  #... you get the idea...

If you would like for me to add more advanced information (such as
TCP Sequences), let me know.

=over 4

=item B<status()>

Returns the status of the host system. Either 'up' or 'down'

=item B<addr()>

Returns the IPv4 address of the system.

=item B<ipv4_addr()>

Explicitly returns the IPv4 address of the system

=item B<mac_addr()>

Explicitly returns the MAC (Media Access Control) address of the system.

I<Note: This only shows up if you ran the nmap scan with the '-A' switch
(present only in nmap 3.55+)>

=item B<mac_vendor()>

Returns the vendor of the MAC (Media Access Control) card of the system.
Example: Netgear, Compaq ... etc.

I<Note: This only shows up if you ran the nmap scan with the '-A' switch
(present only in nmap 3.55+)>

=item B<addrtype()>

Returns the address type of the IP address returned
by addr(). Ex. 'ipv4'

=item B<hostname()>

Returns the first hostname found of the current host object. This is a short-cut
to using hostnames(1).

 $host_obj->hostname() eq $host_obj->hostnames(1) #Always true

=item B<hostnames($number)>

If $number is omitted (or false), returns an array containing all of
the host names. If $number is given, then returns the host name in that
particular index. The index starts at 1.

 $host_obj->hostnames();  #returns an array containing the hostnames found
 $host_obj->hostnames(1); #returns the 1st hostname found
 $host_obj->hostnames(4); #returns the 4th. (you get the idea..)

=item B<extraports_state()>

Returns the state of the extra ports found by nmap. I<(The 'state' attribute
in the extraports tag)>.

=item B<extraports_count()>

Returns the number of extra ports that nmap found to be in a given state. I<(The
'count' attribute in the extraports tag)>.

=item B<tcp_ports([$state])>, B<udp_ports([$state])>

Returns an sorted array containing the tcp/udp ports that were scanned. If the
optional 'state' paramter is passed, it will only return the ports that nmap
found to be in that state.The value of $state can either be 'closed', 'filtered'
 or 'open'.  I<NOTE: If you used a parsing filter such as setting portinfo => 0,
then all ports will return undef.>

 my @ports = $host_obj->tcp_ports; #all ports
 my $port = pop @ports;

 if($host_obj->tcp_port_state($port) ne 'closed'){

	 $host_obj->tcp_service_name($port);  #ex: rpcbind
	 $host_obj->tcp_service_proto($port); #ex: rpc (may not be defined)
	 $host_obj->tcp_service_rpcnum($port);#ex: 100000 (only if proto is rpc)
 }

Again, you could filter what ports you wish to receive:

 #it can be either 'open', 'filtered', 'closed'

 my @filtered_ports = $host_obj->tcp_ports('filtered');
 my @open_ports = $host_obj->tcp_ports('open');

It is important to note that ports that have been identified as 'open|filtered' or 'closed|filtered'
will be counted as both 'open' and 'filtered'. If you specifically want only ports
that have the identifier of 'open|filtered', then you must specifically state:
C<tcp_port('open|filtered')> or C<udp_port('closed|filtered')> (for example).

=item B<tcp_ports_count()>, B<udp_ports_count()>

Returns the number of tcp/udp ports found. This is a short-cut function (but
more efficient) to:

 scalar @{[$host->tcp_ports]} == $host->tcp_ports_count;

=item B<tcp_port_state($port)>, B<udp_port_state($port)>

Returns the state of the given tcp/udp port. I<NOTE> that if PORTINFO filter is used, all ports states
are set to closed.

=item B<tcp_service_confidence($port)>, B<udp_service_confidence($port)>

Returns the confidence level of the accuracy of port/service information.

=item B<tcp_service_extrainfo($port)>, B<udp_service_extrainfo($port)>

Returns any extra information about the running service. This information is
usually available when the scan performed was version scan (-sV).

I<NOTE> This attribute is only available in new versions of nmap (3.40+).

=item B<tcp_service_method($port)>, B<udp_service_method($port)>

Returns the method information of the given service on the specificed $port number.

=item B<tcp_service_name($port)>, B<udp_service_name($port)>

Returns the name of the service running on the
given tcp/udp $port. (if any)

=item B<tcp_service_owner($port)>, B<udp_service_owner($port)>

Returns the owner information of the given $port number. Note that this is not
available unless the nmap scan was run with the ident scanning option.

=item B<tcp_service_product($port)>, B<udp_service_product($port)>

Returns the product content of the service running on the
given tcp/udp $port. (if any)

I<NOTE> This attribute is only available in new versions of nmap (3.40+).

=item B<tcp_service_proto($port)>, B<udp_service_proto($port)>

Returns the protocol type of the given port. This can be tcp, udp, or rpc as
given by nmap.

=item B<tcp_service_rpcnum($port)>, B<udp_service_rpcnum($port)>

Returns the rpc number of the service on the given port. I<This value only
exists if the protocol on the given port was found to be RPC by nmap.>

=item B<tcp_service_tunnel($port)>, B<udp_service_tunnel($port)>

Returns the tunnel information of the given service on the specificed $port number.

=item B<tcp_service_version($port)>, B<udp_service_version($port)>

Returns the version content of the service running on the
given tcp/udp $port. (if any)

I<NOTE> This attribute is only available in new versions of nmap (3.40+).

=item B<os_match>

Same as os_matches(), except this is a short-cut function for obtaining the
first OS guess provided by nmap. The statements are equivalent:

 $host_obj->os_matches(1) eq $host_obj->os_match() #true

=item B<os_matches([$number])>

If $number is omitted, returns an array of possible matching os names.
If $number is given, then returns that index entry of possible os names.
The index starts at 1.

 $host_obj->os_matches();  #returns an array containing the os names found
 $host_obj->os_matches(1); #returns the 1st os name found
 $host_obj->os_matches(5); #returns the 5th. (you get the idea...)

=item B<os_port_used($state)>

Returns the port number that was used in determining the OS of the system.
If $state is set to 'open', then the port id that was used in state open is
returned. If $state is set to 'closed', then the port id that was used in state
closed is returned. (no kidding...). Default, the open port number is returned.

=item B<os_accuracy([$number])>

Returns the accuracy of OS detection for the given machine. The index starts at
1.

=item B<os_family()>

Returns the osfamily_name(s) that was matched to the given host. It is comma
delimited. This osfamily value is determined by the list given in the
*_osfamily_list() functions. (Example of value: 'solaris,unix')

I<Note: see set_osfamily_list()>

=item B<os_class([$number])>

Returns the os_family, os_generation and os_type that was guessed by nmap. The
os_class tag does not always appear in all nmap OS fingerprinting scans. This
appears in newer nmap versions. You should check to see if there are values to
this. If you want a customized (and sure) way of determining an os_family value
use the *_osfamily_list() functions to set them. These will determine what
os_family value to give depending on the osmatches recovered from the scan.

There can be more than one os_class (different kernels of Linux for example).
In order to access these extra os_class information, you can pass an index
number to the function. If no number is given, the total number of osclass
tags parsed will be returned. The index starts at 1.

  #returns the first set
 $num_of_os_classes = $host_obj->os_class();

  #returns the first set (same as passing no arguments)
 ($os_family,$os_gen,$os_vendor,$os_type) = $host_obj->os_class(1);

  #returns os_gen value only. Example: '2.4.x' if is a Linux 2.4.x kernel.
  $os_gen                      = ($host_obj->os_class())[2];# os_gen only

You can play with perl to get the values you want easily.

I<Note: This tag is usually available in new versions of nmap. You can define
your own os_family customizing the os_family lists using the
Nmap::Parser functions: set_osfamily_list() and get_osfamily_list().>

=item B<os_osfamily([$number])>

Given a index number, it returns the osfamily value of that given osclass
information. The index starts at 1.

=item B<os_gen([$number])>

Given a index number, it returns the os-generation value of that given osclass
information. The index starts at 1.

=item B<os_vendor([$number])>

Given a index number, it returns the os vendor value of that given osclass
information. The index starts at 1.

=item B<os_type([$number])>

Given a index number, it returns the os type value of that given osclass
information. Usually this is nmap's guess on how the machine is used for.
Example: 'general purpose', 'web proxy', 'firewall'. The index starts at 1.

=item B<tcpsequence_class()>

Returns the tcpsequence class information.

=item B<tcpsequence_values()>

Returns the tcpsequence values information.

=item B<tcpsequence_index()>

Returns the tcpsequence index information.

=item B<ipidsequence_class()>

Returns the ipidsequence class information

=item B<ipidsequence_values()>

Returns the ipidsequence values information

=item B<tcptssequence_class()>

Returns the tcptssequence class information.

=item B<tcptssequence_values()>

Returns the tcptssequence values information.

=item B<uptime_seconds()>

Returns the number of seconds the host has been up (since boot).

=item B<uptime_lastboot()>

Returns the time and date the given host was last rebooted.

=back

=head1 EXAMPLES

These are a couple of examples to help you create custom security audit tools
using some of the features of the Nmap::Parser module.

=head2 Using ParseScan

You can run an nmap scan and have the parser parse the information automagically.
The only thing is that you cannot use '-oX', '-oN', or '-oG' as one of your
arguments for the nmap command line options passed to parsescan().

 use Nmap::Parser;

 my $np = new Nmap::Parser;
 #this is a simple example (no input checking done)

 my @hosts = @ARGV; #Get hosts from stdin

 #runs the nmap command with hosts and parses it at the same time
 $np->parsescan('nmap','-sS O -p 1-1023',@hosts);

 for my $host ($np->get_host_objects()){
 	
 	#$host is an Nmap::Parser::Host object
 	print $host->hostname."\n";
 	
 }

=head2 Using Register-Callback

This is probably the easiest way to write a script with using Nmap::Parser,
if you don't need the general scan information. During the parsing process, the
parser will obtain information of every host from the xml scan output. The
callback function is called after completely parsing a single host. When the
callback returns (or you finish doing what you need to do for that host), the
parser will delete all information of the host it had sent to the callback. This
callback function is called for every host that the parser encounters.

 use Nmap::Parser;
 my $np = new Nmap::Parser;

 #NOTE: the callback function must be setup before parsing beings
 $np->register_host_callback( \&my_function_here );

 #parsing will begin
 $np->parsefile('scanfile.xml');

 sub my_function_here {
	 #you will receive a Nmap::Parser::Host object for the current host
	 #that has just been finished scanned (or parsing)

     my $host = shift;
     print 'Scanned IP: '.$host->addr()."\n";
	 # ... do more stuff with $host ...

	 #when this function returns, the Nmap::Parser will delete the host
	 #from memory
 }

=head2 Multiple Instances

This is another way of using Nmap::Parser using multiple instances, for example, to check for host states.
In this example, we have a set of hosts that have been scanned for tcp services and saved in
I<base_image.xml>. We now will scan the same hosts, and compare if any new tcp have been open since then
(good way to look for suspicious new services). Easy security compliance detection.


 use Nmap::Parser;
 my $base = new Nmap::Parser;
 my $curr = new Nmap::Parser;
 
 
 $base->parsefile('base_image.xml'); #load previous state
 $curr->parsescan($nmap_exe,$args,@ips); #scan current hosts
 
 for my $ip ($curr->get_host_list()) #all ips scanned
 {
 	#assume that IPs in base == IPs in curr scan
 	my $ip_base = $base->get_host($ip);
 	my $ip_curr = $curr->get_host($ip);
 	my %port = ();
 	
 	#find ports that are open that were not open before
 	#by finding the difference in port lists
	my @diff =  grep { $port{$_} < 2} 
		   (map {$port{$_}++; $_} 
		   ($ip_curr->tcp_ports('open'),$ip_base->tcp_ports('open')));
	
	print "$ip has these new ports open: ".join(',',@diff) if(scalar @diff);
 		
 }
 

=head1 BUG REPORTS AND SUPPORT

Please submit any bugs to:
L<http://sourceforge.net/tracker/?group_id=97509&atid=618345>

Please make sure that you submit the xml-output file of the scan which you are having
trouble. This can be done by running your scan with the I<-oX filename.xml> nmap switch.
Please remove any important IP addresses for security reasons.

=head1 PATCHES AND FEATURE REQUESTS

Please submit any requests to:
L<http://sourceforge.net/tracker/?atid=618348&group_id=97509&func=browse>

=head1 SEE ALSO

 nmap, L<XML::Twig>

The Nmap::Parser page can be found at: L<http://www.nmapparser.com> or L<http://npx.sourceforge.net>.
It contains the latest developments on the module. The nmap security scanner
homepage can be found at: L<http://www.insecure.org/nmap/>. This project is also
on sourceforge.net: L<http://sourceforge.net/projects/npx/>

=head1 CONTRIBUTIONS

Thank you to all who have contributed to the module (bug fixes or suggestions),
and special thanks to the gurus below:

Jeremy Stiffler
Sebastian Wolfgarten
Vince Stratful
Oddbjorn Steffensen

=head1 AUTHOR

Anthony G Persaud <ironstar@iastate.edu> L<http://www.anthonypersaud.com>

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
