package Nmap::Parser::XML;

################################################################################
##			Nmap::Parser::XML				      ##
################################################################################

use strict;
require 5.004;
use XML::Twig;
use Nmap::Parser;

use vars qw(@ISA);
our $VERSION = '0.75';
@ISA = qw(Nmap::Parser);

sub new {

    my $class = shift;
    my $self = $class->SUPER::new();
    return bless $self, $class;

}

################################################################################
##			Nmap::Parser::XML::ScanInfo			      ##
################################################################################
package Nmap::Parser::XML::ScanInfo;
use vars qw(@ISA);
@ISA = qw(Nmap::Parser::ScanInfo);

sub new {

    my $class = shift;
    my $self = $class->SUPER::new();
    return bless $self, $class;

}


################################################################################
##			Nmap::Parser::XML::Host				      ##
################################################################################
package Nmap::Parser::XML::Host;
use vars qw(@ISA);
@ISA = qw(Nmap::Parser::Host);

sub new {

    my $class = shift;
    my $self = $class->SUPER::new();
    return bless $self, $class;

}

__END__


=pod

=head1 NAME

Nmap::Parser::XML - backward compatibility version of the nmap parser

=head1 SYNOPSIS

Please see L<Nmap::Parser> instead.

=head1 DESCRIPTION

L<Nmap::Parser::XML> is now considered the legacy version of the parsing module.
It has now been replaced with L<Nmap::Parser>. This module is included in this
package for backward support of old scripts using the L<Nmap::Parser::XML> module
instead of L<Nmap::Parser>. If you have old scripts using the L<Nmap::Parser::XML>
module, please update them and replace the 'use' statement to use L<Nmap::Parser>
instead.

For the actual documentation of how to use the parser, please see the
L<Nmap::Parser> documentation.

=head1 BUG REPORTS AND SUPPORT

Please submit any bugs to:
L<http://sourceforge.net/tracker/?group_id=97509&atid=618345>

=head1 SEE ALSO

 nmap, L<XML::Twig>, L<Nmap::Parser>

The Nmap::Parser page can be found at: L<http://npx.sourceforge.net/>.
It contains the latest developments on the module. The nmap security scanner
homepage can be found at: L<http://www.insecure.org/nmap/>. This project is also
on sourceforge.net: L<http://sourceforge.net/projects/npx/>

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
