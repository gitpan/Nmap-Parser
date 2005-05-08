use 5.004;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my %depends = (XML::Twig   => 3.16,
               Storable    => 2);

WriteMakefile(
    ABSTRACT		=> 'Nmap output parser for scan data',
    AUTHOR		=> 'Anthony G Persaud (ironstar@iastate.edu)',
    clean		=> {FILES => "*.tar *.old pod2htm*"},
   # EXE_FILES   	=> [ map {"examples/$_/$_"} @programs], #soon
    NAME		=> 'Nmap::Parser',
    PREREQ_PM		=> \%depends,
    VERSION_FROM	=> 'Parser.pm' # finds $VERSION
	);


