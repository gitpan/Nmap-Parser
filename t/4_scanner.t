#!/usr/bin/perl



use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 2;
use constant IP => '127.0.0.1';
use Nmap::Parser;
no warnings;
use vars qw($t1 $t2);
$|=1;

my $p = new Nmap::Parser;
can_ok($p,'parsescan');
my $nmap_path = find_nmap();

SKIP:
    {
skip 'Nmap-Parser: Could not find nmap executable in path',1 if($nmap_path eq '');
ok($nmap_path,"Exe Path: $nmap_path");
#I will add more test later on
}

sub find_nmap {

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
            #  Should symbolic link be considered?  Helps me on cygwin but ...
            next unless -r $path && (-x _ || -l _);

            return $path;
            last DIR;
        }
    }

}