use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
my %depend = (XML::Parser => 2.3,
              XML::Twig   => 3.09
              );

for my $mod (keys %depend){
eval 'require '.$mod;

if($@){print "-- ".$mod." needs to be installed!\n";}
else {printf("%-15s : v%.2f \n",$mod,(eval eval '$'.$mod.'::VERSION'));   }
}

WriteMakefile(
    'NAME'		=> 'Parse::Nmap::XML',
    'VERSION_FROM'	=> 'XML.pm', # finds $VERSION
    'PREREQ_PM'		=> \%depend,
    'ABSTRACT'		=> 'Nmap parse for xml-scan output files',
    'AUTHOR'	       => 'Anthony G Persaud <ironstar@iastate.edu>'
	);


