package Parse::Nmap::XML;

################################################################################
##			Parse::Nmap::XML				      ##
################################################################################

use strict;
require 5.004;
use XML::Twig;
use vars qw($S %H %OS_LIST %F $DEBUG);
use constant IGNORE_ADDPORT => 1;
use constant IGNORE_EXTRAPORTS => 1;


our $VERSION = '0.63';

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
		addport 	=> IGNORE_ADDPORT,
		extraports 	=> IGNORE_EXTRAPORTS,
		}

		);

#Default Filter Values
reset_filters();

%OS_LIST = (
	solaris => [qw(solaris sparc sunos)],
	linux 	=> [qw(linux mandrake redhat slackware)],
	unix 	=> [qw(unix hp-ux hpux bsd immunix aix)],
	win  	=> [qw(win microsoft)],
	mac 	=> [qw(mac osx)],
	switch 	=> [qw(ethernet cisco netscout router switch)],
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
	'addport'	=> IGNORE_ADDPORT,
	'extraports'	=> IGNORE_EXTRAPORTS,
	'ports' 	=> ($F{portinfo} ? undef : 1),
	'tcpsequence' 	=> ($F{sequences} ? undef : 1),
	'ipidsequence' 	=> ($F{sequences} ? undef : 1),
	'tcptssequence' => ($F{sequences} ? undef : 1),
	'uptime' 	=> ($F{uptime} ? undef : 1),
	'scaninfo' 	=> ($F{scaninfo} ? undef : 1),
	'finished' 	=> ($F{scaninfo} ? undef : 1),
	'nmaprun' 	=> ($F{scaninfo} ? undef : 1)
	});

return \%F;

}

sub reset_filters {
%F = (
	osfamily 	=> 1,
	scaninfo	=> 1,
	only_active 	=> 0,
	sequences 	=> 1,
	portinfo	=> 1,
	uptime		=> 1
	);


$_[0]->{twig}->setIgnoreEltsHandlers({
	addport 	=> IGNORE_ADDPORT,
	extraports 	=> IGNORE_EXTRAPORTS,
	}) if(ref($_[0]) eq __PACKAGE__);


return \%F;

}


################################################################################
##			PARSE METHODS					      ##
################################################################################
sub parse {%H =();$S = undef;shift->{twig}->parse(@_);}
sub parsefile {%H=();$S = undef;shift->{twig}->parsefile(@_);}
sub safe_parse {%H=();$S = undef;shift->{twig}->safe_parse(@_);}
sub safe_parsefile {%H=();$S = undef;shift->{twig}->safe_parsefile(@_);}
sub clean {%H = ();$S = undef;$_[0]->{twig}->purge;return $_[0];}

################################################################################
##			POST-PARSE METHODS				      ##
################################################################################

sub get_host_list {my $status = lc($_[1]);
if($status eq 'up' || $status eq 'down')
{return (grep {($H{$_}{status} eq $status)}(keys %H))};
return (keys %H);
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
return @os_matched_ips;

}

sub filter_by_status {
my $self= shift;
my $status = lc(shift);
$status = 'up' if($status ne 'up' && $status ne 'down');
return (grep {$H{$_}{status} eq $status} (keys %H));
}


sub get_scaninfo {return $S;}


################################################################################
##			PRIVATE TWIG HANDLERS				      ##
################################################################################

sub _scaninfo_hdlr {
my ($twig,$scan) = @_;
my ($type,$proto,$num) = ($scan->att('type'),$scan->att('protocol'),$scan->att('numservices'));
if(defined($type)){$S->{type}{$type} = $proto;$S->{numservices}{$type} = $num;}
$twig->purge;}


sub _nmaprun_hdlr {#Last tag in an nmap output
my ($twig,$host) = @_;
unless($F{scaninfo}){$twig->ignore;return;}
$S->{start_time} = $host->att('start');
$S->{nmap_version} = $host->att('version');
$S->{args} = $host->att('args');
$S = Parse::Nmap::XML::ScanInfo->new($S);

$twig->purge;
}


sub _finished_hdlr {my ($twig,$host) = @_;$S->{finish_time} = $host->att('time');$twig->purge;}


sub _host_hdlr {
my($twig, $host)= @_; # handlers are always called with those 2 arguments
my ($addr,$tmp);
    if(not defined($host)){return undef;}
    $tmp        = $host->first_child('address');         # get the element text
    if(not defined $tmp){return undef;}
    $addr = $tmp->att('addr');
    if(!defined($addr) || $addr eq ''){return undef;}
    $H{$addr}{addr} = $addr;
    $H{$addr}{addrtype} = $tmp->att('addrtype');
    $tmp = $host->first_child('hostnames');
    @{$H{$addr}{hostnames}} = _hostnames_hdlr($tmp,$addr) if(defined ($tmp = $host->first_child('hostnames')));
    $H{$addr}{status} = $host->first_child('status')->att('state');
    if($H{$addr}{status} eq 'down')
    {$twig->purge;
	if($F{only_active})
	{delete $H{$addr};}
    	else { $H{$addr} = Parse::Nmap::XML::Host->new($H{$addr});}
    	return;}

    $H{$addr}{ports} = _port_hdlr($host,$addr) if($F{portinfo});
    $H{$addr}{os} = _os_hdlr($host,$addr);
    $H{$addr}{uptime} = _uptime_hdlr($host,$addr) if($F{uptime});

    	if($F{sequences})
	{
	    $H{$addr}{tcpsequence} = _tcpsequence($host,$addr);
	    $H{$addr}{ipidsequence} = _ipidsequence($host,$addr);
	    $H{$addr}{tcptssequence} = _tcptssequence($host,$addr);
	}

    $H{$addr} = Parse::Nmap::XML::Host->new($H{$addr});
    $twig->purge;                                      # purges the twig

}

sub _port_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my ($host,$addr) = (shift,shift);
my ($tmp,@list);
$tmp = $host->first_child('ports');
unless(defined $tmp){return undef;}
@list= $tmp->children('port');
for my $p (@list){
my $proto = $p->att('protocol');
my $portid = $p->att('portid');
if(defined($proto && $portid)){$H{$addr}{ports}{$proto}{$portid} =
				_service_hdlr($host,$addr,$p);}

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
$tmp->{service_name} = $s->att('name');
$tmp->{service_proto} = $s->att('proto') if($s->att('proto'));
$tmp->{service_rpcnum} = $s->att('rpcnum') if($tmp->{service_proto} eq 'rpc');
}

return $tmp;

}

sub _os_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my ($host,$addr) = (shift,shift);
my ($tmp,@list);
if(defined(my $os_list = $host->first_child('os'))){
    $tmp = $os_list->first_child("portused[\@state='open']");
    $H{$addr}{os}{portused}{'open'} = $tmp->att('portid') if(defined $tmp);
    $tmp = $os_list->first_child("portused[\@state='closed']");
    $H{$addr}{os}{portused}{'closed'} = $tmp->att('portid') if(defined $tmp);


    for my $o ($os_list->children('osmatch')){push @list, $o->att('name');  }
    @{$H{$addr}{os}{names}} = @list;

    $H{$addr}{os}{osfamily_names} = _match_os(@list) if($F{osfamily});

    @list = ();
    for my $o ($os_list->children('osclass'))
    {push @list, [$o->att('osfamily'),$o->att('osgen'),$o->att('vendor'),$o->att('type')];}
    @{$H{$addr}{os}{osclass}} = @list;

    }

    return $H{$addr}{os};

}


sub _uptime_hdlr {
my ($host,$addr) = (shift,shift);
my $uptime = $host->first_child('uptime');
my $hash;
if(defined $uptime){
	$hash->{seconds} = $uptime->att('seconds');
	$hash->{lastboot} = $uptime->att('lastboot');
}
return $hash;
}


sub _hostnames_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my $hostnames = shift;
my $addr = shift;
my @names;
for my $n ($hostnames->children('hostname')) {push @names, $n->att('name');}
return @names if(wantarray);
return \@names;

}

sub _tcpsequence {
my ($host,$addr) = (shift,shift);
my $temp;
my $seq = $host->first_child('tcpsequence');
unless($seq){return undef;}

return [$seq->att('class'),$seq->att('values'),$seq->att('index')];

}

sub _ipidsequence {
my ($host,$addr) = (shift,shift);
my $temp;
my $seq = $host->first_child('ipidsequence');
unless($seq){return undef;}
return [$seq->att('class'),$seq->att('values')];

}


sub _tcptssequence {
my ($host,$addr) = (shift,shift);
my $temp;
my $seq = $host->first_child('tcptssequence');
unless($seq){return undef;}
return [$seq->att('class'),$seq->att('values')];
}

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
if(scalar @matches){return (join ',', sort keys %{ {map {$_,1} @matches} } );}
return 'other';

}


################################################################################
##			Parse::Nmap::XML::ScanInfo			      ##
################################################################################

package Parse::Nmap::XML::ScanInfo;

sub new {
my $class = shift;
$class = ref($class) || $class;
my $self =  shift || {};
bless ($self,$class);
return $self;
}

sub num_of_services {
if($_[1] ne ''){return $_[0]->{numservices}{$_[1]};}
else {my $total = 0;for (values %{$_[0]->{numservices}}){$total +=$_;}
return $total;}
}
sub finish_time {return $_[0]->{finish_time};}
sub nmap_version {return $_[0]->{nmap_version};}
sub args {return $_[0]->{args};}
sub start_time {return $_[0]->{start_time};}
sub scan_types {(wantarray) ? 	return (keys %{$_[0]->{type}}) :
				return scalar(keys %{$_[0]->{type}});}
sub proto_of_scan_type {return $_[0]->{type}{$_[1]};}


################################################################################
##			Parse::Nmap::XML::Host				      ##
################################################################################

package Parse::Nmap::XML::Host;


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
sub hostnames {($_[1]) ? 	return @{$_[0]->{hostnames}}[ $_[1] - 1] :
				return @{$_[0]->{hostnames}};}
sub tcp_ports {(wantarray) ? 	return (keys %{$_[0]->{ports}{tcp}}) :
				return $_[0]->{ports}{tcp};}
sub udp_ports {(wantarray) ? 	return (keys %{$_[0]->{ports}{udp}}) :
				return $_[0]->{ports}{udp};}
sub tcp_service_name {return $_[0]->{ports}{tcp}{$_[1]}{service_name};}
sub udp_service_name {return $_[0]->{ports}{udp}{$_[1]}{service_name};}
sub os_matches {($_[1]) ? 	return @{$_[0]->{os}{names}}[ $_[1] - 1 ] :
				return (@{$_[0]->{os}{names}});}
sub os_port_used {
$_[1] ||= 'open';
if(lc($_[1]) eq 'closed'){return $_[0]->{os}{portused}{'closed'};}
elsif(lc($_[1]) eq 'open'){  return $_[0]->{os}{portused}{'open'};}
}

sub os_family {(wantarray) ? 	return (split ',', $_[0]->{os}{osfamily_names}) :
				return $_[0]->{os}{osfamily_names};}

sub os_class {
if($_[1] eq ''){return @{@{$_[0]->{os}{osclass}}[0]}}
elsif(lc($_[1]) eq 'total'){return scalar @{$_[0]->{os}{osclass}};}
elsif($_[1] ne ''){return @{@{$_[0]->{os}{osclass}}[$_[1] - 1]};}

	}

sub tcpsequence {return @{$_[0]->{tcpsequence}}    if($_[0]->{tcpsequence});}
sub ipidsequence {return @{$_[0]->{ipidsequence}}  if($_[0]->{ipidsequence});}
sub tcptssequence {return @{$_[0]->{tcptssequence}} if($_[0]->{tcptssequence});}

sub uptime_seconds {return $_[0]->{uptime}{seconds};}
sub uptime_lastboot {return $_[0]->{uptime}{lastboot};}

1;

__END__

=pod

=head1 NAME

Parse::Nmap::XML - parser for nmap xml scan data using perl.

=head1 SYNOPSIS

  use Parse::Nmap::XML;

 	#PARSING
  my $p = new Parse::Nmap::XML;
  $p->parse($fh); #filehandle or nmap xml output string
  #or $p->parsefile('nmap_output.xml') for files

 	#GETTING SCAN INFORMATION
  print "Scan Information:\n";
  $si = $p->get_scaninfo();
  #Now I can get scan information by calling methods
  print
  'Number of services scanned: '.$si->num_of_services()."\n",
  'Start Time: '.$si->start_time()."\n",
  'Scan Types: ',(join ' ',$si->scan_types())."\n";

 	#GETTING HOST INFORMATION
   print "Hosts scanned:\n";
   for my $ip ($p->get_host_list()){
   $host_obj = Parse::Nmap::XML->get_host($ip);
   print
  'Hostname: '.($host_obj->hostnames())[0],"\n",
  'Address: '.$host_obj->addr()."\n",
  'OS matches: '.(join ',', $host_obj->os_matches())."\n",
  'Last Reboot: '.($host_obj->uptime_lastboot,"\n";
  	#... you get the idea...
   }

  print "\n\nUnix Flavor Machines:\n";
  for ($p->filter_by_osfamily('linux','solaris','unix')){print;}

  print "\n\nAnd for those who like Windows:\n";
  for ($p->filter_by_osfamily('win')){print;}

  $p->clean(); #frees memory


=head1 DESCRIPTION

This is an XML parser for nmap XML reports. This uses the XML::Twig library
which is fast and more memory efficient than using the XML::SAX::PurePerl that
comes with Nmap::Scanner::Scanner. This module, in the authors opinion, is
easier to use for basic information gathering of hosts.

This module is meant to be a balance of easy of use and efficiency. (more ease
of use). If you need more information from an nmap xml-output that is not
available in the release, please send your request. (see below).

=head3 OVERVIEW

Using this module is very simple. (hopefully).

=item I<Set your Options>

You first set any filters you want on the information you will parse. This
is optional, but if you wish the parser to be more efficient, don't parse
information you don't need. Other options (os_family) can be
set also. (See Pre-Parse methods)

Example, if you only want to retain the information of the hosts that nmap
found to be up (active), then set the filter:

 $obj->parse_filters({only_active => 1});

Usually you won't have much information about hosts that are down from nmap
anyways.

=item I<Parse the Info>

Parse the info. You use $obj->parse() or $obj->parsefile(), to parse the nmap xml
information. This information is parsed and constructed internally.

=item I<Get the Scan Info>

Use the $si = $obj->get_scaninfo() to obtain the
Parse::Nmap::XML::ScanInfo object. Then you can call any of the
ScanInfo methods on this object to retrieve the information. See
Parse::Nmap::XML::ScanInfo below.

=item I<Get the Host Info>

Use the $obj->get_host($addr) to obtain the Parse::Nmap::XML::Host object of the
current address. Using this object you can call any methods in the Host object
to retrieve the information that nmap obtained from this scan.

 $obj->get_host($ip_addr);

You can use any of the other methods to filter or obtain
different lists.

 	#returns all ip addresses that were scanned
 $obj->get_host_list()

 	#returns all ip addresses that have osfamily = $os
 $obj->filter_by_osfamily($os)
	 #See get_os_list() and set_os_list()
	 #etc. (see other methods)

	#returns all host objects from the information parsed.
	#All are Parse::Nmap::XML::Host objects
 $obj->get_host_objects()


=item I<Clean up>

This is semi-optional. When files are not that long, this is optional.
If you are in a situation with memory constraints and are dealing with large
nmap xml-output files, this little effort helps. After you are done with everything, you should do a $obj->clean()
to free up the memory used by maintaining the scan and hosts information
from the scan. A much more efficient way to do is, once you are done using a
host object, delete it.

 		#Getting all IP addresses parsed
 for my $host ($obj->get_host_list())
 	{	#Getting the host object for that address
	my $h = $obj->get_host($host);
		#Calling methods on that object
	print "Addr: $host  OS: ".(join ',',$h->os_matches())."\n";
	$obj->del_host($host); #frees memory
	}

	#Or when you are done with everything use $obj->clean()
Or you could skip the $obj->del_host(), and after you are done, perform a
$obj->clean() which resets all the internal trees. Of course there are much
better ways to clean-up (using perl idioms).

=head1 METHODS

=head2 Pre-Parsing Methods

=over 4

=item B<new()>

Creates a new Parse::Nmap::XML object with default handlers and default
osfamily list.

=item B<set_osfamily_list($hashref)>

Decides what is the osfamily name of the given system.

Takes in a hash refernce that referes to pairs of osfamily names to their
keyword list. Shown here is the default. Calling this method will overwrite the
whole list, not append to it. Use C<get_osfamily_list()> first to get the current
listing.

  $obj->set_osfamily_list({
  	solaris => [qw(solaris sparc sunos)],
        linux 	=> [qw(linux mandrake redhat slackware)],
        unix 	=> [qw(unix hp-ux hpux bsd immunix aix)],
        win  	=> [qw(win microsoft)],
	mac 	=> [qw(mac osx)],
	switch 	=> [qw(ethernet cisco netscout router switch)],
	    });

example: osfamily_name = solaris if the os string being matched
matches (solaris, sparc or sunos) keywords

The reason for having this seprately that relying on the 'osclass' tag in the
xml output is that the 'osclass' tag is not generated all the time. Usually
new versions of nmap will generate the 'osclass' tags. These will be available
through the Parse::Nmap::XML::Host methods. (See below).

=item B<get_osfamily_list()>

Returns a hashre containing the current osfaimly names (keys) and
an arrayref pointing to the list of corresponding keywords (values).
See C<set_osfamily_list()> for an example.

=item B<parse_filters($hashref)>

This function takes a hash reference that will set the corresponding filters
when parsing the xml information. All filter names passed will be treated
as case-insensitive.

 $obj->parse_filters({
 	osfamily 	=> 1, #same as any variation. Ex: osfaMiLy
 	only_active	=> 0   #same here
 		});

=item I<OSFAMILY>

If set to true, (the default), it will match the OS guessed by nmap with a
osfamily name that is given in the OS list. See L<set_osfamily_list()>. If
false, it will disable this matching (a bit of speed up in parsing).

=item I<ONLY_ACTIVE>

If set to true, it will ignore hosts that nmap found to be in state 'down'.
If set to perl-wise false, it will parse all the hosts. This is the default.
Note that if you do not place this filter, it will parse and store (in memory)
hosts that do not have much information. So calling a Parse::Nmap::XML::Host
method on one of these hosts that were 'down', will return undef.

=item I<SEQUENCES>

If set to true, parses the tcpsequence, ipidsequence and tcptssequence
information. This is the default.

=item I<PORTINFO>

If set to true, parses the port information. (You usually want this enabled).
This is the default.

=item I<SCANINFO>

If set to true, parses the scan information. This includes the 'scaninfo',
'nmaprun' and 'finished' tags. This is set to true by default. If you don't
care about the scan information of the file, then turn this off to enhance speed
and memory usage.

=item I<UPTIME>

If set to true, parses the uptime information (lastboot, uptime-seconds..etc).
This is the default.

=item B<reset_filters()>

Resets the value of the filters to the default values:

 osfamily 	=> 1
 scaninfo	=> 1
 only_active 	=> 0
 sequences 	=> 1
 portinfo	=> 1
 scaninfo	=> 1
 uptime		=> 1

=back 4

=head2 Parse Methods

=over 4

=item B<parse($source [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::parse().

This method is inherited from XML::Parser.  The "SOURCE" parameter should
either be a string containing the whole XML document, or it should be
an open "IO::Handle". Constructor options to "XML::Parser::Expat" given as
keyword-value pairs may follow the"SOURCE" parameter. These override, for this
call, any options or attributes passed through from the XML::Parser instance.

A die call is thrown if a parse error occurs. Otherwise it will return
the twig built by the parse. Use "safe_parse" if you want the
parsing to return even when an error occurs.

=item B<parsefile($filename [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::parsefile().

This method is inherited from XML::Parser. Open
"$filename" for reading, then call "parse" with the open
handle. The file is closed no matter how "parse" returns.

A die call is thrown if a parse error occurs. Otherwise it willreturn
the twig built by the parse. Use "safe_parsefile" if you want
the parsing to return even when an error occurs.

=item B<safe_parse($source [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::safe_parse().

This method is similar to "parse" except that it wraps the parsing
in an "eval" block. It returns the twig on success and 0 on failure (the twig
object also contains the parsed twig). $@ contains the error message on failure.

Note that the parsing still stops as soon as an error is detected,
there is no way to keep going after an error.


=item B<safe_parsefile($source [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::safe_parsefile().

This method is similar to "parsefile" except that it wraps the
parsing in an "eval" block. It returns the twig on success and 0 on
failure (the twig object also contains the parsed twig) . $@ contains the error
message on failure

Note that the parsing still stops as soon as an error is detected,
there is no way to keep going after an error.

=item B<clean()>

Frees up memory by cleaning the current tree hashes and purging the current
information in the XML::Twig object. Returns the Parse::Nmap::XML object.

=back 4

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
See L<Parse::Nmap::XML::Host>.

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

Returns the the current Parse::Nmap::XML::ScanInfo.
Methods can be called on this object to retrieve information
about the parsed scan. See L<Parse::Nmap::XML::ScanInfo> below.

=back 4


=head2 Parse::Nmap::XML::ScanInfo

The scaninfo object. This package contains methods to easily access
all the parameters and values of the Nmap scan information ran by the
currently parsed xml file or filehandle.

 $si = $obj->get_scaninfo();
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

Returns the start time of the nmap scan.

=item B<finish_time()>

Returns the finish time of the nmap scan.

=item B<nmap_version()>

Returns the version of nmap that ran.

=item B<args()>

Returns the command line parameters that were run with nmap

=item B<scan_types()>

In list context, returns an array containing the names of the scan types
that were selected. In scalar context, returns the total number of scan types
that were selected.

=item B<proto_of_scan_type($scan_type)>

Returns the protocol of the specific scan type.

=back 4


=head2 Parse::Nmap::XML::Host

The host object. This package contains methods to easily access the information
of a host that was scanned.

  $host_obj = Parse::Nmap::XML->get_host($ip_addr);
   #Now I can get information about this host whose ip = $ip_addr
   print
  'Hostname: '.$host_obj->hostnames(1),"\n",
  'Address: '.$host_obj->addr()."\n",
  'OS matches: '.(join ',', $host_obj->os_matches())."\n",
  'Last Reboot: '.($host_obj->uptime_lastboot,"\n";
  #... you get the idea...

If you would like for me to add more advanced information (such as
TCP Sequences), let me know.

=over 4


=item B<status()>

Returns the status of the host system. Either 'up' or 'down'

=item B<addr()>

Returns the IP address of the system

=item B<addrtype()>

Returns the address type of the IP address returned
by addr(). Ex. 'ipv4'

=item B<hostnames($number)>

If $number is omitted (or false), returns an array containing all of
the host names. If $number is given, then returns the host name in that
particular slot. (order). The slot order starts at 1.

 $host_obj->hostnames(0); #returns an array containing the hostnames found
 $host_obj->hostnames();  #same thing
 $host_obj->hostnames(1); #returns the 1st hostname found
 $host_obj->hostnames(4); #returns the 4th. (you get the idea..)

=item B<tcp_ports()>

In a list context, returns an array containing
the open tcp ports on the system. In a scalar
context, a hash reference of the tree branch is returned.

=item B<udp_ports()>

In a list context, returns an array containing
the open udp ports on the system. In a scalar
context, a hash reference of the tree branch is returned.

=item B<tcp_service_name($port)>

Returns the name of the service running on the
given tcp $port. (if any)

=item B<udp_service_name($port)>

Returns the name of the service running on the
given udp $port. (if any)

=item B<os_matches([$number])>

If $number is omitted, returns an array of possible matching os names.
If $number is given, then returns that slot entry of possible os names.
The slot order starts at 1.

 $host_obj->os_matches(0); #returns an array containing the os names found
 $host_obj->os_matches();  #same thing
 $host_obj->os_matches(1); #returns the 1st os name found
 $host_obj->os_matches(5); #returns the 5th. (you get the idea...)

=item B<os_port_used($state)>

Returns the port number that was used in determining the OS of the system.
If $state is set to 'open', then the port id that was used in state open is
returned. If $state is set to 'closed', then the port id that was used in state
closed is returned. (no kidding...). Default, the open port number is returned.

=item B<os_family()>

Returns the osfamily_name that was matched to the given host. This osfamily
value is determined by the list given in the *_osfamily_list() functions.

I<Note: see set_osfamily_list()>

=item B<os_class([$number])>
I<Experimental - interface might change in future releases>

Returns the os_family, os_generation and os_type that was guessed by nmap. The
os_class tag does not always appear in all nmap OS fingerprinting scans. This
appears in newer nmap versions. You should check to see if there are values to
this. If you want a customized (and sure) way of determining an os_family value
use the *_osfamily_list() functions to set them. These will determine what
os_family value to give depending on the osmatches recovered from the scan.

 ($os_family,$os_gen,$os_type) = $host_obj->os_class(); #returns the first set

There can be more than one os_class (different kernels of Linux for example).
In order to access these extra os_class information, you can pass an index
number to the function. If not number is given, the first os_class
information is returned. The slot order starts at 1.

  #returns the first set (same as passing no arguments)
 ($os_family,$os_gen,$os_vendor,$os_type) = $host_obj->os_class(1);

  #returns os_gen value only. Example: '2.4.x' if is a Linux 2.4.x kernel.
  $os_gen                      = ($host_obj->os_class())[2];# os_gen only

You can play with perl to get the values you want easily. Also, if argument
'total' is passed, it will return the total number os_class tags parsed for this
host.

I<Note: This tag is usually available in new versions of nmap. You can define
your own os_family customizing the os_family lists using the
Parse::Nmap::XML functions: set_osfamily_list() and get_osfamily_list().>

=item B<tcpsequence()>

Returns the tcpsequence information in the format:

 ($class,$values,$index) = $host_obj->tcpsequence();

=item B<ipidsequence()>

Returns the ipidsequence information in the format:

 ($class,$values) = $host_obj->ipidsequence();

=item B<tcptssequence()>

Returns the tcptssequence information in the format:

 ($class,$values) = $host_obj->tcptssequence();

=item B<uptime_seconds()>

Returns the number of seconds the host has been up (since boot).

=item B<uptime_lastboot()>

Returns the time and date the given host was last rebooted.

=back 4

=head1 AUTHOR

Anthony G Persaud <ironstar@iastate.edu>

=head1 SEE ALSO

L<nmap(1)>, L<XML::Twig(3)>

  http://www.insecure.org/nmap/
  http://www.xmltwig.com

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

See http://www.perl.com/perl/misc/Artistic.html

=cut
