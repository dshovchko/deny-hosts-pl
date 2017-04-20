#!/usr/bin/perl

use File::Pid;
use Sys::Hostname;
use Sys::Syslog;

$iptables = "iptables -%1s INPUT -p tcp -s %s --dport 22 -j DROP";

%guessing;
%banned;
%iptables;

$now = time();
$next_check = $now + 9999999;

# Get our configuration information
if (my $err = ReadCfg('deny-hosts.cfg')) {
    print(STDERR $err, "\n");
    exit(1);
}

openlog("deny-hosts", "ndelay,pid", "local0");
open (FIFO, $CFG::CFG{'channel'});

my $FPID = File::Pid->new({file => $CFG::CFG{'pid_file'}});
$FPID->write;
if ($$ != $FPID->running) {
    syslog(LOG_INFO, "deny-hosts already running");
    smtp_send("deny-hosts-iptables", "already running", 0);
    print(STDERR "\n", "deny-hosts already running", "\n");
    exit(1);
}

syslog(LOG_INFO, "started");
smtp_send("deny-hosts-iptables", "started", 0);

while (1) {
    while (<FIFO>) {
	$str = $_;
	if ($str=~/Failed \S+ for invalid user .+ (.+) port/) {
	    if(!$guessing{$1}) {
		$guessing{$1}=1;
	    } else {
		$guessing{$1}++;
	    }
	    syslog(LOG_INFO, "guessing: $1 : ".$guessing{$1});
	    if ($guessing{$1}>$CFG::CFG{'maxretry'} && $1) {
                iptables_add($1);
            }
	}
	
	$now = time();
	if ($now > $next_check) {
	    iptables_check();
	}
    }
    smtp_send("syslog restarted");
    sleep 5;
}

syslog(LOG_INFO, "exited");

close (FIFO);
closelog();

$FPID->remove;
exit;

#   Read a configuration file
#   The arg can be a relative or full path, or
#   it can be a file located somewhere in @INC.
sub ReadCfg
{
    my $file = $_[0];

    our $err;

    {   # Put config data into a separate namespace
        package CFG;

        # Process the contents of the config file
        my $rc = do($file);

        # Check for errors
        if ($@) {
            $::err = "ERROR: Failure compiling '$file' - $@";
        } elsif (! defined($rc)) {
            $::err = "ERROR: Failure reading '$file' - $!";
        } elsif (! $rc) {
            $::err = "ERROR: Failure processing '$file'";
        }
    }

    return ($err);
}

sub set_next_check {
    my $new = $_[0];
    
    if ($next_check > $new) {
	$next_check = $new;
    }
}

sub iptables_add {
    my $ip = $_[0];
    
    iptables_parse();
    if (!exists($iptables{$ip})) {
	my $cmd = sprintf($iptables, 'A', $ip);
	syslog(LOG_INFO, $cmd);
	system($cmd);
	my $until = time() + $CFG::CFG{'ban_interval'} * ($guessing{$ip} - $CFG::CFG{'maxretry'});
	$banned{$ip} = {
	    'until' => $until,
	    'pkts' => 0,
	};
	set_next_check($until);
	syslog(LOG_INFO, "set next check: ".$next_check);
	smtp_send('IP denied', $ip);
	syslog(LOG_INFO, "IP denied: $ip");
    }
    else {
	syslog(LOG_INFO, "IP already denied: $ip");
    }
}

sub iptables_remove {
    my $ip = $_[0];
    
    my $cmd = sprintf($iptables, 'D', $ip);
    syslog(LOG_INFO, $cmd);
    system($cmd);
    delete($banned{$ip});
    smtp_send('IP allowed', $ip);
    syslog(LOG_INFO, "IP allowed: $ip");
}

sub iptables_parse {

    my @ipt_lines = `iptables -L INPUT -n -v`;
    my $found_chain  = 0;
    
    %iptables = ();
    $iptables{'raw'} = join("", @ipt_lines);
    
    LINE: for my $line (@ipt_lines) {
        chomp $line;

        last LINE if ($found_chain and $line =~ /^\s*Chain\s+/);

        if ($line =~ /^\s*Chain\s\QINPUT\E\s\(/i) {
            $found_chain = 1;
            next LINE;
        }
        next LINE if $line =~ /\starget\s{2,}prot/i;
        next LINE unless $found_chain;
        next LINE unless $line;

        ### initialize hash
        my %rule = (
            'extended' => '',
            'raw'      => $line,
        );

        my $rule_body = '';
        my $packets   = '';
        my $bytes     = '';

        if ($line =~ /^\s*(\S+)\s+(\S+)\s+(.*)/) {
	    $packets   = $1;
	    $bytes     = $2;
	    $rule_body = $3;
	}

	### iptables:
	### 0     0 ACCEPT  tcp  --  eth1 * 192.168.10.3  0.0.0.0/0  tcp dpt:80
	### 0     0 ACCEPT  tcp  --  eth1 * 192.168.10.15 0.0.0.0/0  tcp dpt:22
	### 33 2348 ACCEPT  tcp  --  eth1 * 192.168.10.2  0.0.0.0/0  tcp dpt:22
	### 0     0 ACCEPT  tcp  --  eth1 * 192.168.10.2  0.0.0.0/0  tcp dpt:80
	### 0     0 DNAT    tcp  --  *    * 123.123.123.123 0.0.0.0/0 tcp dpt:55000 to:192.168.12.12:80

	my $match_re = qr/^(\S+)\s+(\S+)\s+\-\-\s+
			    (\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)/x;

	if ($rule_body =~ $match_re) {
	    $rule{'packets'}  = $packets;
	    $rule{'bytes'}    = $bytes;
	    $rule{'target'}   = $1;
	    my $proto = $2;
	    $proto = 'all' if $proto eq '0';
	    $rule{'protocol'} = $rule{'proto'} = lc($proto);
	    $rule{'intf_in'}  = $3;
	    $rule{'intf_out'} = $4;
	    $rule{'src'}      = $5;
	    $rule{'dst'}      = $6;
	    $rule{'extended'} = $7 || '';
	}

	$iptables{$rule{'src'}} = $rule{'packets'};
    }
}

sub iptables_check() {
    $size = keys %banned;
    return if ($size==0);

    iptables_parse();
    syslog(LOG_INFO, "iptables check");
    
    $now = time();
    foreach $ip (keys %banned) {
	if ($now > $banned{$ip}{'until'}) {
            # check this
	    if ($iptables{$ip} && $banned{$ip}{'pkts'}<$iptables{$ip}) {
		# IP presents in iptables and IP has activity
		my $until = $now + $CFG::CFG{'ban_interval'} * ($guessing{$ip} - $CFG::CFG{'maxretry'});
		$banned{$ip}{'until'} = $until;
		$banned{$ip}{'pkts'} = $iptables{$ip};
		syslog(LOG_INFO, "denied ip: $ip next check after ".$until);
            } else {
		# IP not presents in iptables or IP hasn't activity
        	iptables_remove($ip);
		syslog(LOG_INFO, "iptables remove: $ip");
	    }
        }
    }

    # set next check time
    $next_check = $now + 9999999;
    foreach $ip (keys %banned) {
	set_next_check($banned{$ip}{'until'});
    }
    syslog(LOG_INFO, "set next check: ".$next_check);
    # clear
    %iptables = ();
}

sub smtp_send {
    my $subject = $_[0];
    my $body = $_[1];
    my $dontmail = $_[2];
    
    if (!defined($dontmail)) { 
	$dontmail = 1;
    }
    
    return if ($CFG::CFG{'mail'}{'dontmail'} && $dontmail);
    
    $host = hostname;
    my $time = time();
    (my $sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst) = localtime($time);
    my $now = sprintf("%04d-%02d-%02d %02d:%02d:%02d ", ($year+1900), ($mon+1), $mday, $hour, $min, $sec);
    
    if (open (SENDMAIL, "|".$CFG::CFG{'mail'}{'mailer'})) {
        print SENDMAIL "From: ".$CFG::CFG{'mail'}{'from'}."\n";
        print SENDMAIL "To: ".$CFG::CFG{'mail'}{'to'}."\n";
        print SENDMAIL "Subject: $host $subject $now\n\n";
        print SENDMAIL "$body";
        close (SENDMAIL);
    }
}
