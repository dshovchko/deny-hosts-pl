#!/usr/bin/perl

use Sys::Syslog;

%ban;
%banned;

# Get our configuration information
if (my $err = ReadCfg('deny-hosts.cfg')) {
    print(STDERR $err, "\n");
    exit(1);
}

openlog("deny-hosts", "ndelay,pid", "local0");
open (FIFO, $CFG::CFG{'channel'});

syslog(LOG_INFO, "started");
smtp_send("started");

while (1) {
    while (<FIFO>) {
	$str = $_;
	if ($str=~/Failed password for invalid user .+ (.+) port/) {
	    if(!$ban{$1}) {
		$ban{$1}=1;
	    } else {
		$ban{$1}++;
	    }
	    foreach $key (keys %ban) {
		if($ban{$key}>5 && $key) {
		    if (!$banned{$key}) {
			open (BL, '>>/etc/hosts.sshd.deny');
			print BL $key,"\n";
			close(BL);
			smtp_send($key);
			syslog(LOG_INFO, "IP banned: $key");
		    }
		    delete($ban{$key});
		    $banned{$key} = 1;
		}
	    }
	}
    }
    smtp_send("syslog restarted");
    sleep 5;
}

syslog(LOG_INFO, "exited");

close (FIFO);
closelog();

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


sub smtp_send {
    my $body = $_[0];
    
    my $time = time();
    (my $sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst) = localtime($time);
    my $now = sprintf("%04d-%02d-%02d %02d:%02d:%02d ", ($year+1900), ($mon+1), $mday, $hour, $min, $sec);
    
    if (open (SENDMAIL, "|".$CFG::CFG{'mail'}{'mailer'})) {
        print SENDMAIL "From: ".$CFG::CFG{'mail'}{'from'}."\n";
        print SENDMAIL "To: ".$CFG::CFG{'mail'}{'to'}."\n";
        print SENDMAIL "Subject: IP banned $now\n\n";
        print SENDMAIL "$body";
        close (SENDMAIL);
    }
}
