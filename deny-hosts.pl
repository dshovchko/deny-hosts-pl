#!/usr/bin/perl

use Sys::Syslog;

$from = "admin\@myserver.com";
$to = "admin\@myserver.com";
%ban;
%banned;

openlog("deny-hosts", "ndelay,pid", "local0");
open (FIFO, "/root/bin/deny-hosts/auth.info");

syslog(LOG_INFO, "started");

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

sub smtp_send {
    my $body = $_[0];

    my $time = time();
    my ($sec,my $min,my $hour,my $mday,my $mon,my $year,my $wday,my $yday,my $isdst) = localtime($time);
    my $now = sprintf("%04d-%02d-%02d %02d:%02d:%02d ", ($year+1900), ($mon+1), $mday, $hour, $min, $sec);

    if (open (SENDMAIL, "|/usr/sbin/sendmail -t")) {
        print SENDMAIL "From: $from\n";
        print SENDMAIL "To: $to\n";
        print SENDMAIL "Subject: IP banned $now\n\n";
        print SENDMAIL "$body";
        close (SENDMAIL);
    }
}