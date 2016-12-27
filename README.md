# deny-hosts-pl
This script blocks attempts of guessing the password to connect via ssh.

It continuously monitors the syslog messages coming from sshd, analyzes and blocks attackers IP using */etc/hosts.deny*.


Requirements:
============

1. Perl.
2. Syslog.


Congiguring SSH:
===============

First place disable root login by password:

    PermitRootLogin no

Next, you should limit the number of users who have ssh access:

    AllowUsers user1 user2 user3

These settings you need to change or add in the config file ssh */etc/ssh/sshd_config* and than restart the sshd daemon.


Installation:
============

Place the script in the directory */root/bin/deny-hosts*. Create directory:

    mkdir /root/bin/deny-hosts

Copy script:

    cp deny-hosts.pl /root/bin/deny-hosts/deny-hosts.pl

Give permission to run:

    chmod 755 /root/bin/deny-hosts/deny-hosts.pl

Create a file for the ip block list:

    touch /etc/hosts.sshd.deny

In */etc/hosts.deny* add this line:

    sshd : /etc/hosts.sshd.deny
    

Configuring Syslog:
==================

The interaction between syslog and our program organized through named pipes. Create a channel:

    mknod /root/bin/deny-hosts/auth.info p
    chmod 600 /root/bin/deny-hosts/auth.info

And configure syslog so the messages from sshd fell into this channel. Add in */etc/syslog.conf* this line:

    auth.info;mail.none             |/root/bin/deny-hosts/auth.info


Usage:
=====

You can run the script manually, but better to use Init Script *rc.deny-hosts*


Additionally:
============

The [article](https://shpargalki.org.ua/184/zashchita-ssh-ot-brutforsa-blokirovanie-ip-pri-podbore-parolei) in my blog.
