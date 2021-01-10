#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address.  By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DIPSLAY environment variable to localhost.  This prevents remote hosts from connecting to the proxy display.

#STIG Identification
GrpID="V-230556"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230556r599732_rule"
STIGID="RHEL-08-040341"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

###Check###

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^X11UseLocalhost" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^X11UseLocalhost/ {
	if($2 == "yes") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/ssh/sshd_config
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
