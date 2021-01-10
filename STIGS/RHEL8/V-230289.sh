#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.

#STIG Identification
GrpID="V-230289"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230289r599732_rule"
STIGID="RHEL-08-010510"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^Compression" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^Compression/ {
	if($2 == "no") {
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
