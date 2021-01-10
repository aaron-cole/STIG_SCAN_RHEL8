#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.

#STIG Identification
GrpID="V-230382"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230382r599732_rule"
STIGID="RHEL-08-020350"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^PrintLastLog" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^PrintLastLog/ {
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
