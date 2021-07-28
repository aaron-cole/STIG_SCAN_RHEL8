#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.

#STIG Identification
GrpID="V-230288"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230288r627750_rule"
STIGID="RHEL-08-010500"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^StrictModes" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^StrictModes/ {
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
