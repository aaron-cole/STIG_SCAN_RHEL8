#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230528"
GrpTitle="SRG-OS-000033-GPOS-00014"
RuleID="SV-230528r599732_rule"
STIGID="RHEL-08-040162"
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

if [ -f /etc/ssh/ssh_config ] && [ "$(grep "^RekeyLimit" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^RekeyLimit/ {
	if($2 == "1G 1h") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/ssh/ssh_config
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
