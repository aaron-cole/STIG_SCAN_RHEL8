#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230485"
GrpTitle="SRG-OS-000095-GPOS-00049"
RuleID="SV-230485r599732_rule"
STIGID="RHEL-08-030741"
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

if [ -f /etc/chrony.conf ] && [ "$(grep "^port " /etc/chrony.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" -F= '/^port / {
	if($2 == 0) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/chrony.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
