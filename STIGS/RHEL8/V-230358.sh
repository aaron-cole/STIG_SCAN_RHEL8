#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230358"
GrpTitle="SRG-OS-000070-GPOS-00038"
RuleID="SV-230358r599732_rule"
STIGID="RHEL-08-020120"
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

if [ -f /etc/security/pwquality.conf ] && [ "$(grep "^ucredit" /etc/security/pwquality.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^lcredit/ {
	if($3 <= -1) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/security/pwquality.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
