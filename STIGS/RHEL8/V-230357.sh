#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230357"
GrpTitle="SRG-OS-000069-GPOS-00037"
RuleID="SV-230357r599732_rule"
STIGID="RHEL-08-020110"
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
awk -v opf="$Results" '/^ucredit/ {
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
