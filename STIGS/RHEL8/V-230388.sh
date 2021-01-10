#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230388"
GrpTitle="SRG-OS-000046-GPOS-00022"
RuleID="SV-230388r599732_rule"
STIGID="RHEL-08-030020"
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

if [ -f /etc/audit/auditd.conf ] && [ "$(grep "^action_mail_acct" /etc/audit/auditd.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^action_mail_acct/ {
	if($3 == "root") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/audit/auditd.conf
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
