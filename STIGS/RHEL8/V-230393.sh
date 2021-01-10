#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230393"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230393r599732_rule"
STIGID="RHEL-08-030061"
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

if [ -f /etc/audit/auditd.conf ] && [ "$(grep "^local_events" /etc/audit/auditd.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^local_events/ {
	if($3 == "yes") {
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
