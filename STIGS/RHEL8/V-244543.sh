#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.

#STIG Identification
GrpID="V-244543"
GrpTitle="SRG-OS-000343-GPOS-00134"
RuleID="SV-244543r743878_rule"
STIGID="RHEL-08-030731"
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

if [ -f /etc/audit/auditd.conf ] && [ "$(grep "^space_left_action " /etc/audit/auditd.conf | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^space_left_action / {
	if($3 == "email" || $3 == "EMAIL") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/audit/auditd.conf
else
 echo "space_left_action not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
