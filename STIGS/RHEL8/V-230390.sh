#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230390"
GrpTitle="SRG-OS-000047-GPOS-00023"
RuleID="SV-230390r627750_rule"
STIGID="RHEL-08-030040"
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

if grep "^disk_error_action" /etc/audit/auditd.conf | egrep -vi "suspend|ignore|exec|warn|stop" | egrep -i "syslog|single|halt" >> $Results; then
 echo "Pass" >> $Results
else
 echo "disk_error_action not set properly in /etc/audit/auditd.conf" >> $Results
 echo "Fail" >> $Results
fi
