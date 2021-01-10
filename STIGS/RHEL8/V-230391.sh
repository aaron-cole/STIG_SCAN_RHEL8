#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230391"
GrpTitle="SRG-OS-000047-GPOS-00023"
RuleID="SV-230391r599732_rule"
STIGID="RHEL-08-030050"
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

if grep "^max_log_file_action" /etc/audit/auditd.conf | egrep -vi "suspend|ignore|exec|warn|stop|rotate" | egrep -i "syslog|keep_logs" >> $Results; then
 echo "Pass" >> $Results
else
 echo "max_log_file_action not set properly in /etc/audisp/audisp-remote.conf" >> $Results
 echo "Fail" >> $Results
fi
