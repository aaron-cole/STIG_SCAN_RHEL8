#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230394"
GrpTitle="SRG-OS-000342-GPOS-00133"
RuleID="SV-230394r599732_rule"
STIGID="RHEL-08-030062"
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

if grep "^name_format =" /etc/audit/auditd.conf | egrep -vi "none|user" | egrep -i "hostname|fqdn|numeric" >> $Results; then
 echo "Pass" >> $Results
elif grep "^action = yes" /etc/audit/plugins.d/syslog.conf >> $Results; then
 if grep "^.*@" /etc/rsyslog.conf | grep -v "^#" >> $Results; then 
  echo "Logs are being to sent through rsyslog to remote log server" >> $Results
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "overflow_action not set" >> $Results
 echo "Fail" >> $Results
fi
