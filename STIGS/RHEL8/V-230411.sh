#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230411"
GrpTitle="SRG-OS-000062-GPOS-00031"
RuleID="SV-230411r599732_rule"
STIGID="RHEL-08-030180"
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

if rpm -q audit >> $Results; then
 echo "Startup status- $(systemctl is-enabled auditd)" >> $Results
 echo "Running status- $(systemctl is-active auditd)" >> $Results
 if [ "$(systemctl is-enabled auditd)" == "enabled" ] && [ "$(systemctl is-active auditd)" == "active" ]; then
  echo "Current audit State - $(systemctl status auditd)" >> $Results
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else 
 echo "Fail" >> $Results
fi
