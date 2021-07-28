#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244542"
GrpTitle="SRG-OS-000062-GPOS-00031"
RuleID="SV-244542r743875_rule"
STIGID="RHEL-08-030181"
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

echo "auditd status- $(systemctl status auditd.service)" >> $Results
echo "Running status- $(systemctl is-active auditd.service)" >> $Results

if [ "$(systemctl is-enabled auditd.service)" == "enabled" ] && [ "$(systemctl is-active auditd.service)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
