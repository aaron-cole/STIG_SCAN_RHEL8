#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230297"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230297r627750_rule"
STIGID="RHEL-08-010560"
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

echo "auditd status- $(systemctl status auditd)" >> $Results
echo "Running status- $(systemctl is-active auditd)" >> $Results

if [ "$(systemctl is-enabled auditd)" == "enabled" ] && [ "$(systemctl is-active auditd)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
