#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230526"
GrpTitle="SRG-OS-000423-GPOS-00187"
RuleID="SV-230526r599732_rule"
STIGID="RHEL-08-040160"
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

echo "sshd status- $(systemctl status sshd)" >> $Results
echo "Running status- $(systemctl is-active sshd)" >> $Results

if [ "$(systemctl is-enabled sshd)" == "enabled" ] && [ "$(systemctl is-active sshd)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
