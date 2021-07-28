#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230476"
GrpTitle="SRG-OS-000341-GPOS-00132"
RuleID="SV-230476r627750_rule"
STIGID="RHEL-08-030660"
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

df -h /var/log/audit >> $Results
echo "Do you have a weeks worth of audit logs?" >> $Results
echo "Manual check" >> $Results
echo "Fail" >> $Results
