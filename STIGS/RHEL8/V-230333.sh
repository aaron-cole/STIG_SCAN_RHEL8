#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230333"
GrpTitle="SRG-OS-000021-GPOS-00005"
RuleID="SV-230333r743966_rule"
STIGID="RHEL-08-020011"
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

if grep "^deny = [1-3]" /etc/security/faillock.conf >> $Results; then
  echo "Pass" >> $Results
else
 echo "deny is not set or not configured in /etc/security/faillock.conf" >> $Results
 echo "Fail" >> $Results 
fi

