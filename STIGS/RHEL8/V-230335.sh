#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230335"
GrpTitle="SRG-OS-000021-GPOS-00005"
RuleID="SV-230335r743969_rule"
STIGID="RHEL-08-020013"
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

if grep "^fail_interval = " /etc/security/faillock.conf >> $Results; then
 if [ "$(grep "^fail_interval = " /etc/security/faillock.conf | awk '{print $3}')" -ge 900 ]; then
  echo "Pass" >> $Results
 else
  echo "fail_interval less than 900" >> $Results 
  echo "Fail" >> $Results
 fi  
else
 echo "fail_interval not configured in /etc/security/faillock.conf" >> $Results
 echo "Fail" >> $Results
fi

