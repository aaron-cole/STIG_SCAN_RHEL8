#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230341"
GrpTitle="SRG-OS-000021-GPOS-00005"
RuleID="SV-230341r743978_rule"
STIGID="RHEL-08-020019"
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

if grep "^silent" /etc/security/faillock.conf >> $Results; then
 echo "Pass" >> $Results
else
 echo "silent is either not set or not configured properly in /etc/security/faillock.conf" >> $Results
 echo "Fail" >> $Results
fi
