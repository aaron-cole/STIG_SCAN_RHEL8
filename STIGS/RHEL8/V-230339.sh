#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230339"
GrpTitle="SRG-OS-000021-GPOS-00005"
RuleID="SV-230339r743975_rule"
STIGID="RHEL-08-020017"
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

if grep "^dir = " /etc/security/faillock.conf >> $Results; then
 echo "Is this directory documented?" >> $Results
 echo "Fail" >> $Results
else
 echo "directory is either not set or not configured properly in /etc/security/faillock.conf" >> $Results
 echo "Fail" >> $Results
fi
