#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230245"
GrpTitle="SRG-OS-000206-GPOS-00084"
RuleID="SV-230245r627750_rule"
STIGID="RHEL-08-010210"
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

if [ -e /var/log/messages ]; then
 ls -l /var/log/messages >> $Results
 if [ "$(stat -Lc %a /var/log/messages)" -eq "640" ] || [ "$(stat -Lc %a /var/log/messages)" -eq "600" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "/var/log/messages does not exist" >> $Results 
 echo "Fail" >> $Results
fi
