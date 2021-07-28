#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230248"
GrpTitle="SRG-OS-000206-GPOS-00084"
RuleID="SV-230248r627750_rule"
STIGID="RHEL-08-010240"
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

if [ -e /var/log ]; then
 ls -ld /var/log >> $Results
 if [ "$(stat -Lc %a /var/log)" -eq "755" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "/var/log does not exist" >> $Results 
 echo "Fail" >> $Results
fi
