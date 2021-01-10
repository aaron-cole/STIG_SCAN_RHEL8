#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230250"
GrpTitle="SRG-OS-000206-GPOS-00084"
RuleID="SV-230250r599732_rule"
STIGID="RHEL-08-010260"
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
 if [ "$(stat -Lc %G /var/log)" == "root" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "/var/log does not exist" >> $Results 
 echo "Fail" >> $Results
fi
