#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230276"
GrpTitle="SRG-OS-000433-GPOS-00192"
RuleID="SV-230276r599732_rule"
STIGID="RHEL-08-010420"
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

if dmesg | grep "NX (Execute Disable) protection: active" >> $Results; then
 echo "Pass" >> $Results
else
 if [ "$(cat /proc/cpuinfo | grep -i flags | wc -l)" -eq "$(cat /proc/cpuinfo | grep -i flags | grep nx | wc -l)"; then
  echo "Pass" >> $Results
 else
  echo "dmesg does not have execute disabled and cpuinfo does not show nx attribute" >> $Results
  echo "Fail" >> $Results
 fi
fi
