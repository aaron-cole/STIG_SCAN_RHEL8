#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230468"
GrpTitle="SRG-OS-000062-GPOS-00031"
RuleID="SV-230468r627750_rule"
STIGID="RHEL-08-030601"
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

if grub2-editenv - list | grep "audit=1" >> $Results; then
 if grep "^GRUB_CMDLINE_LINUX=.*audit=1" /etc/default/grub >> $Results; then
  echo "Pass" >> $Results
 else 
  grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "Grub not listing audit" >> $Results
 echo "Fail" >> $Results
fi
