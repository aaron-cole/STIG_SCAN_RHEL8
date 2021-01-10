#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230491"
GrpTitle="SRG-OS-000095-GPOS-00049"
RuleID="SV-230491r599732_rule"
STIGID="RHEL-08-040004"
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

if grub2-editenv - list | grep "pti=on" >> $Results; then
 if grep "^GRUB_CMDLINE_LINUX=.*pti=on" /etc/default/grub >> $Results; then
  echo "Pass" >> $Results
 else 
  grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "Grub not listing pti" >> $Results
 echo "Fail" >> $Results
fi
