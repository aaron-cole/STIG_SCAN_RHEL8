#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230279"
GrpTitle="SRG-OS-000134-GPOS-00068"
RuleID="SV-230279r599732_rule"
STIGID="RHEL-08-010423"
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

if grub2-editenv - list | grep "slub_debug=P" >> $Results; then
 if grep "^GRUB_CMDLINE_LINUX=.*slub_debug=P" /etc/default/grub >> $Results; then
  echo "Pass" >> $Results
 else 
  grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "Grub not listing slub_debug" >> $Results
 echo "Fail" >> $Results
fi
