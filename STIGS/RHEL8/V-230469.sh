#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230469"
GrpTitle="SRG-OS-000341-GPOS-00132"
RuleID="SV-230469r744004_rule"
STIGID="RHEL-08-030602"
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

if grub2-editenv - list | grep "audit_backlog_limit=8192" >> $Results; then
 if grep "^GRUB_CMDLINE_LINUX=.*audit_backlog_limit=8192" /etc/default/grub >> $Results; then
  echo "Pass" >> $Results
 else 
  grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "Grub not listing audit_backlog_limit" >> $Results
 echo "Fail" >> $Results
fi
