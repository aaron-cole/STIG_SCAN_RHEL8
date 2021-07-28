#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230348"
GrpTitle="SRG-OS-000028-GPOS-00009"
RuleID="SV-230348r743987_rule"
STIGID="RHEL-08-020040"
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

if rpm -q tmux >> $Results; then
 if [ -f /etc/tmux.conf ] ; then
  if grep "set -g lock-command vlock" /etc/tmux.conf >> $Results; then
   echo "Pass" >> $Results
  else
   echo "lock-command not setting" >> $Results
   echo "Fail" >> $Results
  fi
 else 
  echo "/etc/tmux.conf not found" >> $Results
  echo "Fail" >> $Results
 fi
else 
 echo "Fail" >> $Results
fi
