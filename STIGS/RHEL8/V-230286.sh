#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If a public host key file is modified by an unauthorized user, the SSH service may be compromised.

#STIG Identification
GrpID="V-230286"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230286r599732_rule"
STIGID="RHEL-08-010480"
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
scorecheck=0

for f in /etc/ssh/ssh_host*_key.pub; do
  stat -c %n-%a $f >> $Results
 if [[ "$(stat -c %a $f)" -eq "644" ]]; then
  echo "" >> /dev/null
 else 
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
