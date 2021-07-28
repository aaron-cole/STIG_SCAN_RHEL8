#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The sudo command allows a user to execute programs with elevated (administrator) privileges. It prompts the user for their password and confirms your request to execute a command by checking a file, called sudoers. If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.

#STIG Identification
GrpID="V-237641"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-237641r646893_rule"
STIGID="RHEL-08-010382"
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

if grep "ALL.*ALL=(ALL).*ALL\|ALL.*ALL=(ALL\:ALL).*ALL" /etc/sudoers | grep -v "^#" >> $Results; then 
 echo "Fail" >> $Results
else 
 if grep -r "ALL.*ALL=(ALL).*ALL\|ALL.*ALL=(ALL\:ALL).*ALL" /etc/sudoers.d  | grep -v "^#" >> $Results; then 
  echo "Fail" >> $Results
 else 
  echo "Nothing Found in /etc/sudoers or /etc/sudoers.d/ files" >> $Results
  echo "Pass" >> $Results 
 fi 
fi
