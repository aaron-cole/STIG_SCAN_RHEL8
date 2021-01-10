#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.

#STIG Identification
GrpID="V-230321"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230321r599732_rule"
STIGID="RHEL-08-010730"
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

for f in $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd); do
 if [ "$(stat -c %a $f)" -gt "750" ]; then
  echo "$f - Fix" >> $Results
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results  
 echo "Pass" >> $Results
fi
