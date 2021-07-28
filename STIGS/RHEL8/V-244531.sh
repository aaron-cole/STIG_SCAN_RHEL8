#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.

#STIG Identification
GrpID="V-244531"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-244531r743842_rule"
STIGID="RHEL-08-010731"
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

for f in $(egrep "[0-9]{4}" /etc/passwd | egrep -v "nologin" | cut -f6 -d":"); do
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
