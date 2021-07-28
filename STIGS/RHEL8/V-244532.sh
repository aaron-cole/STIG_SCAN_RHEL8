#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If a local interactive user's files are group-owned by a group of which the user is not a member, unintended users may be able to access them.

#STIG Identification
GrpID="V-244532"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-244532r743845_rule"
STIGID="RHEL-08-010741"
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
 grpid="$(grep ":$f:" /etc/passwd | cut -f4 -d":")"
 if [ "$(stat -c %g $f)" -eq "$grpid" ]; then
  echo "" >> /dev/null
 else 
  ((scorecheck+=1))
  echo "$f - Fix" >> $Results
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results  
 echo "Pass" >> $Results
fi
