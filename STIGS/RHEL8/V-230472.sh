#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230472"
GrpTitle="SRG-OS-000256-GPOS-00097"
RuleID="SV-230472r627750_rule"
STIGID="RHEL-08-030620"
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

filestocheck="/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules"
for filetocheck in $filestocheck; do
 if [ -e $filetocheck ]; then
  ls -ld $filetocheck >> $Results
  if [ "$(stat -Lc %a $filetocheck)" -eq "750" ] || [ "$(stat -Lc %a $filetocheck)" -eq "755" ]; then
   echo "" >> /dev/null
  else 
   ((scorecheck+=1))
  fi
 else
  echo "$filetocheck does not exist" >> $Results 
  ((scorecheck+=1))
 fi
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
