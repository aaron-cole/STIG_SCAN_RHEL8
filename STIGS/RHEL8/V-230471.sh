#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Without the capability to restrict the roles and individuals that can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

#STIG Identification
GrpID="V-230471"
GrpTitle="SRG-OS-000063-GPOS-00032"
RuleID="SV-230471r627750_rule"
STIGID="RHEL-08-030610"
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

filestocheck="$(ls /etc/audit/rules.d/*.rules)"
filestocheck+=" /etc/audit/auditd.conf"

for filetocheck in $filestocheck; do
 if [ -e $filetocheck ]; then
  ls -ld $filetocheck >> $Results
  if [ "$(stat -Lc %a $filetocheck)" -eq "640" ] || [ "$(stat -Lc %a $filetocheck)" -eq "600" ]; then
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
