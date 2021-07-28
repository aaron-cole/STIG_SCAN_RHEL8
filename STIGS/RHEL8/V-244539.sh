#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244539"
GrpTitle="SRG-OS-000029-GPOS-00010"
RuleID="SV-244539r743866_rule"
STIGID="RHEL-08-020082"
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

if rpm -q gnome-desktop3 >> $Results; then 
 if grep "system-db:local" /etc/dconf/profile/user >> $Results; then
  if  grep -i lock-enabled /etc/dconf/db/local.d/locks/* >> $Results; then
   echo "Pass" >> $Results
  else
   echo "Locks not enabled" >> $Results
   echo "Fail" >> $Results
  fi
 else 
  echo "Installed Setting not defined" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "GNOME is not installed" >> $Results
 echo "NA" >> $Results
fi
