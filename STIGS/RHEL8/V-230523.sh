#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230523"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-230523r599732_rule"
STIGID="RHEL-08-040135"
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

if rpm -q fapolicyd >> $Results; then
 echo "Startup status- $(systemctl is-enabled fapolicyd.service)" >> $Results
 echo "Running status- $(systemctl is-active fapolicyd.service)" >> $Results
 if [ "$(systemctl is-enabled fapolicyd.service)" == "enabled" ] && [ "$(systemctl is-active fapolicyd.service)" == "active" ]; then
  if grep "^permissive = 0" /etc/fapolicyd/fapolicyd.conf >> $Results; then
   echo "Pass" >> $Results
   if tail /etc/fapolicyd/fapolicyd.rules | grep "deny all all" >> $Results; then
    if [ -e /etc/fapolicyd/fapolicyd.mounts ]; then
	 cat /etc/fapolicyd/fapolicyd.mounts >> $Results
	 echo "Ensure enforcement on all system mounts" >> $Results
	 echo "Fail" >> $Results
	else
	 echo "fapolicyd not running on mounts" >> $Results
	 echo "Fail" >> $Results
	fi
   else
    echo "Deny all not implemented correctly?" >> $Results
    echo "Fail" >> $Results
   fi
  else
   grep "^permissive = " /etc/fapolicyd/fapolicyd.conf >> $Results 
   echo "Fail" >> $Results
  fi
 else 
  echo "Fail" >> $Results
 fi
else 
 echo "Fail" >> $Results
fi
