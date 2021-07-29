#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244546"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-244546r743887_rule"
STIGID="RHEL-08-040137"
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
list="$(mount | egrep '^tmpfs| ext4| ext3| xfs' | awk '{ printf "%s\n", $3 }')"
  
if grep "^permissive = 0" /etc/fapolicyd/fapolicyd.conf >> $Results; then
 if tail /etc/fapolicyd/fapolicyd.rules | grep "deny all all" >> $Results; then
  if [ -e /etc/fapolicyd/fapolicyd.mounts ]; then
   cat /etc/fapolicyd/fapolicyd.mounts >> $Results
   for item in $list; do
    if ! grep "$item" /etc/fapolicyd/fapolicyd.mounts >> /dev/null; then
	 echo "$item not found in /etc/fapolicyd/fapolicyd.mounts" >> $Results
	 ((scorecheck+=1))
	fi
   done
  else
   echo "fapolicyd not running on mounts" >> $Results
   ((scorecheck+=1))
  fi
 else
  echo "Deny all not implemented correctly?" >> $Results
  ((scorecheck+=1))
 fi
else
 grep "^permissive = " /etc/fapolicyd/fapolicyd.conf >> $Results 
 ((scorecheck+=1))
fi

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
