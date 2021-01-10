#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-230308"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230308r599732_rule"
STIGID="RHEL-08-010650"
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

if mount | grep nfs | egrep -v "on /proc|sunrpc on" >> $Results; then 
 if [ "$(mount | grep nfs | grep nosuid | wc -l)" == "$(mount | grep nfs | wc -l)" ]; then
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
else 
 echo "No NFS mounts found" >> $Results
 echo "Pass" >> $Results
fi
