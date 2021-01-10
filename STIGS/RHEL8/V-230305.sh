#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-230305"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230305r599732_rule"
STIGID="RHEL-08-010620"
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

if egrep -v "ext|#|swap|gfs|xfs" /etc/fstab | grep "^\/" >> $Results; then 
 if [ "$(egrep -v "ext|#|swap|gfs|xfs" /etc/fstab | grep "^\/" | wc -l)" == "$(egrep -v "ext|#|swap|gfs" /etc/fstab | grep "^\/" | grep nosuid | wc -l)" ]; then 
  echo "Pass" >> $Results
 else
  echo "nosuid is not set on removable file systems" >> $Results
  echo "Fail" >> $Results
 fi
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
