#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-230304"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230304r599732_rule"
STIGID="RHEL-08-010610"
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
 if [ "$(egrep -v "ext|#|swap|gfs|xfs" /etc/fstab | grep "^\/" | wc -l)" == "$(egrep -v "ext|#|swap|gfs" /etc/fstab | grep "^\/" | grep noexec | wc -l)" ]; then 
  echo "Pass" >> $Results
 else
  echo "nosuid is not set on removable file systems" >> $Results
  echo "Fail" >> $Results
 fi
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
