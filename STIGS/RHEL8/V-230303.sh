#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "nodev" mount option causes the system not to interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-230303"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230303r599732_rule"
STIGID="RHEL-08-010600"
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

if egrep -v "ext|^#|swap|gfs|xfs" /etc/fstab | grep "^\/" >> $Results; then 
 if [ "$(egrep -v "ext|#|swap|gfs|xfs" /etc/fstab | grep "^\/" | wc -l)" == "$(egrep -v "ext|#|swap|gfs" /etc/fstab | grep "^\/" | grep nodev | wc -l)" ]; then 
  echo "Pass" >> $Results
 else
  echo "nosuid is not set on removable file systems" >> $Results
  echo "Fail" >> $Results
 fi
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
