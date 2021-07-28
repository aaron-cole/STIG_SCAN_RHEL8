#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.  The only legitimate location for device files is the /dev directory located on the root partition.

#STIG Identification
GrpID="V-230301"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230301r627750_rule"
STIGID="RHEL-08-010580"
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

if mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev' >> $Results; then
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
