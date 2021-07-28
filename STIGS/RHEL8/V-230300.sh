#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-230300"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230300r743959_rule"
STIGID="RHEL-08-010571"
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

if findmnt /boot | grep nosuid >> $Results; then
 echo "Pass" >> $Results
else
 echo "/boot is not mounted with the required options" >> $Results
 echo "Fail" >> $Results
fi
