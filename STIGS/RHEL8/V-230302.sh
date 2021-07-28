#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

#STIG Identification
GrpID="V-230302"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230302r627750_rule"
STIGID="RHEL-08-010590"
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

if findmnt /home | grep noexec >> $Results; then
 echo "Pass" >> $Results
else
 echo "/home is not mounted with the required options" >> $Results
 echo "Fail" >> $Results
fi
