#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230510"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-230510r627750_rule"
STIGID="RHEL-08-040122"
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

if findmnt /dev/shm | grep noexec >> $Results; then
 echo "Pass" >> $Results
else
 echo "/dev/shm is not mounted with the required options" >> $Results
 echo "Fail" >> $Results
fi
