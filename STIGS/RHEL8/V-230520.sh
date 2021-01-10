#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230520"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-230520r599807_rule"
STIGID="RHEL-08-040132"
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

if findmnt /var/tmp | grep nodev >> $Results; then
 echo "Pass" >> $Results
else
 echo "/tmp is not mounted with the required options" >> $Results
 echo "Fail" >> $Results
fi
