#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

#STIG Identification
GrpID="V-230294"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230294r599732_rule"
STIGID="RHEL-08-010542"
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

if findmnt /var/log/audit >> $Results; then
 echo "Pass" >> $Results
else
 echo "/var/log/audit not on seperate partition" >> $Results  
 echo "Fail" >> $Results
fi
