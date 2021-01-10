#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230560"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230560r599732_rule"
STIGID="RHEL-08-040380"
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

if rpm -q iprutils >> $Results; then
 echo "Fail" >> $Results
else 
 echo "Pass" >> $Results
fi
