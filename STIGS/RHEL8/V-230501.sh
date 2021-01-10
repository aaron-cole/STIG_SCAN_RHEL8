#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230501"
GrpTitle="SRG-OS-000112-GPOS-00057"
RuleID="SV-230501r599732_rule"
STIGID="RHEL-08-040060"
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

if rpm -q openssh-server >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results 
fi
