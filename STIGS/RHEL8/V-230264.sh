#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230264"
GrpTitle="SRG-OS-000366-GPOS-00153"
RuleID="SV-230264r599732_rule"
STIGID="RHEL-08-010370"
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

if grep gpgcheck=0 /etc/yum.repos.d/* >> $Results; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
