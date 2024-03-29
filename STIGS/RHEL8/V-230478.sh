#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230478"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230478r744011_rule"
STIGID="RHEL-08-030680"
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

if rpm -q gnutls >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
