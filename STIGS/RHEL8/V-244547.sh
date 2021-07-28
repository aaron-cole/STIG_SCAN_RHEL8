#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244547"
GrpTitle="SRG-OS-000378-GPOS-00163"
RuleID="SV-244547r743890_rule"
STIGID="RHEL-08-040139"
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

if rpm -q usbguard >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
