#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230524"
GrpTitle="SRG-OS-000378-GPOS-00163"
RuleID="SV-230524r744026_rule"
STIGID="RHEL-08-040140"
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

rule_list="$(usbguard list-rules)"
echo "USBGuard Rules" >> $Results
echo $rule_list >> $Results

if [ -z $rule_list ] ; then
 echo "Fail" >> $Results
else 
 echo "Pass" >> $Results
fi
