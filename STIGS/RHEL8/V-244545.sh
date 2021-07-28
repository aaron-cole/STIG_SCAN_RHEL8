#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244545"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-244545r743884_rule"
STIGID="RHEL-08-040136"
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

echo "fapolicyd status- $(systemctl status fapolicyd.service)" >> $Results
echo "Running status- $(systemctl is-active fapolicyd.service)" >> $Results

if [ "$(systemctl is-enabled fapolicyd.service)" == "enabled" ] && [ "$(systemctl is-active fapolicyd.service)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
