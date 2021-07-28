#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244544"
GrpTitle="SRG-OS-000297-GPOS-00115"
RuleID="SV-244544r743881_rule"
STIGID="RHEL-08-040101"
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

echo "Running status- $(systemctl is-active firewalld)" >> $Results

if [ "$(systemctl is-active firewalld)" == "active" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
