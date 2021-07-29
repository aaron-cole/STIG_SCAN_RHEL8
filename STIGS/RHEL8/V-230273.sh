#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230273"
GrpTitle="SRG-OS-000375-GPOS-00160"
RuleID="SV-230273r743943_rule"
STIGID="RHEL-08-010390"
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

if rpm -q openssl-pkcs11 >> $Results; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results 
fi
