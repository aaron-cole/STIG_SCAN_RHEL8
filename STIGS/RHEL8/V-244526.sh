#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244526"
GrpTitle="SRG-OS-000250-GPOS-00093"
RuleID="SV-244526r743827_rule"
STIGID="RHEL-08-010287"
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

if grep "CRYPTO_POLICY=" /etc/sysconfig/sshd | grep -v "^#" >> $Results; then
 echo "CRYPTO_POLICY is defined in /etc/sysconfig/sshd" >> $Results
 echo "Fail" >> $Results
else
 grep "CRYPTO_POLICY=" /etc/sysconfig/sshd >> $Results
 echo "Pass" >> $Results
fi
