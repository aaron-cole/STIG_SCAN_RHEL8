#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230254"
GrpTitle="SRG-OS-000250-GPOS-00093"
RuleID="SV-230254r599732_rule"
STIGID="RHEL-08-010293"
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

if grep "^.include /etc/crypto-policies/back-ends/opensslcnf.config" /etc/pki/tls/openssl.cnf >> $Results; then
 update-crypto-policies --show >> $Results
 if [ "$(update-crypto-policies --show)" == "FIPS" ]; then
  echo "Pass" >> $Results
 else
  echo "System-wide crypto policy is not FIPS" >> $Results
  echo "Fail" >> $Results
 fi
else
 grep ".include" /etc/pki/tls/openssl.cnf >> $Results
 echo "Fail" >> $Results
fi
