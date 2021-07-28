#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230251"
GrpTitle="SRG-OS-000250-GPOS-00093"
RuleID="SV-230251r743937_rule"
STIGID="RHEL-08-010290"
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

grep "^CRYPTO_POLICY=" /etc/crypto-policies/back-ends/opensshserver.config | sed 's/.*MACs=//g' | awk '{print $1}' >> $Results

if [ "$(grep "^CRYPTO_POLICY=" /etc/crypto-policies/back-ends/opensshserver.config | sed 's/.*MACs=//g' | awk '{print $1}')" == "hmac-sha2-512,hmac-sha2-256" ]; then  
 echo "Pass" >> $Results
else
 echo "MACs not correctly definined in /etc/crypto-policies/back-ends/opensshserver.config" >> $Results
 echo "Fail" >> $Results
fi	
 
