#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230256"
GrpTitle="SRG-OS-000250-GPOS-00093"
RuleID="SV-230256r627750_rule"
STIGID="RHEL-08-010295"
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

grep -o +VERS-ALL:.* /etc/crypto-policies/back-ends/gnutls.config >> $Results

if [ "$(grep -o +VERS-ALL:.* /etc/crypto-policies/back-ends/gnutls.config)" == "+VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:+COMP-NULL:%PROFILE_MEDIUM" ]; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi
