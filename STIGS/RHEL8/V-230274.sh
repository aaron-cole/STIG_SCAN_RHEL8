#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230274"
GrpTitle="SRG-OS-000375-GPOS-00160"
RuleID="SV-230274r599732_rule"
STIGID="RHEL-08-010400"
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

if [ -e /etc/sssd/sssd.conf ]; then
 if grep "^certificate_verification = ocsp_dgst=sha1" /etc/sssd/sssd.conf >> $Results; then
  echo "Pass" >> $Results
 else
  echo "certificate_verification not found or set correctly in /etc/sssd/sssd.conf" >> $Results
  echo "Pass" >> $Results
 fi
else
 echo "/etc/sssd/sssd.conf not found" >> $Results
 echo "Fail" >> $Results
fi
