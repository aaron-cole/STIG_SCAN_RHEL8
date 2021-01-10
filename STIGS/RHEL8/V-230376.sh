#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230376"
GrpTitle="SRG-OS-000383-GPOS-00166"
RuleID="SV-230376r599732_rule"
STIGID="RHEL-08-020290"
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
 if grep -i "^cache_credentials = false" /etc/sssd/sssd.conf >> $Results; then
  echo "Pass" >> $Results
 elif grep -i "^cache_credentials = true" /etc/sssd/sssd.conf >> $Results; then
  if grep "offline_credentials_expiration = 1" /etc/sssd/sssd.conf >> $Results; then
   echo "Pass" >> $Results
  else
   echo "offline_credentials_expiration not set or not found in /etc/sssd/sssd.conf" >> $Results
   echo "Fail" >> $Results
  fi
 else
  echo "cache_credentials not found in /etc/sssd/sssd.conf" >> $Results
  echo "Pass" >> $Results
 fi
else
 echo "/etc/sssd/sssd.conf not found" >> $Results
 echo "Fail" >> $Results
fi





