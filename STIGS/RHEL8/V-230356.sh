#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230356"
GrpTitle="SRG-OS-000069-GPOS-00037"
RuleID="SV-230356r599732_rule"
STIGID="RHEL-08-020100"
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
scorecheck=0
filestocheck="/etc/pam.d/system-auth /etc/pam.d/password-auth"

for filetocheck in $filestocheck; do
 if grep "^password.*required.*pam_pwquality.so.*retry=[1-3]" $filetocheck >> $Results; then
  echo "" >> /dev/null
 else
  echo "retry not set in $filetocheck" >> $Results
  ((scorecheck+=1)) 
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
