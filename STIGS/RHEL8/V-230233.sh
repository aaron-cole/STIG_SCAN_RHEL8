#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230233"
GrpTitle="SRG-OS-000073-GPOS-00041"
RuleID="SV-230233r743919_rule"
STIGID="RHEL-08-010130"
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
filestocheck="/etc/pam.d/password-auth"

for filetocheck in $filestocheck; do
 if grep "^password.*pam_unix.so.*rounds=[5-9][0-9][0-9][0-9]" $filetocheck >> $Results; then
  echo "" >> /dev/null
 else
  echo "rounds=5000 or greater not set in $filetocheck" >> $Results
  ((scorecheck+=1)) 
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
