#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-244524"
GrpTitle="SRG-OS-000120-GPOS-00061"
RuleID="SV-244524r743821_rule"
STIGID="RHEL-08-010159"
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
filestocheck="/etc/pam.d/system-auth"

for filetocheck in $filestocheck; do
 if grep "^password.*pam_unix.so.*sha512" $filetocheck >> $Results; then
  echo "" >> /dev/null
 else
  echo "sha512 not set in $filetocheck" >> $Results
  ((scorecheck+=1)) 
 fi
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
