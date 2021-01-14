#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230273"
GrpTitle="SRG-OS-000375-GPOS-00160"
RuleID="SV-230273r599732_rule"
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
scorecheck=0

for package in openssl-pkcs11 esc ; do
 if rpm -q $package >> $Results; then
  echo "" >> /dev/null
 else
 ((scorecheck+=1))
 fi
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
