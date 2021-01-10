#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230224"
GrpTitle="SRG-OS-000185-GPOS-00079"
RuleID="SV-230224r599732_rule"
STIGID="RHEL-08-010030"
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

if blkid | grep -v "crypto_LUKS"; then
 echo "Ensure none are pseudo file systems" >> $Results
 echo "Fail" >> $Results 
else 
 blkid >> $Results
 echo "Pass" >> $Results
fi
