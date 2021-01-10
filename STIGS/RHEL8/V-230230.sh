#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If an unauthorized user obtains access to a private key without a passcode, that user would have unauthorized access to any system where the associated public key has been installed.

#STIG Identification
GrpID="V-230230"
GrpTitle="SRG-OS-000067-GPOS-00035"
RuleID="SV-230230r599732_rule"
STIGID="RHEL-08-010100"
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

echo "Manual Check" >> $Results
echo "Fail" >> $Results