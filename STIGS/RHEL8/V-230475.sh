#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230475"
GrpTitle="SRG-OS-000278-GPOS-00108"
RuleID="SV-230475r627750_rule"
STIGID="RHEL-08-030650"
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

if ps -ef | grep -i tripwire | grep -v grep >> $Results; then
 echo "Tripwire installed and Running" >> $Results
 echo "Pass" >> $Results
elif rpm -q aide >> $Results; then
 echo "AIDE installed manual check" >> $Results
 echo "Fail" >> $Results
else
 echo "AIDE or Tripwire is not installed" >> $Results
 echo "Fail" >> $Results 
fi
