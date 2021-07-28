#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230372"
GrpTitle="SRG-OS-000105-GPOS-00052"
RuleID="SV-230372r627750_rule"
STIGID="RHEL-08-020250"
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

echo "Red Hat IDM? then NA" >> $Results
echo "Manual Check" >> $Results
echo "Fail" >> $Results
