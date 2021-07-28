#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230355"
GrpTitle="SRG-OS-000068-GPOS-00036"
RuleID="SV-230355r627750_rule"
STIGID="RHEL-08-020090"
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
