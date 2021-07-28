#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230354"
GrpTitle="SRG-OS-000029-GPOS-00010"
RuleID="SV-230354r743990_rule"
STIGID="RHEL-08-020080"
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

if rpm -q gnome-desktop3 >> $Results; then
 echo "Manual Check" >> $Results
 echo "Fail" >> $Results
else
 echo "GNOME is not installed" >> $Results
 echo "NA" >> $Results
fi
