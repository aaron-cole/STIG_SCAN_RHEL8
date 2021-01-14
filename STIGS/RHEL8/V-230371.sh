#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230371"
GrpTitle="SRG-OS-000104-GPOS-00051"
RuleID="SV-230371r599732_rule"
STIGID="RHEL-08-020240"
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

if [ "$(awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd)" ]; then
 awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd >> $Results
 echo "Fail" >> $Results
else
 echo "No duplicate UIDs found" >> $Results
 echo "Pass" >> $Results
fi
