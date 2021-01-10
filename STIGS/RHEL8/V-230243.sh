#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230243"
GrpTitle="SRG-OS-000138-GPOS-00069"
RuleID="SV-230243r599732_rule"
STIGID="RHEL-08-010190"
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
pubdirs="$(find / -type d -perm -002 \! -perm -1000 2>/dev/null)"

if [ -n "$pubdirs" ]; then
 echo "$pubdirs" >> $Results
 echo "Fail" >> $Results 
else
 echo "No world-writable directories with out the Sticky BIT found" >> $Results 
 echo "Pass" >> $Results
fi


