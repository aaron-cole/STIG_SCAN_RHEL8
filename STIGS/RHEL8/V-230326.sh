#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier "UID" as the UID of the un-owned files.

#STIG Identification
GrpID="V-230326"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230326r627750_rule"
STIGID="RHEL-08-010780"
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
nousers="$(find / -path /proc -prune -o -nouser 2>>/dev/null | grep -v "^/proc")"

if [ -n "$nousers" ]; then
 echo "Files Found - $nousers" >> $Results
 echo "Fail" >> $Results
else 
 echo "All files/dirs have valid owners" >> $Results
 echo "Pass" >> $Results
 fi

