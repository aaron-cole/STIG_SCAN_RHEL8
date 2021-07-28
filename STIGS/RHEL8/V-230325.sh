#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.

#STIG Identification
GrpID="V-230325"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230325r627750_rule"
STIGID="RHEL-08-010770"
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
initfiles="$(find /home/* -maxdepth 1 -type f \( -name ".login" -o ".bash_profile" -o ".bashrc" -o ".cshrc" -o ".profile" -o ".tcshrc" -o ".kshrc" \) -perm /037 2>>/dev/null)"

if [ -n "$initfiles" ]; then
 echo "$initfiles" >> $Results
 echo "Fail" >> $Results 
else
 echo "No initialization files found with permissions greater than 0740" >> $Results 
 echo "Pass" >> $Results
fi
