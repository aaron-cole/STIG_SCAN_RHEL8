#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230349"
GrpTitle="SRG-OS-000028-GPOS-00009"
RuleID="SV-230349r599732_rule"
STIGID="RHEL-08-020041"
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

if grep '[ -n "$PS1" -a -z "$TMUX" ] && exec tmux' /etc/bashrc >> /dev/null; then
 echo "Setting found in /etc/bashrc" >> $Results
 echo "Pass" >> $Results
else
 echo "tmux setting not found in /etc/bashrc" >> $Results
 echo "Fail" >> $Results
fi
