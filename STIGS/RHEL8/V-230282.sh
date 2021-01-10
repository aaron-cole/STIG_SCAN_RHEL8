#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230282"
GrpTitle="SRG-OS-000445-GPOS-00199"
RuleID="SV-230282r599732_rule"
STIGID="RHEL-08-010450"
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

sestatus >> $Results
if [ "$(sestatus | awk '/^Current mode/ {if($3 == "enforcing") {print}}')" ] && [ "$(sestatus | awk '/^Loaded policy name/ {if($4 == "targeted") {print}}')" ]; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results 
fi
