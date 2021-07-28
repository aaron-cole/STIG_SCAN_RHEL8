#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230259"
GrpTitle="SRG-OS-000259-GPOS-00100"
RuleID="SV-230259r627750_rule"
STIGID="RHEL-08-010320"
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

findfile="$(find -L /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -a ! -group tty -a ! -group slocate -a ! -group postgrop)"

if [ -n "$findfile" ]; then
 echo "files found $findfile" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
