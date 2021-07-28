#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-230262"
GrpTitle="SRG-OS-000259-GPOS-00100"
RuleID="SV-230262r627750_rule"
STIGID="RHEL-08-010350"
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

findfile="$(find -L /lib /lib64 /usr/lib /usr/lib64 -type f ! -group root -a ! -group sssd -a ! -group utmp -a ! -group dbus -a ! -group tty -a ! -group ssh_keys -a ! -group cockpit-wsinstance -a ! -group slocate -a ! -group pcpqa -a ! -group postdrop)"

if [ -n "$findfile" ]; then
 echo "files found $findfile" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
