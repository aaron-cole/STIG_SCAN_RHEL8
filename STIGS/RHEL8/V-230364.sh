#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

#STIG Identification
GrpID="V-230364"
GrpTitle="SRG-OS-000075-GPOS-00043"
RuleID="SV-230364r599732_rule"
STIGID="RHEL-08-020180"
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
scorecheck=0

for user in $(cut -f1 -d ":" /etc/shadow); do
 case $user in
	patrol|heimdall|oracle|hacluster) echo "$user - System Account - excluded" >> $Results;;
	*)	if [[ "$(grep "^$user:" /etc/shadow | cut -f 2 -d ":")" =~ ^\$6* ]] && [[ "$user" != "root" ]]; then 
		 if [[ "$(grep "^$user:" /etc/shadow | cut -f 4 -d ":")" -lt 1 ]]; then 
		  echo "$user - Fix" >> $Results
		  ((scorecheck+=1))
		 fi
		fi;;
 esac
done

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else
 echo "Pass" >> $Results
fi
