#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.

#STIG Identification
GrpID="V-230309"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230309r599732_rule"
STIGID="RHEL-08-010660"
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
wwfiles="$TempDIR/wwfiles"
find / -perm -002 -type f 2>/dev/null | egrep -v "^/proc/|^/sys/" >> $wwfiles
#wwfiles="$(find / -perm -002 -type f 2>/dev/null | egrep -v "^/proc/|^/sys/")"
initfiles=".login .bash_profile .bashrc .cshrc .profile .tcshrc .kshrc"

if [ -z $wwfiles ]; then
 echo "No World Writable files found"
 echo "Pass" >> $Results
else  
 for f in $(ls /home); do
  for item in $initfiles; do 
   if [ -e /home/$f/$item ]; then
    for wwfile in $wwfiles; do
     if grep "$wwfile" /home/$f/$item | grep -v "^#" >> $Results; then
      ((scorecheck+=1))
      echo "/home/$f/$item - Fix" >> $Results
     fi
    done
   fi
  done
 done
fi 

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
