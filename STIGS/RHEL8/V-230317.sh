#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory (other than the user's home directory), executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. If deviations from the default system search path for the local interactive user are required, they must be documented with the Information System Security Officer (ISSO).

#STIG Identification
GrpID="V-230317"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230317r599732_rule"
STIGID="RHEL-08-010690"
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

initfiles="$(find /home/* -maxdepth 1 -type f \( -name ".login" -o ".bash_profile" -o ".bashrc" -o ".cshrc" -o ".profile" -o ".tcshrc" -o ".kshrc" \) 2>>/dev/null)"
for item in $initfiles; do 
 if [ -e $f/$item ]; then
  for i in $(grep "PATH" $f/$item); do
   testline="$(echo "$i" | cut -f 2 -d "=")"
   linecount="$(echo "$i" | cut -f 2 -d "=" | awk -F':' '{ print NF }')"
   Counter=1
   while [ $linecount -ge $Counter ]; do
	testitem="$(echo "$i" | cut -f 2 -d "=" | cut -f $Counter -d ":")"
	case $testitem in
	 PATH|export|\$PATH|\$HOME*|$f*|TMOUT|TERM) echo "" >> /dev/null;;
	 *)	echo "Found $testitem in $f/$item" >> $Results
			((scorecheck+=1));;
	esac
    (( Counter++ ))
   done
  done
 fi
done


if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
