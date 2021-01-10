#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.

#STIG Identification
GrpID="V-230539"
GrpTitle="SRG-OS-000480-GPOS-00227"
RuleID="SV-230539r599732_rule"
STIGID="RHEL-08-040250"
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

chkfiles="$(grep "^net.ipv4.conf.default.accept_source_route " /etc/sysctl.conf /etc/sysctl.d/* | cut -f 1 -d ":" | sort | uniq)"

if [ -n "$chkfiles" ]; then
for chkfile in $chkfiles; do
 if [ "$(grep "^net.ipv4.conf.default.accept_source_route " "$chkfile" | sort | uniq | wc -l)" -eq 1 ]; then
  chkvalues="$(grep "^net.ipv4.conf.default.accept_source_route " "$chkfile" | cut -f 2 -d"=")"
  for chkvalue in $chkvalues; do
   if [ "$chkvalue" -eq 0 ]; then
    echo "Pass - Setting found in $chkfile - $(grep "^net.ipv4.conf.default.accept_source_route " "$chkfile")" >> $Results
   else
    echo "Fail - Setting not found in $chkfile" >> $Results
   fi
  done
 else
  echo "Fail - $chkfile - too many entries" >> $Results
 fi
done
else
 echo "Fail - Setting Not Found in any files" >> $Results
fi
  
#Runtime
sysctl net.ipv4.conf.default.accept_source_route  | awk -v opf="$Results" '/^net.ipv4.conf.default.accept_source_route / {
	if($3 == 0) {
	 print "Pass - Setting Found in runtime -" $0 >> opf
	 } else {
	 print "Fail - Setting Not Found in runtime -" $0 >> opf
	 }
}'

chkfiles="$(grep "^net.ipv6.conf.default.accept_source_route " /etc/sysctl.conf /etc/sysctl.d/* | cut -f 1 -d ":" | sort | uniq)"

if [ -n "$chkfiles" ]; then
for chkfile in $chkfiles; do
 if [ "$(grep "^net.ipv6.conf.default.accept_source_route " "$chkfile" | sort | uniq | wc -l)" -eq 1 ]; then
  chkvalues="$(grep "^net.ipv6.conf.default.accept_source_route " "$chkfile" | cut -f 2 -d"=")"
  for chkvalue in $chkvalues; do
   if [ "$chkvalue" -eq 0 ]; then
    echo "Pass - Setting found in $chkfile - $(grep "^net.ipv6.conf.default.accept_source_route " "$chkfile")" >> $Results
   else
    echo "Fail - Setting not found in $chkfile" >> $Results
   fi
  done
 else
  echo "Fail - $chkfile - too many entries" >> $Results
 fi
done
else
 echo "Fail - Setting Not Found in any files" >> $Results
fi
  
#Runtime
sysctl net.ipv6.conf.default.accept_source_route  | awk -v opf="$Results" '/^net.ipv6.conf.default.accept_source_route / {
	if($3 == 0) {
	 print "Pass - Setting Found in runtime -" $0 >> opf
	 } else {
	 print "Fail - Setting Not Found in runtime -" $0 >> opf
	 }
}'

if grep "Fail" $Results >> /dev/null; then
 echo "Fail" >> $Results 
else
 echo "Pass" >> $Results
fi
