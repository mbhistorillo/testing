#!/binbash
#------------------------------------------------------------------
#----------------Securing SSH in Linux Servers---------------------
#------------------------------------------------------------------
#Reference: http://www.binbert.com/blog/2010/11/securing-ssh-in-linux-servers/

echo "----------Running test on Securing SSH----------\n"

      permitrootlogin=`grep "^PermitRootLogin" /etc/ssh/sshd_config`
      if [[ $permitrootlogin == "PermitRootLogin no" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - PermitRootLogin should be set to NO"
      echo -e "------STATUS: $isVulnerability \n"

      protocol=`grep "^Protocol" /etc/ssh/sshd_config`
      if [[ $protocol == "Protocol 2" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - Protocol should be set to 2"
      echo -e "------STATUS: $isVulnerability \n"

      allowTcpForwarding=`grep "^AllowTcpForwarding" /etc/ssh/sshd_config`
      if [[ $allowTcpForwarding == "AllowTcpForwarding no" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - AllowTcpForwarding should be set to no"
      echo -e "------STATUS: $isVulnerability \n"

      X11Forwarding=`grep "^X11Forwarding" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "X11Forwarding no" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - X11Forwarding should be set to no"
      echo -e "------STATUS: $isVulnerability \n"

      StrictModes=`grep "^StrictModes" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "StrictModes yes" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - StrictModes should be set to yes"
      echo -e "------STATUS: $isVulnerability \n"

      IgnoreRhosts=`grep "^IgnoreRhosts" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "IgnoreRhosts yes" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - IgnoreRhosts should be set to yes"
      echo -e "------STATUS: $isVulnerability \n"

      HostbasedAuthentication=`grep "^HostbasedAuthentication" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "HostbasedAuthentication no" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - HostbasedAuthentication should be set to no"
      echo -e "------STATUS: $isVulnerability \n"

      RhostsRSAAuthentication=`grep "^RhostsRSAAuthentication" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "RhostsRSAAuthentication no" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - RhostsRSAAuthentication should be set to no"
      echo -e "------STATUS: $isVulnerability \n"

#-------------------------------------------------------------------------------
#---------Reference: https://wiki.centos.org/HowTos/OS_Protection --------------
#------------Require root password when booting to single user------------------

echo -e "----------Running Basic Hardening Test----------\n"

      rootonsingleuser=`grep "^~~:S:wait:/sbin/sulogin" /etc/inittab`
      if [[ $rootonsingleuser == "~~:S:wait:/sbin/sulogin" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "Require the root pw when booting into single user mode"
      echo -e "------STATUS: $isVulnerability \n"

#------------No one other than root should be allowed in root's home directory------------------
      rootonlyallowrdinrootdir=`ls -ld /root | grep "^drwx------"`
      if [[ $rootonlyallowrdinrootdir == "drwx------"*"root" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "Permission on /root should be exclusively on root"
      echo -e "------STATUS: $isVulnerability \n"


#------------Remove root's ability to log in from anywhere but the local console------------------
      checksecuretty=`cat /etc/securetty`
      if [[ $checksecuretty == "tty1" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "Remove root's ability to log in from anywhere but the local console"
      echo -e "------STATUS: $isVulnerability \n"

#------------Password expires every 180 days------------------
      Passexpireevery180days=`grep "^PASS_MAX_DAYS" /etc/ssh/sshd_config`
      if [[ $Passexpireevery180days == "PASS_MAX_DAYS 180" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "Password should expires every 180 days"
      echo -e "------STATUS: $isVulnerability \n"


#------------Password expires every 180 days------------------
      Passchangeonceaday=`grep "^PASS_MIN_DAYS" /etc/login.defs`
      if [[ $Passchangeonceaday == "PASS_MIN_DAYS 1" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "Passwords may only be changed once a day"
      echo -e "------STATUS: $isVulnerability \n"


#------------system should use sha512 instead of md5 for password protection------------------
      Passalgo=`authconfig --test | grep "password hashing"`
      if [[ $Passalgo == " password hashing algorithm is md5" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "system should use sha512 instead of md5 for password protection"
      echo -e "------STATUS: $isVulnerability \n"

