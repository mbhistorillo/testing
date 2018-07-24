#!/binbash

#----------------------------------Securing SSH in Linux Servers---------------------------------
#----------Reference: http://www.binbert.com/blog/2010/11/securing-ssh-in-linux-servers/---------

echo "Running test on Securing SSH"

      permitrootlogin=`grep "^PermitRootLogin" /etc/ssh/sshd_config`
      if [[ $permitrootlogin == "PermitRootLogin no" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - PermitRootLogin Should be set to NO"
      echo "------STATUS: $isVulnerability"

      protocol=`grep "^Protocol" /etc/ssh/sshd_config`
      if [[ $protocol == "Protocol 2" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - Protocol Should be set to 2"
      echo "------STATUS: $isVulnerability"

      allowTcpForwarding=`grep "^AllowTcpForwarding" /etc/ssh/sshd_config`
      if [[ $allowTcpForwarding == "AllowTcpForwarding no" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - AllowTcpForwarding Should be set to no"
      echo "------STATUS: $isVulnerability"

      X11Forwarding=`grep "^X11Forwarding" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "X11Forwarding no" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - X11Forwarding Should be set to no"
      echo "------STATUS: $isVulnerability"

      StrictModes=`grep "^StrictModes" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "StrictModes yes" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - StrictModes Should be set to yes"
      echo "------STATUS: $isVulnerability"

      IgnoreRhosts=`grep "^IgnoreRhosts" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "IgnoreRhosts yes" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - IgnoreRhosts Should be set to yes"
      echo "------STATUS: $isVulnerability"

      HostbasedAuthentication=`grep "^HostbasedAuthentication" /etc/ssh/sshd_config`
      if [[ $X11Forwarding == "HostbasedAuthentication no" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "/etc/ssh/sshd_config - HostbasedAuthentication Should be set to no"
      echo "------STATUS: $isVulnerability"



#---------Reference: https://wiki.centos.org/HowTos/OS_Protection --------------
#------------Require root passowrd when booting to single user------------------

      rootonsingleuser=`grep "^~~:S:wait:/sbin/sulogin" /etc/inittab`
      if [[ $rootonsingleuser == "~~:S:wait:/sbin/sulogin" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "Require the root pw when booting into single user mode"
      echo "------STATUS: $isVulnerability"

#------------No one other than root should be allowed in root's home directory------------------
      rootonlyallowrdinrootdir=`ls -ld /root | grep "^drwx------"`
      if [[ $rootonlyallowrdinrootdir == "drwx------"*"root" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "Permission on /root should be "drwx------" or 700"
      echo "------STATUS: $isVulnerability"

#------------Password expires every 180 days------------------
      Passexpireevery180days=`grep "^PASS_MAX_DAYS" /etc/ssh/sshd_config`
      if [[ $Passexpireevery180days == "PASS_MAX_DAYS 180" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "Password should expires every 180 days"
      echo "------STATUS: $isVulnerability"


#------------Password expires every 180 days------------------
      Passchangeonceaday=`grep "^PASS_MIN_DAYS" /etc/login.defs`
      if [[ $Passchangeonceaday == "PASS_MIN_DAYS 1" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "Passwords may only be changed once a day"
      echo "------STATUS: $isVulnerability"


#------------system should use sha512 instead of md5 for password protection------------------
      Passalgo=`authconfig --test | grep "password hashing"`
      if [[ $Passalgo == " password hashing algorithm is md5" ]]
      then
      isVulnerability="OK"
      else
      isVulnerability="NOT OK"
      fi
      echo "system should use sha512 instead of md5 for password protection"
      echo "------STATUS: $isVulnerability"
