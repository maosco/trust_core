#!/bin/sh
# /etc/init.d/multos.sh
### BEGIN INIT INFO
# Provides:          multos.sh
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start daemon at boot time
# Description:       Enable service provided by daemon.
### END INIT INFO

/usr/bin/pigpiod
sleep 1
/usr/bin/multosI2CInterface 1 > /tmp/multosio.log &
