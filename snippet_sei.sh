!#/bin/sh

echo "How to list TCP tracepoints in your kernel "

echo " Kernel Version: "
uname -r

echo " List of TCP tracepoints: "
ls /sys/kernel/debug/tracing/events/tcp/


echo " To enable a tracepoint, you can use the following command: "
echo " sudo echo 1 > /sys/kernel/debug/tracing/events/tcp/tcp_connect/enable "


bpftrace -l "tracepoint:tcp:*"




