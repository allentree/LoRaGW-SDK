#!/bin/bash
pgrep watch_dog;
if [[ $? -ne 0 ]];
then
/sbin/reboot;
fi