#!/bin/bash
sudo last -a -F -n 5 | sed 's/ :0//g'
