#!/bin/bash
	

for fname in raid_perf/*; do
	conf=$(basename "$fname")
	echo "running perf benchmark for $conf"

	mkdir -p output_w100
	mkdir -p output_r100
	mkdir -p output_rw50

	sudo ./bdevperf -c $fname -q 16 -w write -M 0 -s 16384 -t 60 2>&1 > output_w100/$conf.out
	sudo ./bdevperf -c $fname -q 16 -w read -M 0 -s 16384 -t 60 2>&1 > output_r100/$conf.out
	sudo ./bdevperf -c $fname -q 16 -w rw -M 50 -s 16384 -t 60 2>&1 > output_rw50/$conf.out
done
