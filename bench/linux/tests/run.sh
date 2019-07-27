#!/bin/bash

FIO=/home/smherwig/src/fio/out/bin/fio

$FIO test-linux-seqread-n1.fio --output ../results/linux-seqread-n1.out
$FIO test-linux-seqread-n2.fio --output ../results/linux-seqread-n2.out
$FIO test-linux-seqread-n3.fio --output ../results/linux-seqread-n3.out
$FIO test-linux-seqread-n4.fio --output ../results/linux-seqread-n4.out
$FIO test-linux-seqread-n5.fio --output ../results/linux-seqread-n5.out
$FIO test-linux-seqread-n6.fio --output ../results/linux-seqread-n6.out
$FIO test-linux-seqread-n7.fio --output ../results/linux-seqread-n7.out
$FIO test-linux-seqread-n8.fio --output ../results/linux-seqread-n8.out
