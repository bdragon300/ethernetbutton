EESchema Schematic File Version 2
LIBS:power
LIBS:device
LIBS:transistors
LIBS:conn
LIBS:linear
LIBS:regul
LIBS:74xx
LIBS:cmos4000
LIBS:adc-dac
LIBS:memory
LIBS:xilinx
LIBS:special
LIBS:microcontrollers
LIBS:dsp
LIBS:microchip
LIBS:analog_switches
LIBS:motorola
LIBS:texas
LIBS:intel
LIBS:audio
LIBS:interface
LIBS:digital-audio
LIBS:philips
LIBS:display
LIBS:cypress
LIBS:siliconi
LIBS:opto
LIBS:atmel
LIBS:contrib
LIBS:valves
LIBS:hl1102nl
LIBS:smd_crystal
LIBS:button-cache
EELAYER 27 0
EELAYER END
$Descr A4 11693 8268
encoding utf-8
Sheet 1 1
Title ""
Date "11 apr 2014"
Rev ""
Comp ""
Comment1 ""
Comment2 ""
Comment3 ""
Comment4 ""
$EndDescr
$Comp
L SMD_CRYSTAL X1
U 1 1 527E26AB
P 4800 5650
F 0 "X1" H 4800 5800 60  0000 C CNN
F 1 "SMD_CRYSTAL" H 4800 5500 60  0000 C CNN
F 2 "" H 4800 5650 60  0001 C CNN
F 3 "" H 4800 5650 60  0001 C CNN
	1    4800 5650
	0    -1   -1   0   
$EndComp
$Comp
L USB_1 J1
U 1 1 527E212A
P 2500 1600
F 0 "J1" H 2350 2000 60  0000 C CNN
F 1 "USB_1" H 2475 1000 60  0001 C CNN
F 2 "" H 2500 1600 60  0001 C CNN
F 3 "" H 2500 1600 60  0001 C CNN
	1    2500 1600
	-1   0    0    1   
$EndComp
$Comp
L GND #PWR01
U 1 1 52755EAE
P 6300 3350
F 0 "#PWR01" H 6300 3350 30  0001 C CNN
F 1 "GND" H 6300 3280 30  0001 C CNN
F 2 "" H 6300 3350 60  0001 C CNN
F 3 "" H 6300 3350 60  0001 C CNN
	1    6300 3350
	1    0    0    -1  
$EndComp
$Comp
L C C10
U 1 1 52755EA7
P 6300 2950
F 0 "C10" H 6350 3050 50  0000 L CNN
F 1 "100nF" H 6350 2850 50  0000 L CNN
F 2 "" H 6300 2950 60  0001 C CNN
F 3 "" H 6300 2950 60  0001 C CNN
	1    6300 2950
	1    0    0    -1  
$EndComp
$Comp
L GND #PWR02
U 1 1 52755E33
P 1400 3100
F 0 "#PWR02" H 1400 3100 30  0001 C CNN
F 1 "GND" H 1400 3030 30  0001 C CNN
F 2 "" H 1400 3100 60  0001 C CNN
F 3 "" H 1400 3100 60  0001 C CNN
	1    1400 3100
	1    0    0    -1  
$EndComp
$Comp
L C C9
U 1 1 52755E1D
P 1400 2750
F 0 "C9" H 1450 2850 50  0000 L CNN
F 1 "100nF" H 1450 2650 50  0000 L CNN
F 2 "" H 1400 2750 60  0001 C CNN
F 3 "" H 1400 2750 60  0001 C CNN
	1    1400 2750
	1    0    0    -1  
$EndComp
$Comp
L C C4
U 1 1 52751D03
P 4700 4850
F 0 "C4" H 4750 4950 50  0000 L CNN
F 1 "10uF" H 4750 4750 50  0000 L CNN
F 2 "" H 4700 4850 60  0001 C CNN
F 3 "" H 4700 4850 60  0001 C CNN
	1    4700 4850
	0    -1   -1   0   
$EndComp
$Comp
L GND #PWR03
U 1 1 5274CD85
P 10350 1300
F 0 "#PWR03" H 10350 1300 30  0001 C CNN
F 1 "GND" H 10350 1230 30  0001 C CNN
F 2 "" H 10350 1300 60  0001 C CNN
F 3 "" H 10350 1300 60  0001 C CNN
	1    10350 1300
	1    0    0    -1  
$EndComp
$Comp
L R R3
U 1 1 5274C4B6
P 800 3250
F 0 "R3" V 880 3250 50  0000 C CNN
F 1 "10K" V 800 3250 50  0000 C CNN
F 2 "" H 800 3250 60  0001 C CNN
F 3 "" H 800 3250 60  0001 C CNN
	1    800  3250
	-1   0    0    1   
$EndComp
NoConn ~ 3150 3400
$Comp
L CONN_5X2 P4
U 1 1 5274C3F4
P 3250 3000
F 0 "P4" H 3250 3300 60  0000 C CNN
F 1 "ISP Prog" V 3250 3000 50  0000 C CNN
F 2 "" H 3250 3000 60  0001 C CNN
F 3 "" H 3250 3000 60  0001 C CNN
	1    3250 3000
	0    -1   -1   0   
$EndComp
$Comp
L GND #PWR04
U 1 1 5274016A
P 3100 2150
F 0 "#PWR04" H 3100 2150 30  0001 C CNN
F 1 "GND" H 3100 2080 30  0001 C CNN
F 2 "" H 3100 2150 60  0001 C CNN
F 3 "" H 3100 2150 60  0001 C CNN
	1    3100 2150
	1    0    0    -1  
$EndComp
$Comp
L C C2
U 1 1 5273FCDE
P 4650 1750
F 0 "C2" H 4700 1850 50  0000 L CNN
F 1 "10uF" H 4700 1650 50  0000 L CNN
F 2 "" H 4650 1750 60  0001 C CNN
F 3 "" H 4650 1750 60  0001 C CNN
	1    4650 1750
	1    0    0    -1  
$EndComp
$Comp
L C C1
U 1 1 5273FCD9
P 3550 1750
F 0 "C1" H 3600 1850 50  0000 L CNN
F 1 "0.33uF" H 3600 1650 50  0000 L CNN
F 2 "" H 3550 1750 60  0001 C CNN
F 3 "" H 3550 1750 60  0001 C CNN
	1    3550 1750
	1    0    0    -1  
$EndComp
$Comp
L +3.3V #PWR05
U 1 1 5273FCA8
P 4850 1250
F 0 "#PWR05" H 4850 1210 30  0001 C CNN
F 1 "+3.3V" H 4850 1360 30  0000 C CNN
F 2 "" H 4850 1250 60  0001 C CNN
F 3 "" H 4850 1250 60  0001 C CNN
	1    4850 1250
	1    0    0    -1  
$EndComp
$Comp
L LT1585CM Q1
U 1 1 5273FC73
P 4100 1550
F 0 "Q1" H 4100 1850 60  0000 C CNN
F 1 "MC33269DT" H 4100 1550 50  0000 C CNN
F 2 "" H 4100 1550 60  0001 C CNN
F 3 "" H 4100 1550 60  0001 C CNN
	1    4100 1550
	1    0    0    -1  
$EndComp
$Comp
L GND #PWR06
U 1 1 5273EDBD
P 4100 2150
F 0 "#PWR06" H 4100 2150 30  0001 C CNN
F 1 "GND" H 4100 2080 30  0001 C CNN
F 2 "" H 4100 2150 60  0001 C CNN
F 3 "" H 4100 2150 60  0001 C CNN
	1    4100 2150
	1    0    0    -1  
$EndComp
$Comp
L +3.3V #PWR07
U 1 1 5273ED52
P 4600 2850
F 0 "#PWR07" H 4600 2810 30  0001 C CNN
F 1 "+3.3V" H 4600 2960 30  0000 C CNN
F 2 "" H 4600 2850 60  0001 C CNN
F 3 "" H 4600 2850 60  0001 C CNN
	1    4600 2850
	1    0    0    -1  
$EndComp
$Comp
L R R6
U 1 1 5273EB3F
P 4600 3300
F 0 "R6" V 4680 3300 50  0000 C CNN
F 1 "1K" V 4600 3300 50  0000 C CNN
F 2 "" H 4600 3300 60  0001 C CNN
F 3 "" H 4600 3300 60  0001 C CNN
	1    4600 3300
	1    0    0    -1  
$EndComp
$Comp
L R R5
U 1 1 5273EB3D
P 4400 3300
F 0 "R5" V 4480 3300 50  0000 C CNN
F 1 "1K" V 4400 3300 50  0000 C CNN
F 2 "" H 4400 3300 60  0001 C CNN
F 3 "" H 4400 3300 60  0001 C CNN
	1    4400 3300
	1    0    0    -1  
$EndComp
$Comp
L +3.3V #PWR08
U 1 1 5273E606
P 6850 1000
F 0 "#PWR08" H 6850 960 30  0001 C CNN
F 1 "+3.3V" H 6850 1110 30  0000 C CNN
F 2 "" H 6850 1000 60  0001 C CNN
F 3 "" H 6850 1000 60  0001 C CNN
	1    6850 1000
	1    0    0    -1  
$EndComp
$Comp
L R R1
U 1 1 5273E55C
P 6850 1450
F 0 "R1" V 6930 1450 50  0000 C CNN
F 1 "150" V 6850 1450 50  0000 C CNN
F 2 "" H 6850 1450 60  0001 C CNN
F 3 "" H 6850 1450 60  0001 C CNN
	1    6850 1450
	-1   0    0    1   
$EndComp
$Comp
L R R2
U 1 1 5273E558
P 7250 1450
F 0 "R2" V 7330 1450 50  0000 C CNN
F 1 "150" V 7250 1450 50  0000 C CNN
F 2 "" H 7250 1450 60  0001 C CNN
F 3 "" H 7250 1450 60  0001 C CNN
	1    7250 1450
	-1   0    0    1   
$EndComp
$Comp
L +3.3V #PWR09
U 1 1 5273E3CF
P 800 2850
F 0 "#PWR09" H 800 2810 30  0001 C CNN
F 1 "+3.3V" H 800 2960 30  0000 C CNN
F 2 "" H 800 2850 60  0001 C CNN
F 3 "" H 800 2850 60  0001 C CNN
	1    800  2850
	1    0    0    -1  
$EndComp
NoConn ~ 6650 5000
$Comp
L GND #PWR010
U 1 1 5273D617
P 4250 5300
F 0 "#PWR010" H 4250 5300 30  0001 C CNN
F 1 "GND" H 4250 5230 30  0001 C CNN
F 2 "" H 4250 5300 60  0001 C CNN
F 3 "" H 4250 5300 60  0001 C CNN
	1    4250 5300
	1    0    0    -1  
$EndComp
$Comp
L GND #PWR011
U 1 1 5273D5A3
P 4800 6650
F 0 "#PWR011" H 4800 6650 30  0001 C CNN
F 1 "GND" H 4800 6580 30  0001 C CNN
F 2 "" H 4800 6650 60  0001 C CNN
F 3 "" H 4800 6650 60  0001 C CNN
	1    4800 6650
	1    0    0    -1  
$EndComp
$Comp
L GND #PWR012
U 1 1 5273D4E3
P 6050 6200
F 0 "#PWR012" H 6050 6200 30  0001 C CNN
F 1 "GND" H 6050 6130 30  0001 C CNN
F 2 "" H 6050 6200 60  0001 C CNN
F 3 "" H 6050 6200 60  0001 C CNN
	1    6050 6200
	1    0    0    -1  
$EndComp
$Comp
L +3.3V #PWR013
U 1 1 5273D4C4
P 5700 2700
F 0 "#PWR013" H 5700 2660 30  0001 C CNN
F 1 "+3.3V" H 5700 2810 30  0000 C CNN
F 2 "" H 5700 2700 60  0001 C CNN
F 3 "" H 5700 2700 60  0001 C CNN
	1    5700 2700
	1    0    0    -1  
$EndComp
$Comp
L +3.3V #PWR014
U 1 1 5273D410
P 8450 1400
F 0 "#PWR014" H 8450 1360 30  0001 C CNN
F 1 "+3.3V" H 8450 1510 30  0000 C CNN
F 2 "" H 8450 1400 60  0001 C CNN
F 3 "" H 8450 1400 60  0001 C CNN
	1    8450 1400
	1    0    0    -1  
$EndComp
$Comp
L GND #PWR015
U 1 1 5273D28D
P 7250 5800
F 0 "#PWR015" H 7250 5800 30  0001 C CNN
F 1 "GND" H 7250 5730 30  0001 C CNN
F 2 "" H 7250 5800 60  0001 C CNN
F 3 "" H 7250 5800 60  0001 C CNN
	1    7250 5800
	1    0    0    -1  
$EndComp
$Comp
L C C8
U 1 1 5273D038
P 10600 6350
F 0 "C8" H 10650 6450 50  0000 L CNN
F 1 "1nF 1KV" H 10650 6250 50  0000 L CNN
F 2 "" H 10600 6350 60  0001 C CNN
F 3 "" H 10600 6350 60  0001 C CNN
	1    10600 6350
	1    0    0    -1  
$EndComp
$Comp
L GND #PWR016
U 1 1 5273CF68
P 10600 6750
F 0 "#PWR016" H 10600 6750 30  0001 C CNN
F 1 "GND" H 10600 6680 30  0001 C CNN
F 2 "" H 10600 6750 60  0001 C CNN
F 3 "" H 10600 6750 60  0001 C CNN
	1    10600 6750
	1    0    0    -1  
$EndComp
$Comp
L R R13
U 1 1 5273CF0F
P 9300 5800
F 0 "R13" V 9380 5800 50  0000 C CNN
F 1 "75" V 9300 5800 50  0000 C CNN
F 2 "" H 9300 5800 60  0001 C CNN
F 3 "" H 9300 5800 60  0001 C CNN
	1    9300 5800
	1    0    0    -1  
$EndComp
$Comp
L R R14
U 1 1 5273CF0C
P 10800 5800
F 0 "R14" V 10880 5800 50  0000 C CNN
F 1 "75" V 10800 5800 50  0000 C CNN
F 2 "" H 10800 5800 60  0001 C CNN
F 3 "" H 10800 5800 60  0001 C CNN
	1    10800 5800
	1    0    0    -1  
$EndComp
$Comp
L R R15
U 1 1 5273CF09
P 10950 5800
F 0 "R15" V 11030 5800 50  0000 C CNN
F 1 "75" V 10950 5800 50  0000 C CNN
F 2 "" H 10950 5800 60  0001 C CNN
F 3 "" H 10950 5800 60  0001 C CNN
	1    10950 5800
	1    0    0    -1  
$EndComp
$Comp
L R R16
U 1 1 5273CF01
P 11100 5800
F 0 "R16" V 11180 5800 50  0000 C CNN
F 1 "75" V 11100 5800 50  0000 C CNN
F 2 "" H 11100 5800 60  0001 C CNN
F 3 "" H 11100 5800 60  0001 C CNN
	1    11100 5800
	1    0    0    -1  
$EndComp
$Comp
L H1102NL T1
U 1 1 5273CD3B
P 9400 4550
F 0 "T1" H 9450 5250 70  0000 C CNN
F 1 "H1102NL" H 9050 3950 70  0000 C CNN
F 2 "" H 9400 4550 60  0001 C CNN
F 3 "" H 9400 4550 60  0001 C CNN
	1    9400 4550
	1    0    0    -1  
$EndComp
$Comp
L INDUCTOR L1
U 1 1 52716042
P 8450 1950
F 0 "L1" V 8400 1950 40  0000 C CNN
F 1 "100uH" V 8550 1950 40  0000 C CNN
F 2 "" H 8450 1950 60  0001 C CNN
F 3 "" H 8450 1950 60  0001 C CNN
	1    8450 1950
	-1   0    0    1   
$EndComp
$Comp
L R R8
U 1 1 52715FF8
P 7950 4050
F 0 "R8" V 8030 4050 50  0000 C CNN
F 1 "50" V 7950 4050 50  0000 C CNN
F 2 "" H 7950 4050 60  0001 C CNN
F 3 "" H 7950 4050 60  0001 C CNN
	1    7950 4050
	0    -1   -1   0   
$EndComp
$Comp
L R R9
U 1 1 52715FF7
P 7950 4450
F 0 "R9" V 8030 4450 50  0000 C CNN
F 1 "50" V 7950 4450 50  0000 C CNN
F 2 "" H 7950 4450 60  0001 C CNN
F 3 "" H 7950 4450 60  0001 C CNN
	1    7950 4450
	0    -1   -1   0   
$EndComp
$Comp
L C C3
U 1 1 52715FF6
P 7450 4450
F 0 "C3" H 7500 4550 50  0000 L CNN
F 1 "10nF" H 7500 4350 50  0000 L CNN
F 2 "" H 7450 4450 60  0001 C CNN
F 3 "" H 7450 4450 60  0001 C CNN
	1    7450 4450
	0    1    1    0   
$EndComp
$Comp
L C C5
U 1 1 52715FC6
P 7450 5050
F 0 "C5" H 7500 5150 50  0000 L CNN
F 1 "10nF" H 7500 4950 50  0000 L CNN
F 2 "" H 7450 5050 60  0001 C CNN
F 3 "" H 7450 5050 60  0001 C CNN
	1    7450 5050
	0    1    1    0   
$EndComp
$Comp
L R R11
U 1 1 52715FB4
P 7950 5050
F 0 "R11" V 8030 5050 50  0000 C CNN
F 1 "50" V 7950 5050 50  0000 C CNN
F 2 "" H 7950 5050 60  0001 C CNN
F 3 "" H 7950 5050 60  0001 C CNN
	1    7950 5050
	0    -1   -1   0   
$EndComp
$Comp
L R R10
U 1 1 52715FB1
P 7950 4650
F 0 "R10" V 8030 4650 50  0000 C CNN
F 1 "50" V 7950 4650 50  0000 C CNN
F 2 "" H 7950 4650 60  0001 C CNN
F 3 "" H 7950 4650 60  0001 C CNN
	1    7950 4650
	0    -1   -1   0   
$EndComp
$Comp
L C C7
U 1 1 52715F1D
P 4800 6250
F 0 "C7" H 4850 6350 50  0000 L CNN
F 1 "16p" H 4850 6150 50  0000 L CNN
F 2 "" H 4800 6250 60  0001 C CNN
F 3 "" H 4800 6250 60  0001 C CNN
	1    4800 6250
	-1   0    0    1   
$EndComp
$Comp
L C C6
U 1 1 52715F13
P 4450 5550
F 0 "C6" H 4500 5650 50  0000 L CNN
F 1 "16p" H 4500 5450 50  0000 L CNN
F 2 "" H 4450 5550 60  0001 C CNN
F 3 "" H 4450 5550 60  0001 C CNN
	1    4450 5550
	-1   0    0    1   
$EndComp
$Comp
L R R7
U 1 1 52715EB0
P 4850 3700
F 0 "R7" V 4930 3700 50  0000 C CNN
F 1 "10K" V 4850 3700 50  0000 C CNN
F 2 "" H 4850 3700 60  0001 C CNN
F 3 "" H 4850 3700 60  0001 C CNN
	1    4850 3700
	1    0    0    -1  
$EndComp
$Comp
L R R12
U 1 1 52715E78
P 4650 5150
F 0 "R12" V 4730 5150 50  0000 C CNN
F 1 "2K 1%" V 4650 5150 50  0000 C CNN
F 2 "" H 4650 5150 60  0001 C CNN
F 3 "" H 4650 5150 60  0001 C CNN
	1    4650 5150
	0    -1   -1   0   
$EndComp
$Comp
L ENC28J60 U1
U 1 1 52715C03
P 5800 4750
F 0 "U1" H 6200 5900 60  0000 L CNN
F 1 "ENC28J60" H 6150 3650 60  0000 L CNN
F 2 "" H 5800 4750 60  0001 C CNN
F 3 "" H 5800 4750 60  0001 C CNN
	1    5800 4750
	1    0    0    -1  
$EndComp
$Comp
L RJ45 J2
U 1 1 5348241F
P 9600 1450
F 0 "J2" H 9800 1950 60  0000 C CNN
F 1 "RJ45" H 9450 1950 60  0000 C CNN
F 2 "" H 9600 1450 60  0000 C CNN
F 3 "" H 9600 1450 60  0000 C CNN
	1    9600 1450
	1    0    0    -1  
$EndComp
$Comp
L LED D1
U 1 1 534835BA
P 6850 2150
F 0 "D1" H 6850 2250 50  0000 C CNN
F 1 "LED" H 6850 2050 50  0000 C CNN
F 2 "~" H 6850 2150 60  0000 C CNN
F 3 "~" H 6850 2150 60  0000 C CNN
	1    6850 2150
	0    1    1    0   
$EndComp
$Comp
L LED D2
U 1 1 534835D3
P 7250 2150
F 0 "D2" H 7250 2250 50  0000 C CNN
F 1 "LED" H 7250 2050 50  0000 C CNN
F 2 "~" H 7250 2150 60  0000 C CNN
F 3 "~" H 7250 2150 60  0000 C CNN
	1    7250 2150
	0    1    1    0   
$EndComp
$Comp
L ATMEGA8A-A IC1
U 1 1 53484181
P 1750 5050
F 0 "IC1" H 1000 6250 40  0000 L BNN
F 1 "ATMEGA8A-A" H 2250 3500 40  0000 L BNN
F 2 "TQFP32" H 1750 5050 30  0000 C CIN
F 3 "" H 1750 5050 60  0000 C CNN
	1    1750 5050
	1    0    0    -1  
$EndComp
$Comp
L CONN_2X2 P2
U 1 1 53484DAF
P 4050 6150
F 0 "P2" H 4050 6300 50  0000 C CNN
F 1 "BTNS" H 4060 6020 40  0000 C CNN
F 2 "" H 4050 6150 60  0000 C CNN
F 3 "" H 4050 6150 60  0000 C CNN
	1    4050 6150
	0    -1   -1   0   
$EndComp
Wire Wire Line
	2850 5850 2750 5850
Wire Wire Line
	2850 7200 2850 5850
Wire Wire Line
	6750 7200 2850 7200
Wire Wire Line
	6750 4650 6750 7200
Wire Wire Line
	6650 4650 6750 4650
Wire Wire Line
	1700 6650 1800 6650
Wire Wire Line
	1700 6650 1700 7050
Wire Wire Line
	650  6750 1700 6750
Wire Wire Line
	800  4050 850  4050
Wire Wire Line
	700  3750 1800 3750
Wire Wire Line
	3100 2150 3100 1250
Wire Wire Line
	3100 1250 2900 1250
Wire Wire Line
	7350 3800 8250 3800
Wire Wire Line
	8200 5050 8550 5050
Wire Wire Line
	6300 3350 6300 3150
Wire Wire Line
	1400 2950 1400 3100
Wire Wire Line
	6950 3100 6950 5300
Connection ~ 800  3500
Wire Wire Line
	800  3500 3250 3500
Wire Wire Line
	800  3500 800  4050
Wire Wire Line
	3250 3500 3250 3400
Wire Wire Line
	4600 3550 4600 4050
Wire Wire Line
	4600 4050 4100 4050
Connection ~ 4600 3050
Wire Wire Line
	4600 3050 4600 2850
Wire Wire Line
	3800 3050 4600 3050
Connection ~ 4100 2050
Wire Wire Line
	4650 2050 4650 1950
Wire Wire Line
	3550 2050 4650 2050
Wire Wire Line
	3550 2050 3550 1950
Wire Wire Line
	4500 1400 4850 1400
Wire Wire Line
	4850 1400 4850 1250
Wire Wire Line
	7250 4050 7250 3650
Wire Wire Line
	7250 4050 6650 4050
Wire Wire Line
	6850 1000 6850 1200
Wire Wire Line
	4900 4850 5050 4850
Wire Wire Line
	4450 5350 5050 5350
Wire Wire Line
	2750 4350 5050 4350
Wire Wire Line
	3450 4550 5050 4550
Connection ~ 4400 5150
Wire Wire Line
	4400 5150 4400 4850
Wire Wire Line
	4400 4850 4500 4850
Connection ~ 4800 6550
Wire Wire Line
	4800 6450 4800 6650
Wire Wire Line
	4800 6050 4800 5950
Wire Wire Line
	4850 3950 4850 4050
Wire Wire Line
	4850 4050 5050 4050
Connection ~ 5750 6050
Connection ~ 5850 6050
Connection ~ 5950 6050
Connection ~ 6050 6050
Wire Wire Line
	6050 6050 6050 6200
Connection ~ 5700 3350
Connection ~ 5800 3350
Connection ~ 5900 3350
Connection ~ 6000 3350
Wire Wire Line
	8400 5350 7150 5350
Wire Wire Line
	7150 5350 7150 4300
Wire Wire Line
	7150 4300 6650 4300
Connection ~ 7250 5050
Wire Wire Line
	7250 4450 7250 5800
Wire Wire Line
	7700 4650 7700 5050
Connection ~ 7700 4250
Wire Wire Line
	7700 4050 7700 4450
Wire Wire Line
	8200 4050 8550 4050
Wire Wire Line
	10600 6550 10600 6750
Wire Wire Line
	9300 5550 9300 5450
Connection ~ 10800 6050
Connection ~ 10950 6050
Wire Wire Line
	9300 6050 11100 6050
Connection ~ 10600 6050
Wire Wire Line
	10600 6050 10600 6150
Wire Wire Line
	7700 4250 8550 4250
Wire Wire Line
	8200 4650 8550 4650
Wire Wire Line
	7700 4450 7650 4450
Wire Wire Line
	7700 5050 7650 5050
Connection ~ 7700 5050
Connection ~ 7700 4450
Wire Wire Line
	6650 4150 7350 4150
Wire Wire Line
	7350 4150 7350 3800
Wire Wire Line
	6650 4400 7050 4400
Wire Wire Line
	7050 4400 7050 5500
Wire Wire Line
	7050 5500 8500 5500
Wire Wire Line
	5650 6050 6050 6050
Wire Wire Line
	4850 3450 4850 3350
Wire Wire Line
	4850 3350 6100 3350
Connection ~ 4800 5350
Wire Wire Line
	4450 6550 4450 5750
Connection ~ 4800 5950
Wire Wire Line
	4250 5300 4250 5150
Wire Wire Line
	4250 5150 4400 5150
Wire Wire Line
	3250 4450 5050 4450
Wire Wire Line
	3150 4250 5050 4250
Wire Wire Line
	4800 5950 5050 5950
Wire Wire Line
	5050 5950 5050 5450
Wire Wire Line
	4900 5150 5050 5150
Wire Wire Line
	5050 5150 5050 5050
Wire Wire Line
	8450 1400 8450 1650
Wire Wire Line
	6850 1200 7250 1200
Connection ~ 6850 1200
Wire Wire Line
	6950 5300 6650 5300
Wire Wire Line
	6850 5200 6650 5200
Connection ~ 4450 6550
Connection ~ 4100 6550
Connection ~ 4000 6550
Wire Wire Line
	4100 1900 4100 2150
Wire Wire Line
	3550 1550 3550 1400
Connection ~ 3550 1400
Wire Wire Line
	4650 1550 4650 1400
Connection ~ 4650 1400
Wire Wire Line
	7700 4850 8550 4850
Connection ~ 7700 4850
Wire Wire Line
	4000 3950 4000 5750
Wire Wire Line
	4000 3950 4400 3950
Wire Wire Line
	4400 3950 4400 3550
Wire Wire Line
	800  3000 800  2850
Wire Wire Line
	1700 2050 1700 3750
Wire Wire Line
	6850 2350 6850 5200
Wire Wire Line
	5700 2700 5700 3350
Wire Wire Line
	6300 2750 5700 2750
Connection ~ 5700 2750
Wire Wire Line
	8200 4450 8550 4450
Wire Wire Line
	7250 3650 8350 3650
Wire Wire Line
	2900 1400 3700 1400
Wire Wire Line
	4100 4050 4100 5750
Wire Wire Line
	8500 5500 8500 4650
Connection ~ 8500 4650
Wire Wire Line
	8250 3800 8250 4050
Connection ~ 8250 4050
Wire Wire Line
	8350 3650 8350 4450
Connection ~ 8350 4450
Wire Wire Line
	8450 2250 8450 4250
Connection ~ 8450 4250
Wire Wire Line
	8400 5350 8400 5050
Connection ~ 8400 5050
Wire Wire Line
	10350 1300 10350 1100
Wire Wire Line
	10350 1100 10150 1100
Wire Wire Line
	9300 3650 10800 3650
Wire Wire Line
	10800 3650 10800 5550
Wire Wire Line
	10250 4050 10250 3500
Wire Wire Line
	10250 3500 9250 3500
Wire Wire Line
	9250 3500 9250 1900
Wire Wire Line
	10250 4450 10400 4450
Wire Wire Line
	10400 4450 10400 3300
Wire Wire Line
	10400 3300 9350 3300
Wire Wire Line
	9350 3300 9350 1900
Wire Wire Line
	10250 4650 10550 4650
Wire Wire Line
	10550 4650 10550 3150
Wire Wire Line
	10550 3150 9450 3150
Wire Wire Line
	9450 3150 9450 1900
Wire Wire Line
	10250 5050 10700 5050
Wire Wire Line
	10700 5050 10700 3000
Wire Wire Line
	10700 3000 9750 3000
Wire Wire Line
	9750 3000 9750 1900
Wire Wire Line
	10950 5550 10950 2850
Wire Wire Line
	10950 2850 9650 2850
Wire Wire Line
	9650 2850 9650 1900
Wire Wire Line
	9650 1900 9550 1900
Wire Wire Line
	11100 5550 11100 2750
Wire Wire Line
	11100 2750 9950 2750
Wire Wire Line
	9950 2750 9950 1900
Wire Wire Line
	9950 1900 9850 1900
Wire Wire Line
	6950 3100 7250 3100
Wire Wire Line
	7250 3100 7250 2350
Wire Wire Line
	6850 1700 6850 1950
Wire Wire Line
	7250 1700 7250 1950
Wire Wire Line
	3250 4450 3250 4550
Wire Wire Line
	3250 4550 2750 4550
Wire Wire Line
	3150 4250 3150 4450
Wire Wire Line
	3150 4450 2750 4450
Wire Wire Line
	3450 4550 3450 4650
Wire Wire Line
	3450 4650 2900 4650
Wire Wire Line
	2900 4650 2900 4250
Wire Wire Line
	2900 4250 2750 4250
$Comp
L CONN_2X2 P1
U 1 1 534852AF
P 3600 6550
F 0 "P1" H 3600 6700 50  0000 C CNN
F 1 "LEDS" H 3610 6420 40  0000 C CNN
F 2 "" H 3600 6550 60  0000 C CNN
F 3 "" H 3600 6550 60  0000 C CNN
	1    3600 6550
	0    -1   -1   0   
$EndComp
Wire Wire Line
	2750 5450 4100 5450
Connection ~ 4100 5450
Wire Wire Line
	2750 5350 4000 5350
Connection ~ 4000 5350
$Comp
L R R4
U 1 1 53485859
P 3100 5650
F 0 "R4" V 3180 5650 40  0000 C CNN
F 1 "50" V 3107 5651 40  0000 C CNN
F 2 "~" V 3030 5650 30  0000 C CNN
F 3 "~" H 3100 5650 30  0000 C CNN
	1    3100 5650
	0    -1   -1   0   
$EndComp
$Comp
L R R17
U 1 1 53485868
P 3250 5850
F 0 "R17" V 3330 5850 40  0000 C CNN
F 1 "50" V 3257 5851 40  0000 C CNN
F 2 "~" V 3180 5850 30  0000 C CNN
F 3 "~" H 3250 5850 30  0000 C CNN
	1    3250 5850
	0    -1   -1   0   
$EndComp
Wire Wire Line
	2750 5650 2850 5650
Wire Wire Line
	2750 5750 3000 5750
Wire Wire Line
	3000 5750 3000 5850
Wire Wire Line
	4000 6950 4000 6550
Wire Wire Line
	4000 6550 4800 6550
NoConn ~ 2750 5250
NoConn ~ 2750 5150
NoConn ~ 2750 5050
NoConn ~ 2750 4950
NoConn ~ 2750 4850
NoConn ~ 2750 4750
Wire Wire Line
	3550 6950 4000 6950
Connection ~ 3650 6950
NoConn ~ 2750 5950
NoConn ~ 2750 6050
NoConn ~ 2750 6150
NoConn ~ 2750 6250
NoConn ~ 2750 6350
NoConn ~ 2750 4150
NoConn ~ 2750 4050
Connection ~ 1700 3750
Wire Wire Line
	850  4250 700  4250
Wire Wire Line
	700  4250 700  3750
Wire Wire Line
	850  4450 650  4450
Connection ~ 1700 6650
NoConn ~ 850  4750
NoConn ~ 850  4950
Wire Wire Line
	850  4350 850  4250
Connection ~ 850  4250
$Comp
L GND #PWR017
U 1 1 534842DE
P 1700 7050
F 0 "#PWR017" H 1700 7050 30  0001 C CNN
F 1 "GND" H 1700 6980 30  0001 C CNN
F 2 "" H 1700 7050 60  0000 C CNN
F 3 "" H 1700 7050 60  0000 C CNN
	1    1700 7050
	1    0    0    -1  
$EndComp
Connection ~ 1700 6750
$Comp
L +3,3V #PWR018
U 1 1 53484627
P 1700 2050
F 0 "#PWR018" H 1700 2010 30  0001 C CNN
F 1 "+3,3V" H 1700 2160 30  0000 C CNN
F 2 "" H 1700 2050 60  0000 C CNN
F 3 "" H 1700 2050 60  0000 C CNN
	1    1700 2050
	1    0    0    -1  
$EndComp
$Comp
L R R18
U 1 1 53484708
P 3800 3750
F 0 "R18" V 3880 3750 40  0000 C CNN
F 1 "10K" V 3807 3751 40  0000 C CNN
F 2 "~" V 3730 3750 30  0000 C CNN
F 3 "~" H 3800 3750 30  0000 C CNN
	1    3800 3750
	1    0    0    -1  
$EndComp
Wire Wire Line
	3800 3500 3800 3050
Connection ~ 4400 3050
Wire Wire Line
	3800 4000 3800 4550
Connection ~ 3800 4550
Wire Wire Line
	3050 3400 3050 4350
Connection ~ 3050 4350
Wire Wire Line
	3350 3400 3350 4450
Connection ~ 3350 4450
Wire Wire Line
	3450 3400 3550 3400
Wire Wire Line
	3550 3400 3550 4250
Connection ~ 3550 4250
$Comp
L GND #PWR019
U 1 1 53485784
P 3750 2750
F 0 "#PWR019" H 3750 2750 30  0001 C CNN
F 1 "GND" H 3750 2680 30  0001 C CNN
F 2 "" H 3750 2750 60  0000 C CNN
F 3 "" H 3750 2750 60  0000 C CNN
	1    3750 2750
	1    0    0    -1  
$EndComp
Wire Wire Line
	3150 2600 3750 2600
Wire Wire Line
	3750 2600 3750 2750
Connection ~ 3250 2600
Connection ~ 3350 2600
Connection ~ 3450 2600
Wire Wire Line
	3050 2400 3050 2600
Wire Wire Line
	1400 2400 3050 2400
Connection ~ 1700 2400
Wire Wire Line
	1400 2550 1400 2400
Wire Wire Line
	650  4450 650  6750
Wire Wire Line
	3500 5850 3650 5850
Wire Wire Line
	3650 5850 3650 6150
Wire Wire Line
	3350 5650 3550 5650
Wire Wire Line
	3550 5650 3550 6150
$EndSCHEMATC