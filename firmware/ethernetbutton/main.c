#include <avr/io.h>
#include <avr/eeprom.h>
#include <avr/interrupt.h>
#include <string.h>

#include "enc28j60.h"

#define CTLPORT            PORTD
#define CTLPIN             PIND
#define CTLDDR             DDRD

#define CTL_BUTTON          PD0
#define CTL_KEY_ON          PD1

#define LED_BUTTON          PD3
#define LED_KEY_ON          PD4
#define LED_KEY_OFF         PD5
#define LED_STANDBY			PD5
#define LED_ALARM			PD3

#define MAX_BUFFER_SIZE 64

typedef enum { false, true } bool;

bool doSend = false;
bool ctlKey = false;
bool ctlButton = false;
bool linkActive = false;
uint8_t packetBuffer[MAX_BUFFER_SIZE];

uint8_t eedata[] EEMEM = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xd2, 0x72,
	0x81, 0xa1, 0x52, 0x25, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0xff, 0x11,
	0x1f, 0x3b, 0xc0, 0xa8, 0x64, 0x05, 0xc0, 0xa8,
	0x64, 0xff, 0x3e, 0x3f, 0x30, 0x38, 0x00, 0x14,
	0xaa, 0xba, 0x73, 0x63, 0x64, 0x20, 0x73, 0x68,
	0x75, 0x74, 0x64, 0x6f, 0x77, 0x6e
	}; 

void readStatus()
{
	ctlKey = ! (CTLPIN & (1<<CTL_KEY_ON));
	ctlButton = ! (CTLPIN & (1<<CTL_BUTTON));
	linkActive = (enc28j60_read_phy(PHSTAT2) & PHSTAT2_LSTAT ? true : false);
	
	doSend = ctlButton || doSend;
}

void setLeds()
{
	//Clear all LEDs
	CTLPORT &= ~((1<<LED_BUTTON) | (1<<LED_KEY_OFF) | (1<<LED_KEY_ON));

	if ( ! doSend) {
		CTLPORT |= (1<<LED_STANDBY);
	}

	if ( ! linkActive) {
		CTLPORT |= (1<<LED_STANDBY);
		CTLPORT |= (1<<LED_ALARM);
	}

	//if (ctlKey) { //Key is on
		//CTLPORT |= (1<<LED_KEY_ON);
	//} else { //Key is off
		//CTLPORT |= (1<<LED_KEY_OFF);
	//}

	//Key just switched on but the button not pressed yet - turn on button light
	//if (ctlKey && ! doSend) {
		//CTLPORT |= (1<<LED_BUTTON);
	//}
}


void ledFlash()
{
	CTLPORT |= (1<<LED_ALARM);
	_delay_ms(50);
	CTLPORT &= ~(1<<LED_ALARM);
}


int main()
{
	_delay_ms(20);

	DDRA |= (1<<PA0);
	PORTA |= (1<<PA0);
	
	//Init control port
	//CTLDDR |= (1<<LED_BUTTON) | (1<<LED_KEY_OFF) | (1<<LED_KEY_ON);
	CTLDDR |= (1<<LED_STANDBY) | (1<<LED_ALARM);
	CTLDDR &= ~((1<<CTL_BUTTON) | (1<<CTL_KEY_ON));

    //Read packet size from EEPROM
    eeprom_busy_wait();
    uint16_t ipsize = eeprom_read_word( (void *)0x11);
    uint8_t pktsize = ipsize + 14; //IP packet size + Ethernet frame header size
	
	//Crop packet if its size exceeds MAX_BUFFER_SIZE
	if (pktsize > MAX_BUFFER_SIZE) {
		pktsize = MAX_BUFFER_SIZE;
	}

    //Read packet from EEPROM
    eeprom_busy_wait();
    eeprom_read_block(packetBuffer, (void*)0x00, pktsize);

	//Get src MAC from packet
	uint8_t mac_addr[6];
	memcpy(mac_addr, &packetBuffer[0x06], 6);
	//sei();
	enc28j60_init(mac_addr);

	//counter_init();


	while(1) {
        readStatus();
		setLeds();
		//uint16_t x = enc28j60_read_phy(PHSTAT2);
        if (linkActive && doSend) {
            enc28j60_send_packet(packetBuffer, pktsize);
            ledFlash();
            _delay_ms(400);
        }
		if ( ! linkActive) {
			//TODO: clear packets, reset pointer in enc28j60
		}
        _delay_ms(100);
	}

	return 0;
}

