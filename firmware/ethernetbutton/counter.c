#include "counter.h"

uint16_t ms_count;

uint32_t tick_count;
uint32_t second_count;

ISR(TIMER2_COMP_vect)
{
	++ms_count;
	++tick_count;

	if(ms_count == 1000)
	{
		++second_count;
		ms_count = 0;
	}
}

void counter_init()
{
	// clk = Fcpu/128, mode = CTC, freq = 1 kHz
	TCCR0A = (1<<WGM01);
	TCCR0B = (1<<CS01) | (1<<CS00);
	OCR0A = 156;
	TIMSK |= 1<<OCIE0A;
}
