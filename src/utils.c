
#include <stdio.h>
int todo(char* msg)
{
    printf("# TODO MESSAGE: %s\n", msg);
    return -1;
}


#include <stdint.h>

// The checksum field is the 16 bit one's complement of the one's complement sum of all 16 bit words in the header.
// The one's complement of a binary number is the value obtained by inverting (flipping) all the bits in the binary representation of the number.
uint16_t calculate_checksum(uint16_t *packet, int len)
{
	uint32_t sum = 0;

	// addition of 16-bits words
	while (len > 1)
	{
		sum += *packet++;
		len -= 2;
	}
	// if length is odd, add the last byte
	if (len == 1)
		sum += *(uint8_t *)packet;

	// add carry (high 16 bits to low 16 bits) until carry is zero
	// to reduce a 32 bits number into a 16 bits number
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	// return the one's complement of sum
	return (uint16_t)(~sum);
}
