/*
# https://www.bimmerforums.com/forum/newreply.php?do=newreply&p=21662844&noquote=1
# https://www.bimmerforums.com/forum/showthread.php?1153365-Feeler-Open-Source-OBC-Firmware/page31

    wlcd.pde - Example code for controlling an LCD device found in the BMW 3 series from 1992-1999
               with an Arduino.  Please see www.openobc.org for more information regarding the
               particular unit.  Special thanks goes out to M2PC, admin of openobc.org.
               
               Created by Randy Praster, Monday March 28, 2011.  randy22nj@aol.com
               Version 1.0; Released into the public domain.
           

Connections for this example are made as follows:

LCD pin:   Arduino pin:    purpose:
1          +5v             power for LCD controller
2          gnd             ground
3          +5v             power for the LCD contrast
4          +5v             text select pin
5          D4              config_strobe pin *confirmed working with this pin omitted*
6          D5              data_strobe pin
7          D13             used by SPI library; SPI clock pin
8          D11             used by SPI library; MOSI (data) pin
9          D2              final_strobe pin
10         D3              used by SPI library; Slave Select pin

11         to 100khz square wave signal; this can be generated with a 555 IC timer or
           with a PWM circuit running 20us period, 10us pulse width and 50% duty cycle

notes:

	LCD pin 1 is the wire nearest to the left side of the display (the larger text area)
        
	pin 5 is used only when requesting icons.  If using only text this pin can be omitted.           
	This code does not provide access to the hour separating colon as well as other icons
	on the screen.  Look for this support in a future version release. 
	
        The 1 second delays can be reduced to 250ms if you need the LCD to update asap.
        
	This code relies on the SPI routines included with the Arduino software v0022.
        Please keep in mind that future changes to this SPI code could affect the operation
        of this software.

*/

#include <SPI.h>

// Global variables are defined here
 int final_strobe = 2;
 int enable = 3;
 int config_strobe = 4;
 int data_strobe = 5;
 
 int ss = 10; 
 int mosi = 11;
 int miso = 12; //unused but defined here anyway
 int clock = 13;
 
 
void setup()
{

  // write text to the LCD
  writelcd("this is a", "test");

} 

void loop() {}


int writelcd(String seg1,String seg2) {
  
  // set all pin modes (arduino defaults pins to INPUT if not defined otherwise)
  pinMode(final_strobe, OUTPUT);
  pinMode(enable, OUTPUT);
  pinMode(config_strobe, OUTPUT);
  pinMode(data_strobe, OUTPUT);
  pinMode(ss, OUTPUT);
  pinMode(mosi, OUTPUT);
  pinMode(miso, INPUT); // The LCD does not communicate back and this is unused, but defined here anyway for thoroughness.
  pinMode(clock, OUTPUT);
  
  // set default pin states
  digitalWrite(final_strobe, LOW);
  digitalWrite(enable, HIGH);
  digitalWrite(config_strobe, LOW);
  digitalWrite(data_strobe, LOW);
  digitalWrite(clock, LOW);
  
  // delay 1 second
  delayMicroseconds (1000000); 
  
  // begin SPI
  SPI.begin();
  
  // INIT LCD for communication on the SPI bus
  digitalWrite (enable, LOW);
  delayMicroseconds (10);
  digitalWrite (enable, HIGH);
  
  // delay 1 second
  delayMicroseconds (1000000); 
  
  // segment #1 length must be 20 characters.  Apply padding required to ensure this.
  int padneeded = 20 - seg1.length();
  for ( int y = 0; y < padneeded; y++ ) {
    seg1 = seg1 + " ";
  }
 
  // segment #2 length must be 4 characters.  Apply padding required to ensure this.
  int padneeded2 = 4 - seg2.length();
  for ( int y = 0; y < padneeded2; y++ ) {
    seg2 = seg2 + " ";
  } 
  
  // Loop through the data one character at a time, writing the ascii value of each digit to the LCD.
  for ( int x = 0; x < 20; x++ )  {
    SPI.transfer ( int(seg1.charAt(x)) );   
  }

  for ( int x = 0; x < 4; x++ ) {
    SPI.transfer ( int(seg2.charAt(x)) );
  }
    
  // These ascii 32 are needed to pad the entire lcd write buffer to 28 bytes as required by the hardware.
  SPI.transfer (32);
  SPI.transfer (32);
  SPI.transfer (32);
  SPI.transfer (32);

  // the following code requests the LCD to draw its buffer
  // 
  digitalWrite (config_strobe, HIGH);
  delayMicroseconds (50);
  digitalWrite (config_strobe, LOW);
  //
  digitalWrite (data_strobe, HIGH);
  delayMicroseconds (50);
  digitalWrite (data_strobe, LOW);
  //
  digitalWrite (final_strobe, HIGH);
  delayMicroseconds (50);
  digitalWrite (final_strobe, LOW);
  //
    
}
