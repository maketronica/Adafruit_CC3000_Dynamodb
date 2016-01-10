/***************************************************
 Adafruit CC3000 Dynamodb

 Fork of Adafruit's CloudThermometer demo sketch,
 paired down to just a library for writing to
 dynamodb from Arduino over a CC3000.

 Original copywrite notices below.
 ****************************************************/

/***************************************************
  Cloud Data-Logging Thermometer
 
  Log a thermomistor value to an Amazon DynamoDB table every minute.
  
  Copyright 2013 Tony DiCola (tony@tonydicola.com).
  Released under an MIT license: 
    http://opensource.org/licenses/MIT
  Dependencies:
  - Adafruit CC3000 Library 
    https://github.com/adafruit/Adafruit_CC3000_Library
  - RTClib Library
    https://github.com/adafruit/RTClib
  
  Parts of this code were adapted from Adafruit CC3000 library example 
  code which has the following license:
  
  Designed specifically to work with the Adafruit WiFi products:
  ----> https://www.adafruit.com/products/1469
  Adafruit invests time and resources providing this open source code, 
  please support Adafruit and open-source hardware by purchasing 
  products from Adafruit!
  Written by Limor Fried & Kevin Townsend for Adafruit Industries.  
  BSD license, all text above must be included in any redistribution
  
  SHA256 hash and signing code adapted from Peter Knight's library
  available at https://github.com/Cathedrow/Cryptosuite
 ****************************************************/

#include <Adafruit_CC3000.h>
#include <RTClib.h>
#include "sha256.h"
#include "Adafruit_CC3000_Dynamodb.h"

// Don't modify the below constants unless you want to play with calling other DynamoDB APIs
#define     AWS_TARGET             "DynamoDB_20120810.PutItem"
#define     AWS_SERVICE            "dynamodb"
#define     AWS_SIG_PREFIX         "AWS4" 

#define     SHA256_HASH_LENGTH     32
#define     TIMEOUT_MS             15000  // How long to wait (in milliseconds) for a server connection to respond (for both AWS and NTP calls).

AFC3KDD::AFC3KDD(uint8_t csPin, uint8_t irqPin, uint8_t vbatPin, uint8_t spispeed, char* a_aws_access_key, char* a_aws_secret_key, char* a_aws_region, char* a_aws_host) {
  m_cc3000 = Adafruit_CC3000(csPin, irqPin, vbatPin, spispeed);
  m_aws_access_key = a_aws_access_key;
  m_aws_secret_key = a_aws_secret_key;
  m_aws_region = a_aws_region;
  m_aws_host = a_aws_host;
}

AFC3KDD::~AFC3KDD(void) {
}

void AFC3KDD::write(char* table,
                    char* id,
                    unsigned long timestamp,
                    float temperature) {
  // Generate time and date strings
  DateTime dt(timestamp);
  // Set dateTime to the ISO8601 simple date format string.
  char dateTime[17];
  memset(dateTime, 0, 17);
  dateTime8601(dt.year(), dt.month(), dt.day(), dt.hour(), dt.minute(), dt.second(), dateTime);
  // Set date to just the year month and day of the ISO8601 simple date string.
  char date[9];
  memset(date, 0, 9);
  memcpy(date, dateTime, 8);
  // Set currentTimeStr to the string value of the current unix time (seconds since epoch).
  char timestampStr[8*sizeof(unsigned long)+1];
  memset(timestampStr, 0, 8*sizeof(unsigned long)+1);
  ultoa(timestamp, timestampStr, 10);

  // Generate string for the temperature reading.
  char temp[8*sizeof(unsigned long)+5];
  memset(temp, 0, 8*sizeof(unsigned long)+5);
  // Convert to fixed point string.  Using a proper float to string function
  // like dtostrf takes too much program memory (~1.5kb) to use in this sketch.
  ultoa((unsigned long)temperature, temp, 10);
  int n = strlen(temp);
  temp[n] = '.';
  temp[n+1] = '0' + ((unsigned long)(temperature*10)) % 10;
  temp[n+2] = '0' + ((unsigned long)(temperature*100)) % 10;
  temp[n+3] = '0' + ((unsigned long)(temperature*1000)) % 10;

  // Generate string with payload length for use in the signing and request sending.  
  char payloadlen[8*sizeof(unsigned long)+1];
  memset(payloadlen, 0, 8*sizeof(unsigned long)+1);
  ultoa(71+strlen(table)+strlen(id)+strlen(timestampStr)+strlen(temp), payloadlen, 10);

  // Generate the signature for the request.
  // For details on the AWS signature process, see: 
  //   http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

  // First, generate signing key to use in later signature generation.
  // Note: This could be optimized to generate just once per day (when the date value changes),
  // but since calls are only made every few minutes it's simpler to regenerate each time.
  char signingkey[SHA256_HASH_LENGTH];
  char sig_start[strlen(AWS_SIG_PREFIX)+strlen(m_aws_secret_key)+1];
  strcpy(sig_start, AWS_SIG_PREFIX);
  strcat(sig_start, m_aws_secret_key);
  Sha256.initHmac((uint8_t*)sig_start, strlen(sig_start));
  Sha256.print(date);
  memcpy(signingkey, Sha256.resultHmac(), SHA256_HASH_LENGTH);
  Sha256.initHmac((uint8_t*)signingkey, SHA256_HASH_LENGTH);
  Sha256.print(m_aws_region);
  memcpy(signingkey, Sha256.resultHmac(), SHA256_HASH_LENGTH);
  Sha256.initHmac((uint8_t*)signingkey, SHA256_HASH_LENGTH);
  Sha256.print(AWS_SERVICE);
  memcpy(signingkey, Sha256.resultHmac(), SHA256_HASH_LENGTH);
  Sha256.initHmac((uint8_t*)signingkey, SHA256_HASH_LENGTH);
  Sha256.print(F("aws4_request"));
  memcpy(signingkey, Sha256.resultHmac(), SHA256_HASH_LENGTH);
  
  // Second, generate hash of the payload data.
  Sha256.init();
  Sha256.print(F("{\"TableName\":\""));
  Sha256.print(table);
  Sha256.print(F("\",\"Item\":{\"Id\":{\"S\":\""));
  Sha256.print(id);
  Sha256.print(F("\"},\"Date\":{\"N\":\""));
  Sha256.print(timestampStr);
  Sha256.print(F("\"},\"Temp\":{\"N\":\""));
  Sha256.print(temp);
  Sha256.print(F("\"}}}"));
  char payloadhash[2*SHA256_HASH_LENGTH+1];
  memset(payloadhash, 0, 2*SHA256_HASH_LENGTH+1);
  hexString(Sha256.result(), SHA256_HASH_LENGTH, payloadhash);

  // Third, generate hash of the canonical request.
  Sha256.init();
  Sha256.print(F("POST\n/\n\ncontent-length:"));
  Sha256.print(payloadlen);
  Sha256.print(F("\ncontent-type:application/x-amz-json-1.0\nhost:"));
  Sha256.print(m_aws_host);
  Sha256.print(F(";\nx-amz-date:"));
  Sha256.print(dateTime);
  Sha256.print(F("\nx-amz-target:"));
  Sha256.print(AWS_TARGET);
  Sha256.print(F("\n\ncontent-length;content-type;host;x-amz-date;x-amz-target\n"));
  Sha256.print(payloadhash);  
  char canonicalhash[2*SHA256_HASH_LENGTH+1];
  memset(canonicalhash, 0, 2*SHA256_HASH_LENGTH+1);
  hexString(Sha256.result(), SHA256_HASH_LENGTH, canonicalhash);
  
  // Finally, generate request signature from the string to sign and signing key.
  Sha256.initHmac((uint8_t*)signingkey, SHA256_HASH_LENGTH);
  Sha256.print(F("AWS4-HMAC-SHA256\n"));
  Sha256.print(dateTime);
  Sha256.print(F("\n"));
  Sha256.print(date);
  Sha256.print(F("/"));
  Sha256.print(m_aws_region);
  Sha256.print(F("/"));
  Sha256.print(AWS_SERVICE);
  Sha256.print(F("/aws4_request\n"));
  Sha256.print(canonicalhash);
  char signature[2*SHA256_HASH_LENGTH+1];
  memset(signature, 0, 2*SHA256_HASH_LENGTH+1);
  hexString(Sha256.resultHmac(), SHA256_HASH_LENGTH, signature);
  
  // Make request to DynamoDB API.
  uint32_t ip = 0;
  while (ip == 0) {
    if (!m_cc3000.getHostByName(m_aws_host, &ip)) {
      Serial.println(F("Couldn't resolve!"));
    }
    delay(500);
  }
  Adafruit_CC3000_Client www = m_cc3000.connectTCP(ip, 80);
  if (www.connected()) {
    www.fastrprint(F("POST / HTTP/1.1\r\nhost: "));
    www.fastrprint(m_aws_host);
    www.fastrprint(F(";\r\nx-amz-date: "));
    www.fastrprint(dateTime);
    www.fastrprint(F("\r\nAuthorization: AWS4-HMAC-SHA256 Credential="));
    www.fastrprint(m_aws_access_key);
    www.fastrprint(F("/"));
    www.fastrprint(date);
    www.fastrprint(F("/"));
    www.fastrprint(m_aws_region);
    www.fastrprint(F("/"));
    www.fastrprint(AWS_SERVICE);
    www.fastrprint(F("/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-target, Signature="));
    www.fastrprint(signature);
    www.fastrprint(F("\r\ncontent-type: application/x-amz-json-1.0\r\ncontent-length: "));
    www.fastrprint(payloadlen);
    www.fastrprint(F("\r\nx-amz-target: "));
    www.fastrprint(AWS_TARGET);
    www.fastrprint(F("\r\n\r\n{\"TableName\":\""));
    www.fastrprint(table);
    www.fastrprint(F("\",\"Item\":{\"Id\":{\"S\":\""));
    www.fastrprint(id);
    www.fastrprint(F("\"},\"Date\":{\"N\":\""));
    www.fastrprint(timestampStr);
    www.fastrprint(F("\"},\"Temp\":{\"N\":\""));
    www.fastrprint(temp);
    www.fastrprint(F("\"}}}"));
  } 
  else {
    Serial.println(F("Connection failed"));    
    www.close();
    return;
  }
  
  // Read data until either the connection is closed, or the idle timeout is reached.
  Serial.println(F("AWS response:"));
  unsigned long lastRead = millis();
  while (www.connected() && (millis() - lastRead < TIMEOUT_MS)) {
    while (www.available()) {
      char c = www.read();
      Serial.print(c);
      lastRead = millis();
    }
  }
  www.close();
  
}

// Print a value from 0-99 to a 2 character 0 padded character buffer.
// Buffer MUST be at least 2 characters long!
void AFC3KDD::btoa2Padded(uint8_t value, char* buffer, int base) {
  if (value < base) {
    *buffer = '0';
    ultoa(value, buffer+1, base);
  }
  else {
    ultoa(value, buffer, base); 
  }
}

// Convert an array of bytes into a lower case hex string.
// Buffer MUST be two times the length of the input bytes array!
void AFC3KDD::hexString(uint8_t* bytes,
                        size_t len,
                        char* buffer) {
  for (int i = 0; i < len; ++i) {
    btoa2Padded(bytes[i], &buffer[i*2], 16);
  }
}

// Fill a 16 character buffer with the date in ISO8601 simple format, like '20130101T010101Z'.  
// Buffer MUST be at least 16 characters long!
void AFC3KDD::dateTime8601(int year,
                           byte month,
                           byte day,
                           byte hour,
                           byte minute,
                           byte seconds,
                           char* buffer) {
  ultoa(year, buffer, 10);
  btoa2Padded(month, buffer+4, 10);
  btoa2Padded(day, buffer+6, 10);
  buffer[8] = 'T';
  btoa2Padded(hour, buffer+9, 10);
  btoa2Padded(minute, buffer+11, 10);
  btoa2Padded(seconds, buffer+13, 10);
  buffer[15] = 'Z';
}

unsigned long AFC3KDD::getTime() {
  Adafruit_CC3000_Client client;
  uint8_t       buf[48];
  unsigned long ip, startTime, t = 0L;

  // Hostname to IP lookup; use NTP pool (rotates through servers)
  if(m_cc3000.getHostByName("pool.ntp.org", &ip)) {
    static const char PROGMEM
      timeReqA[] = { 227,  0,  6, 236 },
      timeReqB[] = {  49, 78, 49,  52 };

    startTime = millis();
    do {
      client = m_cc3000.connectUDP(ip, 123);
    } while((!client.connected()) &&
            ((millis() - startTime) < TIMEOUT_MS));

    if(client.connected()) {
      // Assemble and issue request packet
      memset(buf, 0, sizeof(buf));
      memcpy_P( buf    , timeReqA, sizeof(timeReqA));
      memcpy_P(&buf[12], timeReqB, sizeof(timeReqB));
      client.write(buf, sizeof(buf));

      memset(buf, 0, sizeof(buf));
      startTime = millis();
      while((!client.available()) &&
            ((millis() - startTime) < TIMEOUT_MS));
      if(client.available()) {
        client.read(buf, sizeof(buf));
        t = (((unsigned long)buf[40] << 24) |
             ((unsigned long)buf[41] << 16) |
             ((unsigned long)buf[42] <<  8) |
              (unsigned long)buf[43]) - 2208988800UL;
      }
      client.close();
    }
  }
  return t;
}

bool AFC3KDD::connectToAP(const char *ssid, const char *key,
                          uint8_t secmode, uint8_t attempts) {
  return m_cc3000.connectToAP(ssid, key, secmode, attempts); 
}

bool AFC3KDD::checkDHCP(void) {
  return m_cc3000.checkDHCP();
}

bool AFC3KDD::begin(uint8_t patchReq,
                    bool useSmartConfigData,
                    const char *_deviceName) {
  return m_cc3000.begin(patchReq, useSmartConfigData, _deviceName);
}

// #######################################################################



// Print a value from 0-99 to a 2 character 0 padded character buffer.
// Buffer MUST be at least 2 characters long!
//void old_btoa2Padded(uint8_t value, char* buffer, int base) {
//  if (value < base) {
//    *buffer = '0';
//    ultoa(value, buffer+1, base);
//  }
//  else {
//    ultoa(value, buffer, base); 
//  }
//}

// Convert an array of bytes into a lower case hex string.
// Buffer MUST be two times the length of the input bytes array!
//void old_hexString(uint8_t* bytes, size_t len, char* buffer) {
//  for (int i = 0; i < len; ++i) {
//    old_btoa2Padded(bytes[i], &buffer[i*2], 16);
//  }
//}

// Fill a 16 character buffer with the date in ISO8601 simple format, like '20130101T010101Z'.  
// Buffer MUST be at least 16 characters long!
//void old_dateTime8601(int year, byte month, byte day, byte hour, byte minute, byte seconds, char* buffer) {
//  ultoa(year, buffer, 10);
//  old_btoa2Padded(month, buffer+4, 10);
//  old_btoa2Padded(day, buffer+6, 10);
//  buffer[8] = 'T';
//  old_btoa2Padded(hour, buffer+9, 10);
//  old_btoa2Padded(minute, buffer+11, 10);
//  old_btoa2Padded(seconds, buffer+13, 10);
//  buffer[15] = 'Z';
//}

// Write a temperature reading to the DynamoDB table.
//void old_dynamoDBWrite(Adafruit_CC3000 cc3000,
//                   char* aws_access_key,
//                   char* aws_secret_access_key,
//                   char* aws_region,
//                   char* aws_host,
//                   char* table,
//                   char* id,
//                   unsigned long currentTime,
//                   float currentTemp) {
  // Generate time and date strings
//  DateTime dt(currentTime);
  // Set dateTime to the ISO8601 simple date format string.
//  char dateTime[17];
//  memset(dateTime, 0, 17);
//  old_dateTime8601(dt.year(), dt.month(), dt.day(), dt.hour(), dt.minute(), dt.second(), dateTime);
//  // Set date to just the year month and day of the ISO8601 simple date string.
//  char date[9];
//  memset(date, 0, 9);
//  memcpy(date, dateTime, 8);
  // Set currentTimeStr to the string value of the current unix time (seconds since epoch).
//  char currentTimeStr[8*sizeof(unsigned long)+1];
//  memset(currentTimeStr, 0, 8*sizeof(unsigned long)+1);
//  ultoa(currentTime, currentTimeStr, 10);

  // Generate string for the temperature reading.
//  char temp[8*sizeof(unsigned long)+5];
//  memset(temp, 0, 8*sizeof(unsigned long)+5);
  // Convert to fixed point string.  Using a proper float to string function
  // like dtostrf takes too much program memory (~1.5kb) to use in this sketch.
//  ultoa((unsigned long)currentTemp, temp, 10);
//  int n = strlen(temp);
//  temp[n] = '.';
//  temp[n+1] = '0' + ((unsigned long)(currentTemp*10)) % 10;
//  temp[n+2] = '0' + ((unsigned long)(currentTemp*100)) % 10;
//  temp[n+3] = '0' + ((unsigned long)(currentTemp*1000)) % 10;

  // Generate string with payload length for use in the signing and request sending.  
//  char payloadlen[8*sizeof(unsigned long)+1];
//  memset(payloadlen, 0, 8*sizeof(unsigned long)+1);
//  ultoa(71+strlen(table)+strlen(id)+strlen(currentTimeStr)+strlen(temp), payloadlen, 10);

  // Generate the signature for the request.
  // For details on the AWS signature process, see: 
  //   http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

  // First, generate signing key to use in later signature generation.
  // Note: This could be optimized to generate just once per day (when the date value changes),
  // but since calls are only made every few minutes it's simpler to regenerate each time.
//  char signingkey[SHA256_HASH_LENGTH];
//  char sig_start[strlen(AWS_SIG_PREFIX)+strlen(aws_secret_access_key)+1];
//  strcpy(sig_start, AWS_SIG_PREFIX);
//  strcat(sig_start, aws_secret_access_key);
//  Sha256.initHmac((uint8_t*)sig_start, strlen(sig_start));
//  Sha256.print(date);
//  memcpy(signingkey, Sha256.resultHmac(), SHA256_HASH_LENGTH);
//  Sha256.initHmac((uint8_t*)signingkey, SHA256_HASH_LENGTH);
//  Sha256.print(aws_region);
//  memcpy(signingkey, Sha256.resultHmac(), SHA256_HASH_LENGTH);
//  Sha256.initHmac((uint8_t*)signingkey, SHA256_HASH_LENGTH);
//  Sha256.print(AWS_SERVICE);
//  memcpy(signingkey, Sha256.resultHmac(), SHA256_HASH_LENGTH);
//  Sha256.initHmac((uint8_t*)signingkey, SHA256_HASH_LENGTH);
//  Sha256.print(F("aws4_request"));
//  memcpy(signingkey, Sha256.resultHmac(), SHA256_HASH_LENGTH);
  
  // Second, generate hash of the payload data.
//  Sha256.init();
//  Sha256.print(F("{\"TableName\":\""));
//  Sha256.print(table);
//  Sha256.print(F("\",\"Item\":{\"Id\":{\"S\":\""));
//  Sha256.print(id);
//  Sha256.print(F("\"},\"Date\":{\"N\":\""));
//  Sha256.print(currentTimeStr);
//  Sha256.print(F("\"},\"Temp\":{\"N\":\""));
//  Sha256.print(temp);
//  Sha256.print(F("\"}}}"));
//  char payloadhash[2*SHA256_HASH_LENGTH+1];
//  memset(payloadhash, 0, 2*SHA256_HASH_LENGTH+1);
//  old_hexString(Sha256.result(), SHA256_HASH_LENGTH, payloadhash);

  // Third, generate hash of the canonical request.
//  Sha256.init();
//  Sha256.print(F("POST\n/\n\ncontent-length:"));
//  Sha256.print(payloadlen);
//  Sha256.print(F("\ncontent-type:application/x-amz-json-1.0\nhost:"));
//  Sha256.print(aws_host);
//  Sha256.print(F(";\nx-amz-date:"));
//  Sha256.print(dateTime);
//  Sha256.print(F("\nx-amz-target:"));
//  Sha256.print(AWS_TARGET);
//  Sha256.print(F("\n\ncontent-length;content-type;host;x-amz-date;x-amz-target\n"));
//  Sha256.print(payloadhash);  
//  char canonicalhash[2*SHA256_HASH_LENGTH+1];
//  memset(canonicalhash, 0, 2*SHA256_HASH_LENGTH+1);
//  old_hexString(Sha256.result(), SHA256_HASH_LENGTH, canonicalhash);
  
  // Finally, generate request signature from the string to sign and signing key.
//  Sha256.initHmac((uint8_t*)signingkey, SHA256_HASH_LENGTH);
//  Sha256.print(F("AWS4-HMAC-SHA256\n"));
//  Sha256.print(dateTime);
//  Sha256.print(F("\n"));
//  Sha256.print(date);
//  Sha256.print(F("/"));
//  Sha256.print(aws_region);
//  Sha256.print(F("/"));
//  Sha256.print(AWS_SERVICE);
//  Sha256.print(F("/aws4_request\n"));
//  Sha256.print(canonicalhash);
//  char signature[2*SHA256_HASH_LENGTH+1];
//  memset(signature, 0, 2*SHA256_HASH_LENGTH+1);
//  old_hexString(Sha256.resultHmac(), SHA256_HASH_LENGTH, signature);
  
  // Make request to DynamoDB API.
//  uint32_t ip = 0;
//  while (ip == 0) {
//    if (!cc3000.getHostByName(aws_host, &ip)) {
//      Serial.println(F("Couldn't resolve!"));
//    }
//    delay(500);
//  }
//  Adafruit_CC3000_Client www = cc3000.connectTCP(ip, 80);
//  if (www.connected()) {
//    www.fastrprint(F("POST / HTTP/1.1\r\nhost: "));
//    www.fastrprint(aws_host);
//    www.fastrprint(F(";\r\nx-amz-date: "));
//    www.fastrprint(dateTime);
//    www.fastrprint(F("\r\nAuthorization: AWS4-HMAC-SHA256 Credential="));
//    www.fastrprint(aws_access_key);
//    www.fastrprint(F("/"));
//    www.fastrprint(date);
//    www.fastrprint(F("/"));
//    www.fastrprint(aws_region);
//    www.fastrprint(F("/"));
//    www.fastrprint(AWS_SERVICE);
//    www.fastrprint(F("/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-target, Signature="));
//    www.fastrprint(signature);
//    www.fastrprint(F("\r\ncontent-type: application/x-amz-json-1.0\r\ncontent-length: "));
//    www.fastrprint(payloadlen);
//    www.fastrprint(F("\r\nx-amz-target: "));
//    www.fastrprint(AWS_TARGET);
//    www.fastrprint(F("\r\n\r\n{\"TableName\":\""));
//    www.fastrprint(table);
//    www.fastrprint(F("\",\"Item\":{\"Id\":{\"S\":\""));
//    www.fastrprint(id);
//    www.fastrprint(F("\"},\"Date\":{\"N\":\""));
//    www.fastrprint(currentTimeStr);
//    www.fastrprint(F("\"},\"Temp\":{\"N\":\""));
//    www.fastrprint(temp);
//    www.fastrprint(F("\"}}}"));
//  } 
//  else {
//    Serial.println(F("Connection failed"));    
//    www.close();
//    return;
//  }
  
  // Read data until either the connection is closed, or the idle timeout is reached.
//  Serial.println(F("AWS response:"));
//  unsigned long lastRead = millis();
//  while (www.connected() && (millis() - lastRead < TIMEOUT_MS)) {
//    while (www.available()) {
//      char c = www.read();
//      Serial.print(c);
//      lastRead = millis();
//    }
//  }
//  www.close();
//}

// getTime function adapted from CC3000 ntpTest sketch.
// Minimalist time server query; adapted from Adafruit Gutenbird sketch,
// which in turn has roots in Arduino UdpNTPClient tutorial.
//unsigned long getTime(Adafruit_CC3000 cc3000) {
//  Adafruit_CC3000_Client client;
//  uint8_t       buf[48];
//  unsigned long ip, startTime, t = 0L;
//
//  // Hostname to IP lookup; use NTP pool (rotates through servers)
//  if(cc3000.getHostByName("pool.ntp.org", &ip)) {
//    static const char PROGMEM
//      timeReqA[] = { 227,  0,  6, 236 },
//      timeReqB[] = {  49, 78, 49,  52 };
//
//    startTime = millis();
//    do {
//      client = cc3000.connectUDP(ip, 123);
//    } while((!client.connected()) &&
//            ((millis() - startTime) < TIMEOUT_MS));
//
//    if(client.connected()) {
//      // Assemble and issue request packet
//      memset(buf, 0, sizeof(buf));
//      memcpy_P( buf    , timeReqA, sizeof(timeReqA));
//      memcpy_P(&buf[12], timeReqB, sizeof(timeReqB));
//      client.write(buf, sizeof(buf));
//
//      memset(buf, 0, sizeof(buf));
//      startTime = millis();
//      while((!client.available()) &&
//            ((millis() - startTime) < TIMEOUT_MS));
//      if(client.available()) {
//        client.read(buf, sizeof(buf));
//        t = (((unsigned long)buf[40] << 24) |
//             ((unsigned long)buf[41] << 16) |
//             ((unsigned long)buf[42] <<  8) |
//              (unsigned long)buf[43]) - 2208988800UL;
//      }
//      client.close();
//    }
//  }
//  return t;
//}
