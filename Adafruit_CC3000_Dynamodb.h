#ifndef CC3000Dynamodb_h
#define CC3000Dynamodb_h

void btoa2Padded(uint8_t value, char* buffer, int base);
void hexString(uint8_t* bytes, size_t len, char* buffer);
void dateTime8601(int year, byte month, byte day, byte hour, byte minute, byte seconds, char* buffer);
void dynamoDBWrite(Adafruit_CC3000 cc3000,
                   char* aws_access_key,
                   char* aws_secret_access_key,
                   char* aws_region,
                   char* aws_host,
                   char* table,
                   char* id,
                   unsigned long currentTime,
                   float currentTemp);
unsigned long getTime(Adafruit_CC3000 cc3000);

#endif
