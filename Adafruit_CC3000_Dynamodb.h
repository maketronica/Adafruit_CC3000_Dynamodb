#ifndef CC3000Dynamodb_h
#define CC3000Dynamodb_h

#include <Adafruit_CC3000.h>

class AFC3KDD {
    Adafruit_CC3000 m_cc3000 = Adafruit_CC3000(0,0,0,SPI_CLOCK_DIV2);
    char* m_aws_access_key;
    char* m_aws_secret_key;
    char* m_aws_region;
    char* m_aws_host;
    //unsigned long timestamp;
    //float currentTemp;
  public:
    AFC3KDD(uint8_t, uint8_t, uint8_t, uint8_t, char*, char*, char*, char*);
    ~AFC3KDD();
    void write(char*, char*, unsigned long, float);
    void btoa2Padded(uint8_t value, char* buffer, int base);
    void hexString(uint8_t* bytes, size_t len, char* buffer);
    void dateTime8601(int year, byte month, byte day, byte hour,
                      byte minute, byte seconds, char* buffer);
    unsigned long getTime();
    bool connectToAP(const char *ssid, const char *key, uint8_t secmode,
                     uint8_t attempts = 0); 
    bool checkDHCP(void);
    bool begin(uint8_t patchReq = 0, bool useSmartConfigData = false, const char *_deviceName = NULL);
};

//void old_btoa2Padded(uint8_t value, char* buffer, int base);
//void old_hexString(uint8_t* bytes, size_t len, char* buffer);
//void old_dateTime8601(int year, byte month, byte day, byte hour,
//                      byte minute, byte seconds, char* buffer);
//void old_dynamoDBWrite(Adafruit_CC3000 cc3000,
//                   char* aws_access_key,
//                   char* aws_secret_access_key,
//                   char* aws_region,
//                   char* aws_host,
//                   char* table,
//                   char* id,
//                   unsigned long currentTime,
//                   float currentTemp);
//unsigned long old_getTime(Adafruit_CC3000 cc3000);


#endif
