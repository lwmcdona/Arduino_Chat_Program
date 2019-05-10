/*
1st Partner: Logan McDonald
2nd Partner: Veronica Salm
CMPUT 274 LBL EA2
Fall 2016

Arduino Encrypted Chat Program:
- Arduinos exchange a common shared key used to encrypt and decrypt data.
- Public keys are exchanged automatically.
- A streaming cipher is used to encrypt data and then decrypt it at its destination,
using a different pseudorandom key for each character.
*/

#include <Arduino.h>

const int digitalPin = 13;

/*Generates a 32 bit random number to be used as the secret key.*/
uint32_t random_number() {
    const int random_number_pin = 1; // The analog pin to be read from
    int reading;
    uint32_t number = 0;
    for (int i=0; i<32; ++i) { // reads 32 bits
        number = number << 1; // shifts the number to the left to free up the last bit
        reading = (analogRead(random_number_pin)) & 1; // reads from the pin and converts it to a single bit (1 or 0)
        number = number | reading; // replaces the last bit of number with the value of the reading

        delay(50); // allow the reading to fluctuate
    }
    return number;
}

/*Calculates and returns (a*b) mod m
Parameters:
a: base, nonnegative integer, a < 2^31
b: exponent, nonnegative integer, a=b=0 not allowed, b < 2^32
m: 0 or positive integer m < 2^31
Running time grows linearly with the number of bits in a.
*/
uint32_t mul_mod(uint32_t a, uint32_t b, uint32_t m) {
    uint32_t r = 0; //result - to be modified and returned
    uint32_t p = b % m;
    uint32_t shift;
    for (int i=0; i<31; ++i) {
        shift = 1;
        if (((shift << i) & a) != 0) { //use a mask to determine if the ith bit is 1
            r = (r + p) % m; //perform a mod after each addition
        }
        p = (p << 1) % m; //perform a mod after each multiplication
    }
    return r;
}

/*Calculates and returns (a**b) mod m
Parameters:
a: base, nonnegative integer
b: exponent, nonnegative integer, a=b=0 not allowed
m: 0 or positive integer m<2^31
Running time grows linearly with b.
*/
uint32_t fast_pow_mod(uint32_t a, uint32_t b, uint32_t m) { //the fast function developed in class on 09-28-16
    uint32_t result = 1 % m;
    uint32_t p = a % m;
    for (int i = 0; i < 32; ++i) {
        if ( (b & (1ul<<i)) !=0 ) { //1ul converts 1 to an unsigned long
            result = mul_mod(result, p, m);
        }
        p = mul_mod(p,p,m);
    }
    return result;
}

/*Code used to test the pow mod and mul mod functions to ensure that they work correctly.*/
/*
void test_fast_pow_mod(uint32_t a, uint32_t b, uint32_t m, uint32_t expd) {
    uint32_t test = fast_pow_mod(a, b, m);
    Serial.print("The result is: ");
 Serial.println(test);
    Serial.print("Expected: ");
    Serial.println(expd);
}

void test_function() {
    test_fast_pow_mod(16807, 2, 2147483647, 282475249);
    test_fast_pow_mod(16807, 4, 2147483647, 984943658);
    test_fast_pow_mod(16807, 2229654386, 2147483647, 761890985);
    test_fast_pow_mod(16807, 3039853402, 2147483647, 1195409470);
    // test_fast_pow_mod(16807, 2, 2147483647, 33614);
    // test_fast_pow_mod(16807, 4, 2147483647, 67228);
    // test_fast_pow_mod(2147483646, 4, 2147483647, 2147483643);
    // test_fast_pow_mod(2147483646, 4, 2147483647, 2147483643);
    // test_fast_pow_mod(2147483646, 4, 2147483647, 2147483643);
    // test_fast_pow_mod(2147483646, 4, 2147483647, 2147483643);
}
*/


/* Converts the encrypt and decrypt keys to a new pseudorandom key.
 * Implements the Park-Miller algorithm with 32 bit integer arithmetic
 * @return ((current_key * 48271)) mod (2^31 - 1);
 * This is linear congruential generator, based on the multiplicative
 * group of integers modulo m = 2^31 - 1.
 * The generator has a long period and it is relatively efficient.
 * Most importantly, the generator's modulus is not a power of two
 * (as is for the built-in rng),
 * hence the keys mod 2^{s} cannot be obtained
 * by using a key with s bits.
 * Based on:
 * http://www.firstpr.com.au/dsp/rand31/rand31-park-miller-carta.cc.txt
 */
uint32_t next_key(uint32_t current_key) {
    const uint32_t modulus = 0x7FFFFFFF; // 2^31-1
    const uint32_t consta = 48271;  // we use that consta<2^16
    uint32_t lo = consta*(current_key & 0xFFFF);
    uint32_t hi = consta*(current_key >> 16);
    lo += (hi & 0x7FFF)<<16;
    lo += hi>>15;
    if (lo > modulus) lo -= modulus;
    return lo;
}

/** Waits for a certain number of bytes on Serial3 or timeout
* @param nbytes: the number of bytes we want
* @param timeout: timeout period (ms); specifying a negative number
*                turns off timeouts (the function waits indefinitely
*                if timeouts are turned off).
* @return True if the required number of bytes have arrived.
*/
bool wait_on_serial3( uint8_t nbytes, long timeout ) {
    unsigned long deadline = millis() + timeout;//wraparound not a problem
    while (Serial3.available()<nbytes && (timeout<0 || millis()<deadline))
    {
        delay(1); // be nice, no busy loop
    }
    return Serial3.available()>=nbytes;
}

/*
* Writes an uint32_t to Serial3, starting from the least-significant
* and finishing with the most significant byte.
*/
void uint32_to_serial3(uint32_t num) {
    Serial3.write((char) (num >> 0));
    Serial3.write((char) (num >> 8));
    Serial3.write((char) (num >> 16));
    Serial3.write((char) (num >> 24));
}

/*
* Reads an uint32_t from Serial3, starting from the least-significant
* and finishing with the most significant byte.
*/
uint32_t uint32_from_serial3() {
    uint32_t num = 0;
    num = num | ((uint32_t) Serial3.read()) << 0;
    num = num | ((uint32_t) Serial3.read()) << 8;
    num = num | ((uint32_t) Serial3.read()) << 16;
    num = num | ((uint32_t) Serial3.read()) << 24;
    return num;
}

/*
* Client FSM: The client will continually send connection requests to the
* server until it receives an acknowledgement. Once this has occurred, it
* will send an acknowledgement of the acknowledgement to the server before
* moving into the data exchange state.
*/
bool client_fsm (uint32_t public_key, uint32_t& partners_public_key) {
    enum State {Start = 1, WaitingForAck, DataExchange};
    /* Error state is not necessary because timeout acts as an error state */
    State curr_state = Start;

    while (Serial3.available() != 0) { //consumes any characters that may be sent before it waits for acknowledgement
      char garbage = Serial3.read();
    }
    while (true) {
        if (curr_state == Start) {
            /*  Send CR(ckey)
                CR(ckey) is 5 byte long: 'C' followed by the 4 bytes of the public key */
            Serial3.write('C');
            uint32_to_serial3(public_key);
            curr_state = WaitingForAck;
        }
        else if (curr_state == WaitingForAck) {
            // wait for ACK(skey)
            // ACK(skey) is also 5 byte long: 'A' followed by the 4 bytes of the public key.
            uint8_t nbytes = 5;
            long timeout = 1000;
            // wait until their are 5 bytes on Serial 3 or else timeout
            // if 5 bytes are read, read the first character and if it is an A then read the key
            // send acknowledgement
            if (wait_on_serial3(nbytes, timeout)) {
                char A = Serial3.read();
                Serial.print((int) A);
                if (A == 'A') {
                    partners_public_key = uint32_from_serial3();
                    Serial3.write('A');
                    curr_state = DataExchange;
                    break;
                }
            }
            else { // if timeout (1000) has occurred
                Serial.println("Timeout error occurred. The key exchange will restart.");
                Serial.println("------------------------------------------------------");
                curr_state = Start;
            }
        }
    }
    Serial.println(curr_state);
    return curr_state == DataExchange;
}
/*
* Server FSM: The server waits to receive a connection request, and
* then sends an acknowledgement. Once it has received an acknowledgement
* of the acknowledgement from the client, it initiates data exchange.
* Any outstanding requests that have not been acknowledged are considered
* to be garbage characters and will later be consumed.
*/
bool server_fsm(uint32_t public_key, uint32_t& partners_public_key) {
    enum State {Listen = 1, WaitingForKey, WaitForAck, DataExchange};
    /* Error state is not necessary because timeout acts as an error state */

    State curr_state = Listen;
    int counter = -1;
    uint8_t single_byte = 1;
    uint8_t key_bytes = 4;
    long timeout = 1000;

    while (true) {
        if (curr_state == Listen) {Serial.println("Waiting for data...");}
        if (curr_state == Listen && (wait_on_serial3(single_byte, timeout))) {
            counter = 0;
            char C = Serial3.read();
            if (C == 'C') {
                curr_state = WaitingForKey;
            }
        }
        else if ((curr_state == WaitingForKey) && (wait_on_serial3(key_bytes, timeout))) {
            partners_public_key = uint32_from_serial3();
            if (counter = 1) { // only send A and the public_key the first time through
                Serial3.write('A');
                uint32_to_serial3(public_key);
            }
            curr_state = WaitForAck;
        }
        else if ((curr_state == WaitForAck) && (wait_on_serial3(single_byte, timeout))) {
            char input = Serial3.read();
            if (input == 'A') {
                curr_state = DataExchange;
                break;
            }
            else if (input == 'C') {
                curr_state = WaitingForKey;
            }
        }
        else { // if timeout (1000) has occurred
            Serial.println("Timeout error occurred. The key exchange will restart.");
            Serial.println("------------------------------------------------------");
            curr_state = Listen;
        }
        ++counter;
    }
}

/*Prints the Arduino's public key and informs the user that the key exchange is about to occur. */
void initiate_message(uint32_t public_key) {
    Serial.print("Here is this Arduino's public key: ");
    Serial.println(public_key);
    Serial.println("The key exchange will occur automatically.");
    Serial.println("------------------------------------------");
}

/*Initiates the key exchange between arduinos.*/
uint32_t initiate() {
    Serial.println("Welcome! Setting up..."); //lets the user know that the program is initiating
    // This was done because it does take some time to create the random number
    uint32_t prime = 2147483647; //prime and generator from assignment part 2
    uint32_t generator = 16807;
    uint32_t private_key = random_number(); // generates a 32-bit random number
    uint32_t partners_public_key;
    uint32_t public_key = fast_pow_mod(generator, private_key, prime); //generates a public key based on the user's private key

    int role = digitalRead(digitalPin);

    if (role == LOW) {
        Serial.println("This Arduino is the client.");
        initiate_message(public_key);
        if (client_fsm(public_key, partners_public_key)) { // if the exchange is completed for the client
            Serial.println("Exchange complete. Proceed to Data Exchange.");
            Serial.println("--------------------------------------------");
            Serial.println("You may now type the characters you wish to send on the encrypted channel: ");
        }
        else {
            Serial.print("Error occurred. Please restart and try again.");
        }
    }
    else if (role == HIGH) {
        Serial.println("This Arduino is the server.");
        initiate_message(public_key);
        if (server_fsm(public_key, partners_public_key)) { // if the exchange is completed for the server
            Serial.println("Exchange complete. Proceed to Data Exchange.");
            Serial.println("--------------------------------------------");
            Serial.println("You may now type the characters you wish to send on the encrypted channel: ");
        }
        else {
            Serial.print("Error occurred. Please restart and try again.");
        }
    }
    else {
        Serial.print("Your arduino is not configured properly. Please check the configuration and try again.");
    }
    // generate the shared secret key
    uint32_t shared_secret = fast_pow_mod(partners_public_key, private_key, prime);
    return shared_secret;
}

int main() {
    init();
    Serial.begin(9600);
    Serial3.begin(9600);

    uint32_t shared_secret = initiate(); //exchanges keys between arduinos
    uint8_t encrypt_key = shared_secret % 256; // convert to an 8 bit key
    uint8_t decrypt_key = shared_secret % 256;

    while (Serial3.available() != 0) { //consumes any outstanding server and client requests before moving on to data exchange
      char garbage = Serial3.read();
    }
    while (true) { //sends and recieves data character by character
      if (Serial.available() > 0) {
            char c = Serial.read();
            Serial.write(c); //echo back to screen
            c = c ^ encrypt_key; // encrypt data
            Serial3.write(c); //sending byte to the "other" Arduino

            encrypt_key = next_key(encrypt_key) % 256; // change key for next character
        }
      if (Serial3.available() > 0) {
          char c = Serial3.read();
          c = c ^ decrypt_key; //decrypt data
          Serial.print(c); //print byte from other arduino

          decrypt_key = next_key(decrypt_key) % 256; // change key for the next decryption
      }
    }
    Serial3.end();
    Serial.end();
    return 0;
}
