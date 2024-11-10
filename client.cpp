#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

int sock;
const long long P = 23;
const long long alpha = 5;
unsigned char aesKey[16];

struct EncryptedData {
    unsigned char iv[16];
    unsigned char email[32];
    unsigned char uname[16];
    unsigned char password[16];
};

struct EncryptedLoginData {
    unsigned char iv[16];
    unsigned char uname[16];
    unsigned char password[16];
};

void create_socket()
{
    // create the socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    // setup an address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(8080);
    connect(sock, (struct sockaddr *) &server_address, sizeof(server_address));
}

void sendMsg2Server(const string& message) {
    char buf[256];
    memset(buf, 0, sizeof(buf)); 
    strcpy(buf, message.c_str());  
    send(sock, buf, sizeof(buf), 0); 
    memset(buf, 0, sizeof(buf)); 
     
}

long long generatePublicKey(long long privateKey)
{
  return static_cast <long long>(pow(alpha, privateKey)) %  P;
}

long long computeSharedSecret(long long rcvdPublicKey, long long privateKey)
{
  return static_cast <long long>(pow(rcvdPublicKey, privateKey)) %  P;
}

void handleErrors() {
    cerr << "Error occurred." << endl;
    exit(1);
}


void deriveAESKey(long long sharedSecret, unsigned char* key, int key_length = 16) {
   
    string sharedSecretStr = to_string(sharedSecret);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(sharedSecretStr.c_str()), sharedSecretStr.size(), hash);

    memcpy(key, hash, key_length);
}

vector<unsigned char> encryptAES(const string& plaintext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
        handleErrors();
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

void loginProcess()
{
string uname, pwd;
cout<<"*         ***    ********   *   *        *\n";
cout<<"*        *   *   *          *   * *      *\n";
cout<<"*        *   *   *   ****   *   *   *    *\n";
cout<<"*        *   *   *      *   *   *     *  *\n";
cout<<"********  ***    ********   *   *      * *\n";
cout<<"Provide credentials to login.\n";
cout<<"Enter username: ";
cin>>uname;
cout<<"Enter password: ";
cin>>pwd;
 
sendMsg2Server("Login initiated...");
unsigned char iv[16] = {0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
vector<unsigned char> uname_encrypted = encryptAES(uname, aesKey, iv);
vector<unsigned char> pwd_encrypted = encryptAES(pwd, aesKey, iv);

auto printEncrypted = [](const vector<unsigned char>& data) {
        for (unsigned char c : data) {
            cout << hex << static_cast<int>(c) << " ";
        }
        cout << dec << endl;
    };

    cout << "Encrypted Username: ";
    printEncrypted(uname_encrypted);

    cout << "Encrypted Password: ";
    printEncrypted(pwd_encrypted);
    
    EncryptedLoginData edata;
    EncryptedLoginData& data=edata;
    
    if (uname_encrypted.size() != 16 || pwd_encrypted.size() != 16) {
        cout<<uname_encrypted.size()<<endl;
        cout<<pwd_encrypted.size()<<endl;
                        
        std::cerr << "Error: Each encrypted field and IV must be exactly 16 bytes." << std::endl;
        return;
    }

    memcpy(data.iv, iv, 16);
    memcpy(data.uname, uname_encrypted.data(), 16);
    memcpy(data.password, pwd_encrypted.data(), 16);
    
    if (send(sock, reinterpret_cast<const unsigned char*>(&data), sizeof(data), 0) == -1) {
        std::cerr << "Error: Failed to send encrypted data packet to the server." << std::endl;
    }

}

void registrationProcess()
{
string email, uname, pwd;

//cout<<"******    ******   ********   *  ******  ********  ******   ******\n";
//cout<<"*    *    *        *          *  *          *      *        *    *\n";
//cout<<"* * *     ******   *   ****   *  ******     *      ******   * * *\n";
//cout<<"*    *    *        *      *   *       *     *      *        *    *\n";
//cout<<"*     *   ******   ********   *  ******     *      ******   *     *\n";
while(true){
 cout<<"Provide following registration details to proceed.\n";
 cout<<"Enter valid email address: ";
 cin>>email;
 cout<<"Enter username: ";
 cin>>uname;
 cout<<"Enter password: ";
 cin>>pwd;
 if (email.size() <= 16 && uname.size() <= 16 && pwd.size() <= 16) {
     break;
  } 
 else 
  {
     cout << "Error: Each input (email, username, password) must be 16 characters or fewer. Please try again.\n";
  }
}

sendMsg2Server("Registration initiated...");
unsigned char iv[16] = {0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
vector<unsigned char> email_encrypted = encryptAES(email, aesKey, iv);
vector<unsigned char> uname_encrypted = encryptAES(uname, aesKey, iv);
vector<unsigned char> pwd_encrypted = encryptAES(pwd, aesKey, iv);

auto printEncrypted = [](const vector<unsigned char>& data) {
        for (unsigned char c : data) {
            cout << hex << static_cast<int>(c) << " ";
        }
        cout << dec << endl;
    };

    cout << "Encrypted Email: ";
    printEncrypted(email_encrypted);

    cout << "Encrypted Username: ";
    printEncrypted(uname_encrypted);

    cout << "Encrypted Password: ";
    printEncrypted(pwd_encrypted);
    
    EncryptedData edata;
    EncryptedData& data=edata;
    
    if (email_encrypted.size() != 32 || uname_encrypted.size() != 16 || 
        pwd_encrypted.size() != 16) {
        cout<<email_encrypted.size()<<endl;
        cout<<uname_encrypted.size()<<endl;
        cout<<pwd_encrypted.size()<<endl;
                        
        std::cerr << "Error: Each encrypted field and IV must be exactly 16 bytes." << std::endl;
        return;
    }

    memcpy(data.iv, iv, 16);
    memcpy(data.email, email_encrypted.data(), 32);
    memcpy(data.uname, uname_encrypted.data(), 16);
    memcpy(data.password, pwd_encrypted.data(), 16);
    
    if (send(sock, reinterpret_cast<const unsigned char*>(&data), sizeof(data), 0) == -1) {
        std::cerr << "Error: Failed to send encrypted data packet to the server." << std::endl;
    }

    // Send the message to the server
    //sendMsg2Server(string(email_encrypted.begin(), email_encrypted.end()));
    //sendMsg2Server(string(uname_encrypted.begin(), uname_encrypted.end()));
    //sendMsg2Server(string(pwd_encrypted.begin(), pwd_encrypted.end()));
    
    /*cout<<string(email_encrypted.begin(), email_encrypted.end())<<endl;
    cout<<string(uname_encrypted.begin(), uname_encrypted.end())<<endl;
    cout<<string(pwd_encrypted.begin(), pwd_encrypted.end())<<endl;
    */

}



void menu() {
    string message;
    while (true) {
        cout << "Choose an option (1 or 2):\n1. Login (already registered)\n2. Register (as new user)\nYour answer: ";
        getline(cin, message);

        if (message == "1") {
            bool loginSuccess = false;
	    while (!loginSuccess) {
		loginProcess();
		
		// Clear buffer and receive response from server
		char buf [256];
		memset(buf, 0, sizeof(buf));
		recv(sock, buf, sizeof(buf), 0);

		if (strcmp(buf, "Username or password is incorrect.") == 0) 
		{
		    cout << "Error: Username or password is incorrect. Please try again." << endl;
		} 
		else 
		{
		    cout << "Login successful!" << endl;
		    loginSuccess = true;
		}
	    }
	    break;
        } 
	else if (message == "2") {
	    
	    bool registrationSuccess = false;
	    while (!registrationSuccess) {
		registrationProcess();
		
		// Clear buffer and receive response from server
		char buf [256];
		memset(buf, 0, sizeof(buf));
		recv(sock, buf, sizeof(buf), 0);

		if (strcmp(buf, "Username already exists.") == 0) 
		{
		    cout << "Error: Username already exists. Please try a different username." << endl;
		} 
		else 
		{
		    cout << "Registration successful!" << endl;
		    registrationSuccess = true;
		}
	    }
	    break;
	} 
        else {
            cout << "Invalid option. Please choose 1 or 2.\n";
        }
    }
}


int main() {
    char buf[256];
    bool flagrcv = false;
    bool flagsend = false;

    cout << "\n\t>>>>>>>>>> FAST NUCES University Chat Client <<<<<<<<<<\n\n";
    
        //deffie helman key exhcange
    srand(time(0));
    long long privKeyClient = rand()%10+1;
    long long pubKeyClient = generatePublicKey(privKeyClient);
    
    // Create socket and connect to the server
    create_socket();

    while (true) {
    
	//send the key to server
	if(flagsend==false){
	string pubKeyMsg = to_string(pubKeyClient);
	send(sock, pubKeyMsg.c_str(), pubKeyMsg.size()+1, 0);
	cout<<"Send publicKey to server: " <<pubKeyClient <<endl;
	flagsend=true;
	}
	
	//to make sure that key exchanged one time only
    if(flagrcv==false){
        // clear buffer and receive public key from server
        memset(buf, 0, sizeof(buf));
        recv(sock, buf, sizeof(buf), 0);
        long long rcvdServerPubKey = stoll(buf);
        cout<<"Received Public Key from Server "<<rcvdServerPubKey<<endl;
        long long sharedKey = computeSharedSecret(rcvdServerPubKey, privKeyClient);
        cout <<"Shared Secret Key (Client) :" <<sharedKey<<endl;
        deriveAESKey(sharedKey, aesKey);
        cout << "Derived 16-byte AES key (Client): ";
        for (int i = 0; i < 16; ++i) {
            printf("%02x", aesKey[i]);
        }
        cout << endl;
        flagrcv = true;
        //call menu function 1 time, then start chat
        menu();
        }
        
        // Get user input and send it to the server
        cout << "You (Client): ";
        string message;
        getline(cin, message);

        // Send the message to the server
        memset(buf, 0, sizeof(buf));
        strcpy(buf, message.c_str());
        send(sock, buf, sizeof(buf), 0);

        // If the client sends "exit", terminate the chat
        if (message == "exit") {
            cout << "You disconnected from the chat.\n";
            break;
        }

        // Clear buffer and receive response from server
        memset(buf, 0, sizeof(buf));
        recv(sock, buf, sizeof(buf), 0);
        cout << buf << endl;
    }

    // Close the socket after communication
    close(sock);

    return 0;
}
