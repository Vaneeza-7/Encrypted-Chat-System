#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <openssl/sha.h>

using namespace std;

int sock;
const long long P = 23;
const long long alpha = 5;

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

long long generatePublicKey(long long privateKey)
{
  return static_cast <long long>(pow(alpha, privateKey)) %  P;
}

long long computeSharedSecret(long long rcvdPublicKey, long long privateKey)
{
  return static_cast <long long>(pow(rcvdPublicKey, privateKey)) %  P;
}

void loginProcess()
{

cout<<"*         ***    ********   *   *        *\n";
cout<<"*        *   *   *          *   * *      *\n";
cout<<"*        *   *   *   ****   *   *   *    *\n";
cout<<"*        *   *   *      *   *   *     *  *\n";
cout<<"********  ***    ********   *   *        *\n";
cout<<"Provide credentials to proceed.\n";

}

void registrationProcess()
{
string email, uname, pwd;
cout<<"******    ******   ********   *  ******  ********  ******   ******\n";
cout<<"*    *    *        *          *  *          *      *        *    *\n";
cout<<"* * *     ******   *   ****   *  ******     *      ******   * * *\n";
cout<<"*    *    *        *      *   *       *     *      *        *    *\n";
cout<<"*     *   ******   ********   *  ******     *      ******   *     *\n";
cout<<"Provide following details to proceed.\n";
cout<<"Enter valid email address:";
cin>>email;
cout<<"Enter username:";
cin>>uname;
cout<<"Enter password";
cin>>pwd;
//encryptAES(email, uname, pwd);

}

void menu() {
    string message;
    while (true) {
        cout << "Choose an option (1 or 2):\n1. Login (already registered)\n2. Register (as new user)\nYour answer: ";
        getline(cin, message);

        if (message == "1") {
            loginProcess();
            break;
        } 
        else if (message == "2") {
            registrationProcess();
            break;
        } 
        else {
            cout << "Invalid option. Please choose 1 or 2.\n";
        }
    }
}

void deriveAESKey(long long sharedSecret, unsigned char* key, int key_length = 16) {
   
    string sharedSecretStr = to_string(sharedSecret);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(sharedSecretStr.c_str()), sharedSecretStr.size(), hash);

    memcpy(key, hash, key_length);
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
        unsigned char aesKey[16];
        deriveAESKey(sharedKey, aesKey);
        cout << "Derived 16-byte AES key (Client): ";
        for (int i = 0; i < 16; ++i) {
            printf("%02x", aesKey[i]);
        }
        cout << endl;
        flagrcv = true;
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
