#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>
#include <cmath>
#include <ctime>
#include <openssl/sha.h>

using namespace std;

const long long P = 23;
const long long alpha = 5;

long long generatePublicKey(long long privateKey)
{
  return static_cast <long long>(pow(alpha, privateKey)) %  P;
}

long long computeSharedSecret(long long rcvdPublicKey, long long privateKey)
{
  return static_cast <long long>(pow(rcvdPublicKey, privateKey)) %  P;
}

void deriveAESKey(long long sharedSecret, unsigned char* key, int key_length = 16) {
   
    string sharedSecretStr = to_string(sharedSecret);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(sharedSecretStr.c_str()), sharedSecretStr.size(), hash);

    memcpy(key, hash, key_length);
}

int main() {
    char buf[256];
    char message[256] = "Server: ";
    
    cout << "\n\t>>>>>>>>>> FAST NUCES University Chat Server <<<<<<<<<<\n\n";
    
    // create the server socket
    int server_socket;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    // define the server address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    server_address.sin_addr.s_addr = INADDR_ANY;

    // bind the socket to the specified IP and port
    bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));
    listen(server_socket, 5);
    
    //deffie helman key exhcange
    srand(time(0));
    long long privKeyServer = rand()%10+1;
    long long pubKeyServer = generatePublicKey(privKeyServer);
    bool flagrcv = false;
    bool flagsend = false;

    while (1) {
        // accept incoming connections
        int client_socket;
        client_socket = accept(server_socket, NULL, NULL);

        // create a new process to handle the client
        pid_t new_pid;
        new_pid = fork();
        if (new_pid == -1) {
            // error occurred while forking
            cout << "Error! Unable to fork process.\n";
        } else if (new_pid == 0) {
            // child process handles the client
            while (true) {
            //to make sure that key exchanged one time only
            if(flagrcv==false){
                // clear buffer and receive public key from client
                memset(buf, 0, sizeof(buf));
                recv(client_socket, buf, sizeof(buf), 0);
                long long rcvdClientPubKey = stoll(buf);
                cout<<"Received Public Key from Client "<<rcvdClientPubKey<<endl;
                
                long long sharedKey = computeSharedSecret(rcvdClientPubKey, privKeyServer);
                cout <<"Shared Secret Key (Server) :" <<sharedKey<<endl;
                unsigned char aesKey[16];
		deriveAESKey(sharedKey, aesKey);
		cout << "Derived 16-byte AES key (Server): ";
		for (int i = 0; i < 16; ++i) {
		    printf("%02x", aesKey[i]);
		}
		cout << endl;
                flagrcv = true;
                }
                //send the key to client
		if(flagsend==false){
		string pubKeyMsg = to_string(pubKeyServer);
		send(client_socket, pubKeyMsg.c_str(), pubKeyMsg.size()+1, 0);
		cout<<"Send publicKey to client: " <<pubKeyServer <<endl;
		flagsend=true;
		}
                
                // clear buffer and receive message from client
                memset(buf, 0, sizeof(buf));
                recv(client_socket, buf, sizeof(buf), 0);

                // if client sends "exit", close the connection
                if (strcmp(buf, "exit") == 0) {
                    cout << "Client disconnected.\n";
                    break;
                }

                cout << "Client: " << buf << endl;
                // Send a response back to the client
                cout << "You (Server): ";
                string response;
                getline(cin, response);
                strcpy(message + 8, response.c_str()); // append the response after "Server: "
                send(client_socket, message, sizeof(message), 0);
            }

            // Close the client socket after communication
            close(client_socket);
            exit(0);
        } else {
            // parent process continues accepting clients
            close(client_socket);
        }
    }

    close(server_socket);

    return 0;
}
