#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>
#include <cmath>
#include <ctime>
#include <vector>
#include<fstream>
#include <iomanip>
#include <string>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

const long long P = 23;
const long long alpha = 5;
unsigned char aesKey[16];
unsigned char aesKey2[16];
string ultimateUname;

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

void sendMsg2Client(const string& message, int client_sock) {
    char buf[256];
    memset(buf, 0, sizeof(buf)); 
    strcpy(buf, message.c_str());  
    send(client_sock, buf, sizeof(buf), 0); 
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

void deriveNewKey(long long sharedSecret, unsigned char* key, string uname,  int key_length = 16) {
   
    string sharedSecretStr = to_string(sharedSecret);
    sharedSecretStr = uname+sharedSecretStr;
    cout<<"Shared Secret Key: "<<sharedSecretStr<<endl;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(sharedSecretStr.c_str()), sharedSecretStr.size(), hash);

    memcpy(key, hash, key_length);
}

void deriveAESKey(long long sharedSecret, unsigned char* key, int key_length = 16) {
   
    string sharedSecretStr = to_string(sharedSecret);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(sharedSecretStr.c_str()), sharedSecretStr.size(), hash);

    memcpy(key, hash, key_length);
}

string decryptAES(const vector<unsigned char>& ciphertext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    vector<unsigned char> plaintext(ciphertext.size());
    int len;
    int plaintext_len;

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
        handleErrors();
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return string(plaintext.begin(), plaintext.end());
}

// Function to generate a random 8-byte (64-bit) salt
string generateSalt() {
    unsigned char salt[8];  // 8 bytes for a 16-character hexadecimal salt
    RAND_bytes(salt, sizeof(salt));
    stringstream ss;
    for (int i = 0; i < 8; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(salt[i]);
    }
    return ss.str();
}

// Function to hash a password with a salt using SHA-256
string hashPassword(const string& password, const string& salt) {
    string saltedPassword = password + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(saltedPassword.c_str()), saltedPassword.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

bool isUsernameTaken(const string& username, const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        // File does not exist, meaning no users are registered yet
        return false;
    }
    
    
    string line;

    while (getline(file, line)) {
        size_t pos = line.find("username: ");
        if (pos != string::npos) {
            size_t start = pos + 10;
            size_t end = line.find(",", start);
            string foundUsername = line.substr(start, end - start);

            if (foundUsername == username) {
                return true;
            }
        }
    }

    return false;
}

// Function to store user credentials
bool storeUser(const string& email, const string& username, const string& password, const string& filename) {
    // Check if the username already exists
    if (isUsernameTaken(username, filename)) {
        cout << "Username already exists." << endl;
        return false;
    }

    // Generate salt and hash the password
    string salt = generateSalt();
    string hashedPassword = hashPassword(password, salt);

    ofstream file(filename, ios::app);
    if (!file) {
        cerr << "Error opening file." << endl;
        return false;
    }

    // Write the user's information
    file << "email: " << email << ", username: " << username 
         << ", password: " << hashedPassword << " salt: " << salt << endl;

    cout << "User registered successfully." << endl;
    return true;
}

bool retrievePasswordAndSalt(const string username, const string filename, string& hashedPassword, string& salt) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error opening file." << endl;
        return false;
    }
    
    string line;
    while (getline(file, line)) {
        size_t pos = line.find("username: ");
        if (pos != string::npos) {
            size_t start = pos + 10;
            size_t end = line.find(",", start);
            string foundUsername = line.substr(start, end - start);

            size_t passwordEnd;
            if (foundUsername == username) {
                // Extract hashed password
                size_t passwordPos = line.find("password: ", end);
                if (passwordPos != string::npos) {
                    size_t passwordStart = passwordPos + 10;
                    passwordEnd = line.find(" ", passwordStart);
                    hashedPassword = line.substr(passwordStart, passwordEnd - passwordStart);
                }
                
                // Extract salt
                size_t saltPos = line.find("salt: ", passwordEnd);
                if (saltPos != string::npos) {
                    size_t saltStart = saltPos + 6;
                    salt = line.substr(saltStart);
                }

                file.close();
                return true;  // Successfully retrieved password and salt
            }
        }
    }

    file.close();
    return false;  // Username not found
}

bool verifyLogin(string uname, string pwd, string filename)
{
 //Check if the username exists
    if (isUsernameTaken(uname, filename)) {
    
    //retrieve password and salt for this username
        string storedHashedPassword, storedSalt;
        if (retrievePasswordAndSalt(uname, filename, storedHashedPassword, storedSalt)) {
            // Hash the entered password with the retrieved salt and compare
            string enteredHashedPassword = hashPassword(pwd, storedSalt);
           
            if (enteredHashedPassword == storedHashedPassword) {
                cout << "Login successful." << endl;
                return true;
            } else {
                cout << "Password incorrect." << endl;
                return false;
          }
    	}
	else
	 {
	   cout<<"error retrieving data"<<endl;
	   return false; 
	 }
    }
    else
    {
     cout<<"Username incorrect."<<endl;
     return false;
    }

}

void loginProcess(int client_socket)
{

    EncryptedLoginData data;
    int bytes_received = recv(client_socket, reinterpret_cast<unsigned char*>(&data), sizeof(data), 0);

    if (bytes_received <= 0) {
        cerr << "Error: Failed to receive data or connection closed by client." << endl;
    } else {

        cout << "Received IV: ";
        for (int i = 0; i < 16; ++i) {
            cout << hex << static_cast<int>(data.iv[i]) << " ";
        }
        cout << dec << endl;

        cout << "Received Encrypted Username: ";
        for (int i = 0; i < 16; ++i) {
            cout << hex << static_cast<int>(data.uname[i]) << " ";
        }
        cout << dec << endl;

        cout << "Received Encrypted Password: ";
        for (int i = 0; i < 16; ++i) {
            cout << hex << static_cast<int>(data.password[i]) << " ";
        }
        cout << dec << endl;

        // decrypting the fields
        string uname, pwd;
        uname = decryptAES(vector<unsigned char>(data.uname, data.uname + 16), aesKey, data.iv);
        pwd = decryptAES(vector<unsigned char>(data.password, data.password + 16), aesKey, data.iv);
	
	cout << "Decrypted Username: " << uname << endl;
	cout << "Decrypted Password: " << pwd << endl;

	if (verifyLogin(uname, pwd, "creds.txt")) {
		cout << "User logged in successfully." << endl;
		ultimateUname=uname;
	    } else {
		cout << "Username or password is incorrect." << endl;
		sendMsg2Client("Username or password is incorrect.", client_socket);
		
	    }

	 }
}

void registrationProcess(int client_socket)
{

    EncryptedData data;
    int bytes_received = recv(client_socket, reinterpret_cast<unsigned char*>(&data), sizeof(data), 0);

    if (bytes_received <= 0) {
        cerr << "Error: Failed to receive data or connection closed by client." << endl;
    } else {

        cout << "Received IV: ";
        for (int i = 0; i < 16; ++i) {
            cout << hex << static_cast<int>(data.iv[i]) << " ";
        }
        cout << dec << endl;

        cout << "Received Encrypted Email: ";
        for (int i = 0; i < 32; ++i) {
            cout << hex << static_cast<int>(data.email[i]) << " ";
        }
        cout << dec << endl;

        cout << "Received Encrypted Username: ";
        for (int i = 0; i < 16; ++i) {
            cout << hex << static_cast<int>(data.uname[i]) << " ";
        }
        cout << dec << endl;

        cout << "Received Encrypted Password: ";
        for (int i = 0; i < 16; ++i) {
            cout << hex << static_cast<int>(data.password[i]) << " ";
        }
        cout << dec << endl;

        // decrypting the fields
        string email, uname, pwd;
        email = decryptAES(vector<unsigned char>(data.email, data.email + 32), aesKey, data.iv);
        uname = decryptAES(vector<unsigned char>(data.uname, data.uname + 16), aesKey, data.iv);
        pwd = decryptAES(vector<unsigned char>(data.password, data.password + 16), aesKey, data.iv);
	
	cout << "Decrypted Email: " << email << endl;
	cout << "Decrypted Username: " << uname << endl;
	cout << "Decrypted Password: " << pwd << endl;

	if (storeUser(email, uname, pwd, "creds.txt")) {
		cout << "User stored successfully." << endl;
		ultimateUname=uname;
	    } else {
		cout << "Failed to store user." << endl;
		sendMsg2Client("Username already exists.", client_socket);	
	    }
	 }
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
    
    long long privKeyServer2 = rand()%10+1;
    long long pubKeyServer2 = generatePublicKey(privKeyServer2);
    bool flagrcv2 = false;
    bool flagsend2 = false;
    bool flagg=false;

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
                
                if (strcmp(buf, "Registration initiated...") == 0) {
                    //cout << "Registration initiated..."<<endl;
                    memset(buf, 0, sizeof(buf));
                    registrationProcess(client_socket);
                }
                
                if (strcmp(buf, "Login initiated...") == 0) {
                    //cout << "Registration initiated..."<<endl;
                    memset(buf, 0, sizeof(buf));
                    loginProcess(client_socket);
                }
                
                if(!ulimateUname.empty() && flagg==false)
                {
                 cout <<"Shared new Secret Key (Server) :" <<ultimateUname + sharedKey2<<endl;
                 flagg=true;
                }
		///2nd key exchange
		/*if(flagrcv2==false){
                // clear buffer and receive public key from client
                memset(buf, 0, sizeof(buf));
                recv(client_socket, buf, sizeof(buf), 0);
                long long rcvdClientPubKey2 = stoll(buf);
                cout<<"Received new Public Key from Client "<<rcvdClientPubKey2<<endl;
                
                long long sharedKey2 = computeSharedSecret(rcvdClientPubKey2, privKeyServer2);
                //cout <<"Shared new Secret Key (Server) :" <<ultimateUname+sharedKey2<<endl;
		deriveNewKey(sharedKey2, aesKey2, ultimateUname);
		cout << "Derived 16-byte AES key (Server): ";
		for (int i = 0; i < 16; ++i) {
		    printf("%02x", aesKey2[i]);
		}
		cout << endl;
                flagrcv2 = true;
                }
                //send the key to client
		if(flagsend2==false){
		string pubKeyMsg2 = to_string(pubKeyServer2);
		send(client_socket, pubKeyMsg2.c_str(), pubKeyMsg2.size()+1, 0);
		cout<<"Send publicKey to client: " <<pubKeyServer2 <<endl;
		flagsend2=true;
		string uname = ultimateUname;
		send(client_socket, uname.c_str(), uname.size()+1, 0);
		}
                */
                
                // clear buffer and receive message from client
                //memset(buf, 0, sizeof(buf));
                //recv(client_socket, buf, sizeof(buf), 0);

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
