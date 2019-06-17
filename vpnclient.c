#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#define BUFF_SIZE 2000
#define C_PORT_NUMBER 60000
#define SERVER_IP "10.0.2.5" 
#define SERVER_NAME "zuovpnserver.com"
#define SERVER_PORT 55556
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "./ca_client" 
#define CA_FILE "./ca_client/cacert.pem"


struct sockaddr_in peerAddr;

int sendAuth(SSL* ssl){
  char username[100],password[100],buf[100];
  printf("Input the username:  ");
  scanf("%s",username);
  printf("Input the password:  ");
  scanf("%s",password);
  SSL_write(ssl, username, strlen(username));
  SSL_write(ssl, password, strlen(password));
  int len;
  len = SSL_read (ssl, buf, sizeof(buf) - 1);
  buf[len] = '\0';
  if (strcmp(buf, "SUCC")) {
    printf("Wrong password or username\n");
    return 0; 
  }
  printf("Correct username and password\n");
  return 1;
}

int createTunDevice() {
  int tunfd;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

  tunfd = open("/dev/net/tun", O_RDWR);
  ioctl(tunfd, TUNSETIFF, &ifr);       

  return tunfd;
}

int connectToTCPServer(){
  int sockfd;
  char *hello="Hello";
  struct sockaddr_in client;
  char buff[100];

  memset(&client, 0, sizeof(client));
  client.sin_family = AF_INET;                 
  client.sin_addr.s_addr = htonl(INADDR_ANY);
  client.sin_port = htons(C_PORT_NUMBER);

  memset(&peerAddr, 0, sizeof(peerAddr));
  peerAddr.sin_family = AF_INET;
  peerAddr.sin_port = htons(SERVER_PORT);
  peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  bind(sockfd, (struct sockaddr*) &client, sizeof(client)); 

  // Send a hello message to "connect" with the VPN server
  sendto(sockfd, hello, strlen(hello), 0,
    (struct sockaddr *) &peerAddr, sizeof(peerAddr));
  return sockfd;
}

void tunSelected(int tunfd, int sockfd, SSL* ssl){
  int  len;
  char buff[BUFF_SIZE];

  printf("Got a packet from TUN\n");

  bzero(buff, BUFF_SIZE);
  len = read(tunfd, buff, BUFF_SIZE);
  buff[len] = '\0';
  SSL_write(ssl, buff, len);
}

void socketSelected (int tunfd, int sockfd, SSL* ssl){
  int  len;
  char buff[BUFF_SIZE];

  printf("Got a packet from the tunnel\n");

  bzero(buff, BUFF_SIZE);
  len = SSL_read(ssl, buff, BUFF_SIZE);
  buff[len] = '\0';
    if(len==0){
    SSL_shutdown(ssl);  
    SSL_free(ssl);
    close(sockfd);
    exit(0);
  }
  write(tunfd, buff, len);
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   if(SSL_CTX_load_verify_locations(ctx,CA_FILE, CA_DIR) < 1){
    printf("Error setting the verify locations. \n");
    exit(0);
   }
   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}

int setupTCPClient(const char* hostname, int port){
  struct sockaddr_in server_addr;

  // Get the IP address from hostname
  struct hostent* hp = gethostbyname(hostname);

  // Create a TCP socket
  int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // Fill in the destination information (IP, port #, and family)
  memset (&server_addr, '\0', sizeof(server_addr));
  memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
  server_addr.sin_port   = htons (port);
  server_addr.sin_family = AF_INET;

  // The uinformation of the client
  struct sockaddr_in client;
  memset(&client, 0, sizeof(client));
  client.sin_family = AF_INET;                 
  client.sin_addr.s_addr = htonl(INADDR_ANY);
  client.sin_port = htons(C_PORT_NUMBER);
  bind(sockfd, (struct sockaddr*) &client, sizeof(client)); 

  // Connect to the destination
  connect(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr));

  return sockfd;
}

int main (int argc, char * argv[]) {
  char *hostname = SERVER_NAME;
  int port = SERVER_PORT;
  if (argc > 1) hostname = argv[1];
  if (argc > 2) port = atoi(argv[2]);

  int tunfd;
  tunfd  = createTunDevice();

  /*----------------TLS initialization ----------------*/
  SSL *ssl   = setupTLSClient(hostname);
  /*----------------Create a TCP connection ---------------*/
  int sockfd = setupTCPClient(hostname, port);
  /*----------------TLS handshake ---------------------*/
  SSL_set_fd(ssl, sockfd);
  int err = SSL_connect(ssl); 
  CHK_SSL(err);
  printf("SSL connection is successful\n");
  printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
  /*----------------Send/Receive data --------------------*/
  char buf[9000];
  char sendBuf[200];
  sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n", hostname);
  SSL_write(ssl, sendBuf, strlen(sendBuf));

  int len;
  len = SSL_read (ssl, buf, sizeof(buf) - 1);
  buf[len] = '\0';
  printf("%s\n",buf);
  if(! sendAuth(ssl)) 
    // need another function
    return 0;
  printf("VPN is almost ready!\n");

  int i=0;
  while (1){
    fd_set readFDSet;

    FD_ZERO(&readFDSet);
    FD_SET(sockfd, &readFDSet);
    FD_SET(tunfd, &readFDSet);
    select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

    if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd, ssl);
    if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
  }
  printf("finished\n");
}