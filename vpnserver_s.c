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
#include <unistd.h>

#include <shadow.h>
#include <crypt.h>

#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) {ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

//struct sockaddr_in peerAddr;
void tunSelected(int tunfd, int sockfd, SSL* ssl);
void socketSelected (int tunfd, int sockfd, SSL* ssl);

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}

// int initTCPServer() {
//   int sockfd;
//   struct sockaddr_in server;
//   char buff[100];

//   memset(&server, 0, sizeof(server));
//   server.sin_family = AF_INET;                 
//   server.sin_addr.s_addr = htonl(INADDR_ANY);
//   server.sin_port = htons(PORT_NUMBER);        

//   sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//   bind(sockfd, (struct sockaddr*) &server, sizeof(server)); 

//     // Wait for the VPN client to "connect".
//   bzero(buff, 100);
//   int peerAddrLen = sizeof(struct sockaddr_in);
//   int len = recvfrom(sockfd, buff, 100, 0,                  
//     (struct sockaddr *) &peerAddr, &peerAddrLen);

//   printf("Connected with the client: %s\n", buff);
//   return sockfd;
// }

int authClient(SSL* ssl){
  int len;
  char username[100];
  len = SSL_read (ssl, username, sizeof(username) - 1);
  username[len] = '\0';
  printf("Get username: %s\n",username);
  char password[100];
  len = SSL_read (ssl, password, sizeof(password) - 1);
  password[len] = '\0';
  printf("Get password: %s\n",password);
  
  struct spwd *pw;
  char *epasswd;
  pw = getspnam(username);
  if (pw == NULL) {
    printf("No such username\n");
    return -1; 
  }
  printf("Login name: %s\n", pw->sp_namp);
  printf("Passwd    : %s\n", pw->sp_pwdp);
  epasswd = crypt(password, pw->sp_pwdp);
  if (strcmp(epasswd, pw->sp_pwdp)) {
    printf("Wrong password\n");
    return -1; 
  }
  return 1;
}

void processRequest(int tunfd, SSL* ssl, int sockfd)
{
  char buf[1024];
  int len = SSL_read (ssl, buf, sizeof(buf) - 1);
  buf[len] = '\0';
  printf("Received: %s\n",buf);

  // Construct and send the HTML page
  char *reply ="Connected from server\r\n";
  SSL_write(ssl, reply, strlen(reply));
  //SSL_shutdown(ssl);  SSL_free(ssl);

  if(authClient(ssl)==1){
    char *success ="SUCC";
    SSL_write(ssl, success, strlen(success));
  }
  else{
    char *fail = "FAIL";
    SSL_write(ssl, fail, strlen(fail));
    // here might need a better function
    return;
  }

  int i=0;
  while (1) {
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

int setupTCPServer()
{
  struct sockaddr_in sa_server;
  int listen_sock;
    //We may have to use AF_INET here, dont know why
  listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  CHK_ERR(listen_sock, "socket");
  memset (&sa_server, '\0', sizeof(sa_server));
  sa_server.sin_family      = AF_INET;
  sa_server.sin_addr.s_addr = htonl(INADDR_ANY);
  sa_server.sin_port        = htons (PORT_NUMBER);

  int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
  CHK_ERR(err, "bind");

  err = listen(listen_sock, 5);
  CHK_ERR(err, "listen");
  return listen_sock;
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




int main () {
  // SSL_METHOD *meth;
  // SSL_CTX* ctx;
  SSL *ssl;
  int tunfd;
  int sockfd;

  // // Step 0: OpenSSL library initialization 
  // // This step is no longer needed as of version 1.1.0.
  // SSL_library_init();
  // SSL_load_error_strings();
  // SSLeay_add_ssl_algorithms();

  // // Step 1: SSL context initialization
  // meth = (SSL_METHOD *)TLSv1_2_method();
  // ctx = SSL_CTX_new(meth);
  // SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  // // Step 2: Set up the server certificate and private key
  // SSL_CTX_use_certificate_file(ctx, "./cert_server/server-cert.pem", SSL_FILETYPE_PEM);
  // SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);
  // // Step 3: Create a new SSL structure for a connection
  // ssl = SSL_new (ctx);

  struct sockaddr_in sa_client;
  size_t client_len;
  tunfd = createTunDevice();
  sockfd = setupTCPServer();
  

  while(1){
    int sock = accept(sockfd, (struct sockaddr*)&sa_client, &client_len);
    if(fork() == 0) { // The child process
      close (sockfd);

      SSL_METHOD *meth;
      SSL_CTX* ctx;
      SSL *ssl;
      // Step 0: OpenSSL library initialization 
      // This step is no longer needed as of version 1.1.0.
      SSL_library_init();
      SSL_load_error_strings();
      SSLeay_add_ssl_algorithms();
      // Step 1: SSL context initialization
      meth = (SSL_METHOD *)TLSv1_2_method();
      ctx = SSL_CTX_new(meth);
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
      // Step 2: Set up the server certificate and private key
      SSL_CTX_use_certificate_file(ctx, "./cert_server/server-cert.pem", SSL_FILETYPE_PEM);
      SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);
      // Step 3: Create a new SSL structure for a connection
      ssl = SSL_new (ctx);

      SSL_set_fd (ssl, sock);
      // I don't know why but if I use err there will always be some problems
      if ((SSL_accept (ssl)) < 1) {
        ERR_print_errors_fp(stderr); 
        exit(2); 
      }
      printf ("SSL connection established!\n");
      printf("%s\n", inet_ntoa(sa_client.sin_addr));
      printf("%d\n", ssl->init_num);
      // when the connection is established, use this function to finish the vpn task
      processRequest(tunfd, ssl, sock);
      SSL_shutdown(ssl);  SSL_free(ssl);
      close(sock);
      return 0;
    } 
    else { // The parent process
      close(sock);
    }
    //return 0;
  }
} 