#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT     53
#define MAXLINE 1024

int
main ()
{
  int sockfd;
  char buffer[MAXLINE];
  char *hello = "Hello from server";

  struct sockaddr_in servaddr, cliaddr;
  char name[128] = { 0 };

  // Creating socket file descriptor
  if ((sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
      perror ("socket creation failed");
      exit (EXIT_FAILURE);
    }

  memset (&servaddr, 0, sizeof (servaddr));
  memset (&cliaddr, 0, sizeof (cliaddr));

  // Filling server information
  servaddr.sin_family = AF_INET;        // IPv4
  servaddr.sin_addr.s_addr = inet_addr ("182.167.50.30");
  servaddr.sin_port = htons (PORT);

  if (bind (sockfd, (const struct sockaddr *) &servaddr,
            sizeof (servaddr)) < 0)
    {
      perror ("bind failed");
      exit (EXIT_FAILURE);
    }

  int len, n;
  n = recvfrom (sockfd, (char *) buffer, MAXLINE,
                MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
  buffer[n] = '\0';
  (void) gethostname (name, 127);
  printf ("Client : %s \n", buffer);
  sendto (sockfd, (const char *) hello, strlen (hello),
          MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);
  printf ("%s\n", hello);
  return 0;
}