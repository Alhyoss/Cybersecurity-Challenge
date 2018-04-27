#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "radium.h"

// Test using local server:   $ mkfifo network
//                            $ ./client radium.conf get_flag < network | ./server > network
//
// Run against remote server: $ ./client <(echo "") ping < network | nc 127.0.0.1 8023 > network
//
// Active man-in-the-middle:  $ (nc 127.0.0.1 8024 < network) | (nc 127.0.0.1 8023 | tee network | xxd)
//                            # Note that packets sent by the server are displayed using xxd. To print
//                            # client packets, switch both nc commands (or turn this into a script ;).
int main(int argc, char *argv[])
{
	struct radium_session session;
	memset(&session, 0, sizeof(session));

	if (argc < 3) {
		fprintf(stderr, "Usage: %s config command\n", argv[0]);
		return -1;
	} else if (radium_read_config(&session, argv[1]) < 0)
		return -1;

	// Terminate program after 5 seconds (prevent possible DoS)
	alarm(5);

	session.using_encryption = session.secretkey[0] == '\0';
	session.client_command = argv[2];
	return radium_loop(&session);
}

