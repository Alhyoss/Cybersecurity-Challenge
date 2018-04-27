#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "radium.h"

int main(int argc, char *argv[])
{
	struct radium_session session;
	memset(&session, 0, sizeof(session));

	if (radium_read_config(&session, "radium.conf") < 0) {
		return -1;
	} else if (session.secretkey[0] == '\0') {
		fprintf(stderr, "Config did not contain a secret key\n");
		return -1;
	} else if (session.password[0] == '\0') {
		fprintf(stderr, "Config did not contain a privileged command password\n");
		return -1;
	}

	// Terminate program after 5 seconds (prevent possible DoS)
	alarm(5);

	session.is_server = 1;
	return radium_loop(&session);
}

