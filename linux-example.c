#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "P256-cortex-ecdh.h"

static void get_random_bytes(unsigned char* buf, int len) {
	int rand_fd = open("/dev/urandom", O_RDONLY);
        if (rand_fd < 0) {
                perror("opening /dev/urandom");
                exit(1);
        }

	int nread = 0;
	while (len) {
		int nbytes = read(rand_fd, buf + nread, len);
		if (nbytes < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("get_random_bytes");
			exit(1);
		}
		if (nbytes == 0) {
			fprintf(stderr, "rand_fd closed\n");
			exit(1);
		}
		nread += nbytes;
		len -= nbytes;
	}
	close(rand_fd);
}

int main() {
	unsigned char secret_key_alice[32], secret_key_bob[32];
	unsigned char public_key_alice[64], public_key_bob[64];
	unsigned char shared_secret_alice[32], shared_secret_bob[32];

	// Alice computes
	do {
		get_random_bytes(secret_key_alice, 32);
	} while (!P256_ecdh_keygen(public_key_alice, secret_key_alice));

	// Bob computes
	do {
		get_random_bytes(secret_key_bob, 32);
	} while (!P256_ecdh_keygen(public_key_bob, secret_key_bob));

	// The public keys are now exchanged over some protocol

	// Alice computes
	if (!P256_ecdh_shared_secret(shared_secret_alice, public_key_bob, secret_key_alice)) {
		puts("Bob provided an invalid public key (probably trying some attack)");
		exit(1);
	}

	// Bob computes
	if (!P256_ecdh_shared_secret(shared_secret_bob, public_key_alice, secret_key_bob)) {
		puts("Alice provided an invalid public key (probably trying some attack");
		exit(1);
	}

	if (memcmp(shared_secret_alice, shared_secret_bob, 32) == 0) {
		puts("SUCCESS: Both Bob and Alice computed the same shared secret");
	} else {
		puts("FAILED: Bob and Alice did not compute the same shared secret");
		exit(1);
	}

	return 0;
}
