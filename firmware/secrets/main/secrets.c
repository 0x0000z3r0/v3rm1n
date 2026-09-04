#include <stdio.h>

void
app_main(void)
{
	static const char *const artifacts[] = {
	    "https://api.example.com/v1/device",
	    "http://192.168.4.1/admin",
	    "updates.example.net",
	    "username=admin",
	    "password=v3rm1n-test-password",
	    "ssid=v3rm1n-test-network",
	    "api_key=v3rm1n-test-api-key-not-real",
	    "token=v3rm1n-test-token-not-real",
	    "-----BEGIN CERTIFICATE-----",
	    "-----BEGIN PRIVATE KEY-----",
	};

	for (size_t i = 0; i < sizeof(artifacts) / sizeof(artifacts[0]); i++)
		printf("%s\n", artifacts[i]);
}
