static float yo(int i, short s, unsigned long long ull, int j, int *p, char c,
		const char *str, double d, float f, long double ld)
{
	(void)i;
	(void)s;
	(void)ull;
	(void)j;
	(void)p;
	(void)c;
	(void)str;
	(void)d;
	(void)f;
	(void)ld;
	return 3.14;
}

static int test()
{
	float f;
	int i = 5;
	f = yo(i, 7, 18446744073709551615ull, 666666, (int *)-2, 13, "yo",
	       567.890, 1.23456789, 9.876543210987654321);
	return (int)f;
}

int main(void)
{
	return test();
}
