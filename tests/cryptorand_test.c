#include "../cryptorand.c"
#include <stdio.h>

int main(int argc, char** argv)
{
    unsigned char pRandom[64] = {0};

    /* Initialize the random number generator first. */
    cryptorand rng;
    cryptorand_init(&rng);

    /* Now generate some random content. */
    cryptorand_generate(&rng, pRandom, sizeof(pRandom));

    /* Destroy the random number generator when we're done with it. */
    cryptorand_uninit(&rng);

    (void)argc;
    (void)argv;

    return 0;
}
