#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
    float income;
    float costs;
    float stock_price;
    float volatility;
    bool ai_company;
} Stock;


typedef bool (*Algorithm)(Stock e);

float askf(char *prompt) {
    printf("%s (0.0-100.0): ", prompt);
    char buf[0x10];
    fgets(buf, 0x100, stdin);
    return atof(buf);
}

bool askb(char *prompt) {
    printf("%s [Y/n]: ", prompt);
    char r = getchar();
    return r != 'n' && r != 'N';
}


float randf() {
    return (float)rand()/(float)RAND_MAX;
}

Stock create_stock() {
    Stock s;
    s.income = randf();
    s.costs = randf();
    s.stock_price = randf();
    s.volatility = randf();
    s.ai_company = randf() > 0.5;
    return s;
}


int main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    srand(time(NULL));

    float profit = askf("How important is profits to you?");
    float price = askf("How much do you value big stocks?");
    float risk = askf("How risk tolerant are you?");
    bool ai = askb("Do you want to be rich?");

    Algorithm algorithm;
    if (ai) {
        bool ai_alg(Stock s) {
            puts("AI alg");
            return s.ai_company;
        }
        algorithm = ai_alg;
    } else {
        bool real_alg(Stock s) {
            puts("Real alg");
            return ((s.income - s.costs)*profit + s.stock_price*price + s.volatility*risk) > 10;
        }
        algorithm = real_alg;
    }


    float made = 0;
    for (int i = 0; i < 10; i++) {
        Stock s = create_stock();
        bool bought = algorithm(s);

        float new_price = randf();
        if (bought) {
            made += new_price-s.stock_price;
        }
    }

    if (made > 0) {
        printf("Yaaay you made %f dkk and are rich now\n", made);
    } else {
        printf("You lost %f dkk sorry tough luck\n", made);
    }

    return 0;
}

void gadget() {
    __asm__(
        "jmp %rsp; ret;"
    );
}
