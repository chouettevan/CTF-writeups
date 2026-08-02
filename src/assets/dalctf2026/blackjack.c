#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NAME_BUF  64

static const char *card_name(int c) {
    static const char *names[] = {
        "A","2","3","4","5","6","7","8","9","10","J","Q","K"
    };
    return names[c - 1];
}

static int draw_card(void) {
    return (rand() % 13) + 1;
}

static int hand_total(int *cards, int n) {
    int total = 0;
    int aces = 0;
    for (int i = 0; i < n; i++) {
        int c = cards[i];
        if(c == 1){ 
          aces++; 
          total += 11; 
        }
        else if(c >= 11) total += 10;
        else total += c;
    }
    while (total > 21 && aces > 0) { total -= 10; aces--; }
    return total;
}

static void print_hand(const char *label, int *cards, int n, int hide_second) {
    printf("%s: ", label);
    for (int i = 0; i < n; i++) {
        if (i == 1 && hide_second)
            printf("[?] ");
        else
            printf("%s ", card_name(cards[i]));
    }
    printf("(%d)\n", hide_second ? hand_total(cards, 1) : hand_total(cards, n));
}


static int play_hand(void) {
    int p[12], d[12];
    int pc = 0, dc = 0;

    p[pc++] = draw_card(); 
    d[dc++] = draw_card();
    p[pc++] = draw_card(); 
    d[dc++] = draw_card();

    printf("\n--- New Hand ---\n");
    print_hand("Dealer shows", d, dc, 1);
    print_hand("Your hand   ", p, pc, 0);

    int bust = 0;
    while (1) {
        int total = hand_total(p, pc);
        if (total > 21) { printf("Bust! You lose.\n"); bust = 1; break; }
        if (total == 21) { printf("Blackjack!\n"); break; }
        printf("(h)it or (s)tand? ");
        char c[4];
        fgets(c, sizeof(c), stdin);
        if (c[0] != 'h' && c[0] != 'H') break;
        p[pc++] = draw_card();
        printf("You drew: %s. ", card_name(p[pc - 1]));
        print_hand("Hand", p, pc, 0);
    }

    if (bust) return 0;

    int ptotal = hand_total(p, pc);

    printf("Dealer reveals: ");
    print_hand("Dealer hand ", d, dc, 0);
    while (hand_total(d, dc) < 17) {
        d[dc++] = draw_card();
        printf("Dealer hits: %s. Dealer: %d\n",
               card_name(d[dc - 1]), hand_total(d, dc));
    }

    int dtotal = hand_total(d, dc);
    printf("You: %d  |  Dealer: %d\n", ptotal, dtotal);

    if (dtotal > 21 || ptotal > dtotal) {
        printf("You win!\n");
        return 1;
    } else if (ptotal == dtotal) {
        printf("Push. It's a tie.\n");
    } else {
        printf("Dealer wins.\n");
    }
    return 0;
}

void game_loop(void) {
    char name[NAME_BUF];
    int  won;

    while (1) {
        won = play_hand();

        if (won) {
            printf("\n*** You win! ***\n");
            printf("The casino will deposit your winnings.\n");
            printf("Enter your name for the transaction record: ");
            fgets(name, 256, stdin);
            name[strcspn(name, "\n")] = '\0';
            printf("Processing transaction for: ");
            printf(name);               
            printf("\n\n");
        }

        printf("Play another hand? [y/n]: ");
        fflush(stdout);
        int ch = fgetc(stdin);
        int tmp;
        while ((tmp = fgetc(stdin)) != '\n' && tmp != EOF);
        if (ch != 'y' && ch != 'Y') break;
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    srand(time(NULL));

    printf("+===========================================+\n");
    printf("|       Welcome to Boundary Casino!         |\n");
    printf("|    Here all tech works well and fast!     |\n");
    printf("|  Beat the dealer and claim your prize.    |\n");
    printf("+===========================================+\n\n");

    game_loop();

    printf("Thanks for playing!\n");
    return 0;
}
