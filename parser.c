#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Remove anything not necessary in the string */
void removeSubstr (char *string, char *sub) {
    char *match = string;
    int len = strlen(sub);
    while ((match = strstr(match, sub))) {
        *match = '\0';
        strcat(string, match+len);
        match++;
    }
}

int main() {
    int y;
    FILE *data;
    char action;
    char line[100]; 	// output parsed string is limited
    int counter = 0;
    char keyword[] = ""; // no function whatsoever
    int result,index = 0;


    struct rule {
        char keyword1[100];
        char keyword2[100];
    } ruleset[10];

    if((data=fopen("rule", "r")) != NULL) {
        while(fgets(line,sizeof(line),data)) {
            if((strcmp(line,keyword))) {
                char s[10] = "$,";
                char *token = strtok(line, s);

                while(token != NULL) {
                    /* char *end2; */
                    /* char *line2 = token; */
                    /* char *temporaryToken; */
                    /* printf("Token 1: %s\n", token); */
                    /* while(temporaryToken != NULL) { */
                    /*   printf("Token 2: %s\n", temporaryToken); */
                    /* } */
                    /* if(strcmp(token,"XML")==0) { */
                    /*     counter = 0; */
                    /* } */
                    if(counter==1) {
                        strcpy(ruleset[index].keyword1, token);
                    }
                    if(counter==2) {
                        strcpy(ruleset[index].keyword2, token);
                        index++;
                    }
                    counter++;
                    token = strtok(NULL, s);
                }
            }
        }
    }

    /* Skid's code */
    for(y = 0; y < index; y++) {
        //printf("%s ", directory[y].fName);
        /* removeSubstr(directory[y].fName, "RGS_"); */
        /* removeSubstr(directory[y].fName, "NAMES"); */
        /* removeSubstr(directory[y].fName, "ARGS"); */
        /* removeSubstr(directory[y].fName, "XML"); */
        //removeSubstr(ruleset[y].keyword1, "RGS_NAMES|ARGS|XML:/* \"");
        removeSubstr(ruleset[y].keyword1, "ARGS|XML:/* \"");
	removeSubstr(ruleset[y].keyword1, "RGS_NAMES|");
        printf("%s ", ruleset[y].keyword1);
        removeSubstr(ruleset[y].keyword2, "\" \"phase:2");
	//removeSubstr(ruleset[y].keyword2, "\" \"phasrev:\' rev:\'");
        printf("%s", ruleset[y].keyword2);
        printf("\n");
    }

    fclose(data);
    return 1;
}
