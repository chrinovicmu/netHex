#include <stdio.h>
#include <stdlib.h>
#define MAZ_LEN 256

struct Person{
    char name[MAZ_LEN];
    char surname[MAZ_LEN];
    int age;
    char accessed[MAZ_LEN];
};

int main(int argc, char *argv[])
{
    struct Person p = {"chris", "mukanya", 18, "yes"};


    struct Person * ptr = &p; 
    char *name_ptr = (char *)ptr; 
    char *accessed = name_ptr + (MAZ_LEN*2) + sizeof(int); 

    printf("%s\n", name_ptr);
    printf("%s\n", accessed);
    return EXIT_SUCCESS;
}
