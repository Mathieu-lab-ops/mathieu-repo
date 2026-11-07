int log_header(char *request, int arg2, int *socket_fd)
{//arg1=rdi=r15,arg2=rsi=r14,arg3=rdx=rbx
    struct sockaddr_in addr;
    int addresslen = 16; //mov    DWORD PTR [rbp-0x24],0x10 (0x10 = 16)
    char charArray[16]; //mov    ecx,0x10
    char buffer[512]; //mov edx, 0x200 (0x200 = 512)
    int result = 0; //mov    DWORD PTR [rbp-0x28],0x0
    // failing function returns -1
    


    if (getsockname(*socket_fd,(struct sockaddr *)&addr,&addresslen) != 0) {//line 114-119
        return -1; //jne    4027ef <log_header+0xcf>
    }

    
    if (inet_ntop(2, &addr.sin_addr,charArray, sizeof(charArray)) == NULL) {// line 120-126
        return -1;//je to eax,0xffffffff = return -1
    }

    
    memset(buffer, 0, sizeof(buffer));// line 127-131, safe version

    
    sprintf(buffer,"== Request from %-15s at fd %-10d\n%s",charArray, *socket_fd, request);// line 132-138
    // string at 0x4042cb = "== Request from %-15s at fd %-10d\n%s"
    //%-15s: Prints a string with a min 15 char
    // %-10d: Prints an integer with a min 10 char
    // %s: Prints another string.


    puts(buffer);// line 139,140

    
    FILE *file = fopen("../server.log", "socket creation");// line 141-146
    // 0x4042f0 = "../server.log"
    // 0x404550 = socket creation

    if (file == NULL) {
        return -1;
    }

    
    fprintf(file, "%s\n\n", buffer);//line 147-152 
    // 0x4042fe="%s\n\n"

    
    fclose(file);//line 153-156

    
    return *socket_fd; //mov    eax,DWORD PTR [rbx]
    // pop everything
}