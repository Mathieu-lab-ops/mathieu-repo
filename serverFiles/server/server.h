#include <stddef.h>
#include <sys/socket.h>

#define MAX_PATH 300

struct credentials {
  char* user_name; //null-terminated string, struct ownes this buffer
  char passwd_sha256[32]; //not null-terminated
};

struct file_info {
  char file_name[MAX_PATH]; //Bug could put something longer than file name
  char mime_type[64];
  long file_size;
};


// ===== Functions with intentional bugs =====================================//

//Logs arg:header to stdout and to a log file
//Returns args:client_fd on success and -1 on error
int log_header(const char* header, ssize_t header_len, int* client_fd);

//Extracts the HTTP Authorization field, decodes the base64 value, and hashes
//the passwd with SHA256
//Returns true on success
//TIP: you don't need to understand every operation in this function to 
//find the bug
bool extract_credentials(const char* header, struct credentials* credentials); // base64 encoded is not encrypted if obtain header can decode

//Returns true if arg:header contains a valid username and password
bool authenticate(const char* header);

//Builds a 200 response in arg:response_buf, and creates (or overwrites) the
//file with arg:body
void build_200_response_create(const char* file_name, const char* body,
  int body_len, char* response_buf, size_t* response_len);// buffer overflow?

//Parses the request in arg:request_buf, logs the request header using 
//`log_header`, receives any remaining body data, executes the request, and 
//builds a response in arg:response_buf
//Arg:file_info is owned by the caller (meaning the calling is responsible for
//its memory management)
//TIP: this function contains multiple bugs
void parse_request(int client_fd, struct file_info* file_info, char* request_buf, ssize_t* request_buf_len, char* response_buf,
  size_t* response_len);

//Receives at least the whole header, calls `parse_request`, and sends the
//response back to the client using its file descriptor
//TIP: you probably do not need this bug
void handle_client(int client_fd);



// ===== Functions without (intentional) bugs ================================//

//Maps the file extension to a HTTP content-type string
//The returned char* points to a global constant
const char* ext_to_mime(const char* file_ext);

//Extracts and returns the HTTP Content-Length field as an int
//Returns -1 on error
int extract_content_length(const char* header);

//Extracts the file name from arg:header
//Passes ownership of the returned file name to the caller
//Returns null on error
char* extract_file_name(const char* header);

//Returns true if arg:file_name is inside the current (`server_data`) directory
//TIP: this function does not contain a bug, but its functionality interacts 
//with a bug in its caller
bool validate_file_name(const char* file_name);

//Builds a 200 response in arg:response_buf containing the contents 
//of the requested file
void build_200_response_read(struct file_info* file_info, char* response_buf,
  size_t* response_len);

//Builds a 200 response in arg:response_buf, and appends arg:body to the file
void build_200_response_append(const char* file_name, const char* body,
  int body_len, char* response_buf, size_t* response_len);

//Build and error response in arg:response_buf
void build_400_response(char* response_buf, size_t* response_len);
void build_401_response(char* response_buf, size_t* response_len);
void build_403_response(char* response_buf, size_t* response_len);
void build_404_response(char* response_buf, size_t* response_len);
void build_411_response(char* response_buf, size_t* response_len);
void build_413_response(char* response_buf, size_t* response_len);
void build_418_response(char* response_buf, size_t* response_len);
void build_500_response(char* response_buf, size_t* response_len);

//The entry function for each new connection thread
//Directly calls `handle_client`
void* handle(void* arg);

//Nothing to see here
void totally_unsuspicious_code();

//Prints the process ID to stdout
void print_pid();

//Minor initializations
void init();

//Creates and binds a socket, spawns a new thread for each incomming connection
int main(int argc, char* argv[]);
