#include <stdint.h>

#define PROC			"/proc"
#define CMDLINE			"cmdline"
#define TCP			"/proc/net/tcp"
#define TCP6			"/proc/net/tcp6"
#define UDP			"/proc/net/udp"
#define UDP6			"/proc/net/udp6"
#define READ_SIZE		1
#define LINE_DELIMITER		'\n'
#define COLON			':'
#define IPV4_STR_LEN		15
#define IPV6_HEX_STR_LEN	32
#define MAX_SOCKET_SIZE		256
#define STATE_ESTABLISHED	0x01
#define STATE_TIME_WAIT		0x06
#define STATE_LISTEN		0x0A	/* TCP listen state */
#define STATE_ALT_LISTEN	0x07	/* UDP listen state */
#define IPV4_COLUMN_HEADERS	"Proto\tLocal Address\t\tForeign Address\t\tState\t\tPID\t\tProcess"
#define IPV6_COLUMN_HEADERS	"Proto\tLocal Address\t\t\t\t\t\tForeign Address\t\t\t\t\t\tState\t\tPID\t\tProcess"
#define IPV4_DELIM		"-----------------------------------------------------------------------------------------------------------------------------------------------"
#define IPV6_DELIM		"--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"

struct netstat
{
	char *local_ip;
	char *remote_ip;
	uint16_t local_port;
	uint16_t remote_port;
	uint32_t inode;
	int pid;
	int state;
	char *path;
	char *arguments;
};

void print_socket_info(char *label, char *type);
struct netstat **get_socket_info(char *socket_file, int *struct_size);
char *get_cmdline_args(int pid);
char *read_file(char *file_name, int *file_size);
char *parse_socket_string(char *socket_string, uint16_t *port);
void resolve_socket_owners(struct netstat **socket_info, int socket_info_size);
char *dotted_decimal(uint32_t ip);
char *format_ipv6(char *raw_v6);
char *link_info(char *link_file);
char *get_column(char *row, int colnum);
int is_numeric_string(char *string);
uint32_t byteswap32(uint32_t byte);
