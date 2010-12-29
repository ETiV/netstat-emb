/* Simple utility that combines functionality from netstat and lsof. Intended as a netstat replacement for Linux-based embedded systems that do not include netstat/lsof. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include "netstat-emb.h"
#include "config.h"

int main(int argc, char *argv[])
{
	printf("\n");

	if(argc == 2)
	{
		if(argv[1][1] == '6')
		{
			printf("%s\n%s\n", IPV6_COLUMN_HEADERS, IPV6_DELIM);
			print_socket_info("tcp6", TCP6);
			print_socket_info("udp6", UDP6);
		} else {
			printf("Usage: %s [-6]\n", argv[0]);
		}
		goto end;
	}

	printf("%s\n%s\n", IPV4_COLUMN_HEADERS, IPV4_DELIM);
	print_socket_info("tcp", TCP);
	print_socket_info("udp", UDP);

end:
	printf("\n");
	return EXIT_SUCCESS;
}

/* Prints socket info to stdout */
void print_socket_info(char *label, char *type)
{
	int i = 0, netstat_size = 0;
        struct netstat **netstat = NULL;

	netstat = get_socket_info(type, &netstat_size);

        for(i=0; i<netstat_size; i++)
        {
		printf("%s\t", label);

		/* This "prettifies" the output and prevents '(null)' from being printed by printf */
		if(netstat[i]->path == NULL)
		{
			netstat[i]->path = strdup(" ");
		}
		if(netstat[i]->arguments == NULL)
		{
			netstat[i]->arguments = strdup(" ");
		}

		/* Print local/remote ip/port */
                printf("%-18s\t%d\t", netstat[i]->local_ip, netstat[i]->local_port);
                printf("\t%-18s\t%d\t", netstat[i]->remote_ip, netstat[i]->remote_port);
	
		/* Print the current socket state */
                switch(netstat[i]->state)
                {
			case STATE_LISTEN:
			case STATE_ALT_LISTEN:
                        	printf("\tLISTEN     ");
				break;
			case STATE_TIME_WAIT:
				printf("\tTIME_WAIT  ");
				break;
			case STATE_ESTABLISHED:
				printf("\tESTABLISHED");
				break;
			default:
                        	printf("\tUNKNOWN    ");
                }

		/* Print the owner's PID, file path, and command line arguments */
                printf("\t%-8d\t%s %s\n", netstat[i]->pid, netstat[i]->path, netstat[i]->arguments);
        
		/* Free up malloced strings */
                if(netstat[i]->local_ip) free(netstat[i]->local_ip);
                if(netstat[i]->remote_ip) free(netstat[i]->remote_ip);
		if(netstat[i]->path) free(netstat[i]->path);
		if(netstat[i]->arguments) free(netstat[i]->arguments);
		free(netstat[i]);
        }

	if(netstat) free(netstat);
	return;
}

/* Parses the socket file data and allocates/populates the netstat structure */
struct netstat **get_socket_info(char *socket_file, int *struct_size)
{
	int count = 0, file_size = 0;
	char *file = NULL, *row = NULL;
	char *local_str = NULL, *remote_str = NULL, *state_str = NULL, *inode_str = NULL;
	struct netstat **net_info = NULL, **tmp = NULL;
	uint16_t local_port = 0, remote_port = 0;

	/* Read in the socket info file */
	file = read_file(socket_file, &file_size);
	if(!file || file_size == 0)
	{
		goto end;
	}

	/* row is used to iterate through lines in file */
	row = file;

	while(1)
	{
		/* Go to the next line in the file (the first line is the column names, which we ignore) */
		row = strchr(row, LINE_DELIMITER);
		if(!row)
		{
			break;
		}
		row++;

		/* Be sure we haven't gotten to the end of the file */
 		if(strlen(row) == 0)
		{
			break;
		}

		/* Get the column strings for columns 1, 2 and 9 */
		local_str = get_column(row, 1);
		remote_str = get_column(row, 2);
		state_str = get_column(row, 3);
		inode_str = get_column(row, 9);
 
		if(local_str && remote_str && inode_str)
		{
			/* Allocate space for another struct netstat pointer */
			tmp = net_info;
			net_info = realloc(net_info, sizeof(struct netstat *) * count+1);
			if(!net_info)
			{
				perror("realloc");
				if(tmp) free(tmp);
				count = 0;
				goto end;
			}

			/* Allocate some memory for the netstat structure */
			net_info[count] = malloc(sizeof(struct netstat));
			if(!net_info[count])
			{
				perror("malloc");
				goto end;
			}
			memset(net_info[count], 0, sizeof(struct netstat));

			/* Parse out the IP addresses and port numbers */
			net_info[count]->local_ip = parse_socket_string(local_str, &local_port);
			net_info[count]->remote_ip = parse_socket_string(remote_str, &remote_port);

			/* Populate the known fields of the netstat structure */
			net_info[count]->inode = atoi(inode_str);
			net_info[count]->local_port = local_port;
			net_info[count]->remote_port = remote_port;
			net_info[count]->state = strtoul(state_str, NULL, 16);

			/* Increment the structure counter */
			count++;
		} else {
			fprintf(stderr, "ERROR: Failed to parse socket entry in %s\n", socket_file);
		}

		if(local_str) free(local_str);
		if(remote_str) free(remote_str);
		if(state_str) free(state_str);
		if(inode_str) free(inode_str);
	}

	/* Figure out which processes own each open socket */
        resolve_socket_owners(net_info, count);

end:
	*struct_size = count;
	return net_info;
}

/* Loops through the /proc directory and attempts to resolve each socket in the netstat structure to the process that opened it */
void resolve_socket_owners(struct netstat **socket_info, int socket_info_size)
{
	int i = 0;
	DIR *proc_dir = NULL, *fd_dir = NULL;
	struct dirent *proc_dir_info = NULL, *fd_dir_info = NULL;
	char fd_dir_name[FILENAME_MAX] = { 0 }, link_path[FILENAME_MAX] = { 0 }, exe_path[FILENAME_MAX] = { 0 };
	char socket_name[MAX_SOCKET_SIZE] = { 0 };
	char *link_name = NULL;

	/* Open the /proc directory */	
	proc_dir = opendir(PROC);
	if(!proc_dir)
	{
		perror("opendir");
		goto end;
	}

	/* Loop through each entry in /proc */
	while((proc_dir_info = readdir(proc_dir)) != NULL)
	{
		/* If the file name inside of /proc is a number, it's probably a PID directory.
		 * Checking the file type to see if this is a directory is explicitly skipped here, as
		 * some file systems don't support file types.
		 */
		if(is_numeric_string(proc_dir_info->d_name))
		{
			/* Create the full path to this process's file descriptor directory: /proc/{pid}/fd */
			memset((void *) &fd_dir_name, 0, FILENAME_MAX);
			snprintf((char *) &fd_dir_name, FILENAME_MAX-1, "%s/%s/fd", PROC, proc_dir_info->d_name);

			/* Open the file descriptor directory */
			fd_dir = opendir(fd_dir_name);
			if(!fd_dir)
			{
				/* If it failed, oh well, go to the next one */
				continue;
			}

			/* Loop through each file in the file descriptor directory */
			while((fd_dir_info = readdir(fd_dir)) != NULL)
			{
				/* Create the full path to this file in the file descriptor directory: /proc/{pid}/fd/{fd} */
				memset((void *) &link_path, 0, FILENAME_MAX);
				snprintf((char *) &link_path, FILENAME_MAX, "%s/%s", fd_dir_name, fd_dir_info->d_name);

				/* Assume each file in the fd directory is a link file, and get the name of the file that is linked to */
				link_name = link_info((char *) &link_path);
				if(link_name)
				{
					/* Loop through each socket, checking to see if this link file points to a socket file descriptor
					 * wich has the same inode as the socket.
					 */
					for(i = 0; i<socket_info_size; i++)
					{
						/* Create the socket string as it will appear in the link file: socket:[{inode}] */
						memset((void *) &socket_name, 0, MAX_SOCKET_SIZE);
						snprintf((char *) &socket_name, MAX_SOCKET_SIZE-1, "socket:[%d]", socket_info[i]->inode);

						/* Check to see if this link file links to this socket descriptor */
						if(memcmp(link_name, (char *) &socket_name, strlen((char *) &socket_name)) == 0)
						{
							/* Create the full path to this process's path file: /proc/{pid}/exe */
							memset((void *) &exe_path, 0, FILENAME_MAX);
							snprintf((char *) &exe_path, FILENAME_MAX, "%s/%s/exe", PROC, proc_dir_info->d_name);

							/* Populate the owner's PID and full executable path */
							socket_info[i]->pid = atoi(proc_dir_info->d_name);
							socket_info[i]->path = link_info((char *) &exe_path);
							socket_info[i]->arguments = get_cmdline_args(socket_info[i]->pid);
							break;
						}
					}

					free(link_name);
				}
			}
			
			closedir(fd_dir);
		}
	}

end:
	if(proc_dir) closedir(proc_dir);
	return;
}

/* Prases and formats the command line arguments for each process */
char *get_cmdline_args(int pid)
{
	char cmdline_file[FILENAME_MAX] = { 0 };
	char *cmdline = NULL, *args = NULL;
	int i = 0, cmdline_size = 0, args_offset = 0;

	/* Format the path to the cmdline file */
	snprintf((char *) &cmdline_file, FILENAME_MAX, "%s/%d/%s", PROC, pid, CMDLINE);

	/* Read in the cmdline file */
	cmdline = read_file((char *) cmdline_file, &cmdline_size);
	
	/* Loop through the cmdline file contents, replacing null bytes with spaces.
	 * Loop while i < cmdline_size-1, as the last byte is a null byte and we want
	 * the resulting string to be properly null terminated.
	 */
	for(i=0; i<cmdline_size-1; i++)
	{
		if(cmdline[i] == 0x00)
		{
			/* The first null byte delimits the command from its arguments.
			 * We don't care about this null byte, so mark i+1 as the start
			 * of the arguments and continue to the next loop.
			 */
			if(!args_offset)
			{
				args_offset = i+1;
				continue;
			}

			/* Once a null byte is found, replace it with a space */
			memset(cmdline+i, ' ', 1);
		}
	}

	if(args_offset)
	{
		args = strdup(cmdline+args_offset);
	}

	if(cmdline) free(cmdline);
	return args;
}

/* Reads in a file of unknown length. Return buffer is not guarunteed to be null terminated */
char *read_file(char *file_name, int *file_size)
{
	char *buf = NULL, *tmp = NULL;
	int buf_size = 0, read_size = 0;
	int fd = 0;

	/* Open target file */
	fd = open(file_name, 0);
        if(!fd)
        {
        	perror("open");
        	goto end;
	}

	do
	{
		/* Allocate one byte at a time, since file size is not known */
		tmp = buf;
        	buf = realloc(buf, buf_size+READ_SIZE);
        	if(!buf)
        	{
			buf_size = 0;
			if(tmp) free(tmp);
        	        perror("realloc");
        	        goto end;
        	}
        	memset(buf+buf_size, 0, READ_SIZE);
	
		/* Read next byte from the file */
	        read_size = read(fd, buf+buf_size, READ_SIZE);
	        if(read_size == -1)
	        {
	                perror("read");
	                goto end;
	        }
		/* Increment buffer size counter for each successfully read byte */
		buf_size += READ_SIZE;
	} while(read_size > 0);

end:
	*file_size = buf_size;
	if(fd) close(fd);
	return buf;
}

/* Parses a socket string as read from the TCP and UDP socket files. 
 * String format is: <hex ip string >:<hex port string>.
 */
char *parse_socket_string(char *socket_string, uint16_t *port)
{
	char *ip_ptr = NULL, *port_ptr = NULL, *ip = NULL;
	char delim = COLON;

	/* Copy the original string so we don't clobber it */
	ip_ptr = strdup(socket_string);
	if(!ip_ptr)
	{
		goto end;
	}

	/* Find the colon delimiter; the port number is one byte after it */
	port_ptr = strchr(ip_ptr, delim);
	if(!port_ptr)
	{
		goto end;
	}
	memset(port_ptr,0,1);
	port_ptr++;

	/* Convert IP addresses */
	if(strlen(ip_ptr) == IPV6_HEX_STR_LEN)
	{
		ip = format_ipv6(ip_ptr);
	} else {
		ip = dotted_decimal((uint32_t) strtoul(ip_ptr, NULL, 16));
	}

	/* Convert port number */
	*port = (uint16_t) strtoul(port_ptr, NULL, 16);
end:
	if(ip_ptr) free(ip_ptr);
	return ip;
}

/* Converts a 32 bit little endian byte order value into a dotted decimal IP address string */
char *dotted_decimal(uint32_t ip)
{
	char *dotted_decimal = NULL;

	dotted_decimal = malloc(IPV4_STR_LEN+1);
	if(dotted_decimal)
	{
		/* Only byte-swap if the host system is big endian.
		 * ENDIANESS is defined in the Makefile.
		 */
		if(ENDIANESS == BIG)
		{
			ip = byteswap32(ip);
		}

		memset(dotted_decimal, 0, IPV4_STR_LEN+1);
		snprintf(dotted_decimal, IPV4_STR_LEN, "%d.%d.%d.%d", (ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), (ip >> 24));
	} else {
		perror("malloc");
	}

	return dotted_decimal;
}

/* Formats IPV6 addresses */
char *format_ipv6(char *raw_v6)
{
	char *ipv6 = NULL;
	int i = 0;

	/* Allocate enough room for the IPV6 address, plus colons, plus trailing NULL byte */
	ipv6 = malloc(IPV6_HEX_STR_LEN + 8);
	if(!ipv6)
	{
		perror("malloc");
		goto end;
	}
	memset(ipv6, 0, (IPV6_HEX_STR_LEN+8));

	/* Insert a colon every 4 characters */
	for(i=0; i<IPV6_HEX_STR_LEN; i+=4)
	{
		strncat(ipv6, raw_v6+i, 4);
		strncat(ipv6, ":", 1);
	}

	/* NULL out the trailing colon in the address */
	memset(ipv6+strlen(ipv6)-1,0,1);

end:
	return ipv6;
}

/* Get info about a link file */
char *link_info(char *link_file)
{
	char *buf = NULL;

	/* lstat is intentionally not called. Some link files in the /proc directory 
	 * are valid, but have a file size of zero.
	 */
	buf = malloc(FILENAME_MAX+1);
	if(buf)
	{
		memset(buf, 0, FILENAME_MAX+1);

		/* Read in the link file data */
		if(readlink(link_file, buf, FILENAME_MAX) == -1)
		{
			free(buf);
			buf = NULL;
		}
	} else {
		perror("malloc");
	}

	return buf;
}

/* Retrieves a column value from a given row */
char *get_column(char *row, int colnum)
{
        int row_size = strlen(row);
        int i = 0, j = 0, col_size = 0, count = 0;
        char *column = NULL;

        for(i=0; i<row_size; i++)
        {
                /* If this character is a white space, skip it */
                if(row[i] <= ' ')
                {
                        continue;
                }

                /* Loop through the string until a column delimiter is found.
                 * A column delimiter is any whitespace character.
                 */
                for(j=i; j < row_size; j++)
                {
                        /* If this character is a white space */
                        if(row[j] <= ' ')
                        {
                                /* We have reached the end of this column */
                                break;
                        }
                }

                /* Is this the column that we want? */
                if(count == colnum)
                {
                        /* Calculate the string length of this column and copy it into a buffer */
                        col_size = j - i;
                        column = malloc(col_size+1);
                        if(!column)
                        {
                                perror("Malloc failure");
                                break;
                        }
                        memset(column,0,col_size+1);
                        memcpy(column,row+i,col_size);
                        break;
                } else {
                        /* Set i == j to start searching for the next column at the end of this one.
                         * Increment count to track column count.
                         */
                        i = j;
                        count++;
                }
        }

        return column;
}

/* Byte-swapps a 32-bit value */
uint32_t byteswap32(uint32_t byte)
{
	uint32_t swap = 0;

	swap = (byte >> 24);
	swap += (((byte >> 16) & 0xFF) << 8);
	swap += (((byte >> 8 ) & 0xFF) << 16);
	swap += ((byte & 0xFF) << 24);

	return swap;
}

/* Determines if all characters in a string are numeric 0-9 or not */
int is_numeric_string(char *string)
{
	int i = 0, ok = 1, string_size = 0;
	
	string_size = strlen(string);

	for(i = 0; i<string_size; i++)
	{
		if(string[i] < '0' || string [i] > '9')
		{
			ok = 0;
			break;
		}
	}

	return ok;
}
