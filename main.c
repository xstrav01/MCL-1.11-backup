/**
 *
 *  Copyright (C) 2020 Michal Moravanský
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>

#include <getopt.h>

#include "crypto/include/system.h"
#include "crypto/src/setup.h"
#include "crypto/src/controllers/issuer.h"
#include "crypto/src/controllers/revocation-authority.h"
#include "crypto/src/controllers/verifier.h"

#include "service/lib/helpers/mem_helper.h"
#include "service/config/service-config.h"
#include "service/include/help.h"
#include "service/include/multos/apdu.h"
#include "service/lib/pcsc/reader.h"
#include "service/src/controllers/multos/user.h"
#include "service/src/controllers/remote/user.h"

static struct option long_options[] = {
        {"personalization",      no_argument,       0, 'p'},
        {"revocation-authority", no_argument,       0, 'r'},
        {"issuer",               no_argument,       0, 'i'},
        {"verifier",             no_argument,       0, 'v'},
        {"attributes",           required_argument, 0, 'a'},
        {"disclosed-attributes", required_argument, 0, 'd'},
        {"user-name",            required_argument, 0, 'n'},
        {"user-surname",         required_argument, 0, 's'},
        {"new-epoch",            optional_argument, 0, 'e'},
        {"revoke-user-c",        required_argument, 0, 'b'},
        {"revoke-user-id",       required_argument, 0, 'B'},
        {"update-bl",            required_argument, 0, 'u'},
        {"rewrite-bl",           required_argument, 0, 'w'},
        {"create-credentials",   required_argument, 0, 'c'},
        {"help",                 no_argument,       0, 'h'},
        {0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
    system_par_t sys_parameters = {1};

    revocation_authority_par_t ra_parameters = {0};
    revocation_authority_keys_t ra_keys = {0};
    revocation_authority_signature_t ra_signature = {0};

    issuer_par_t ie_parameters = {0};
    issuer_keys_t ie_keys = {0};
    issuer_signature_t ie_signature = {0};

    user_identifier_t ue_identifier = {0};
    user_attributes_t ue_attributes = {0};

    user_credential_t ue_credential = {0};
    user_pi_t ue_pi = {0};

    uint8_t nonce[NONCE_LENGTH] = {0};
    uint8_t epoch[EPOCH_LENGTH] = {0};

    bool first_usage = false;
    bool verifier_attributes_given = false;

    int opt;
    int no = NUMBER_OF_CREDENTIALS_TYPES - 1;
    int r;
    size_t it;

    char str_disclosed_attributes[MAX_INPUT] = {0};
    char str_ue_name[USER_NAME_MAX_LENGTH] = {0};
    char str_ue_surname[USER_NAME_MAX_LENGTH] = {0};
    char str_ue_identifier[2 * USER_MAX_ID_LENGTH + 1] = {0};
    char str_credentials[MAX_INPUT + 1] = {0};
    char str_epoch[2 * EPOCH_LENGTH + 1] = {0};

    char *ptr;

    // assign credentials
    ie_credentials_details_t eid = {"Name and surname", "Birthdate", "Nationality", "Permanent residence", "Sex"};
    eid.ue_attributes.num_attributes = 5;
    ie_credentials_details_t ticket = {"Name and surname", "Card number", "Type of ticket"};
    ticket.ue_attributes.num_attributes = 3;
    ie_credentials_details_t employee = {"Name and surname", "Employee id", "Employer", "Employee position"};
    employee.ue_attributes.num_attributes = 4;
    ie_credentials_details_t user_defined = {"attribute 1", "attribute 2", "attribute 3", "attribute 4", "attribute 5" , "attribute 6", "attribute 7", "attribute 8", "attribute 9"};

    ie_credentials_t cr[NUMBER_OF_CREDENTIALS_TYPES] = {eid, "eid", ticket, "ticket", employee, "employee card",  user_defined, "user defined"};

    char temp[PATH_MAX] = {0};
    char epoch_temp[PATH_MAX] = {0};
    FILE *user_list;
    FILE *ra_parameters_file;
    FILE *ra_public_parameters_file;
    FILE *ra_public_keys_file;
    FILE *ra_private_key_file;
    FILE *ra_rh_file;
    FILE *ra_revoked_rh_file;
    FILE *ra_blacklist_file;
    FILE *ie_private_keys_file;
    FILE *ie_issuer_attributes_file;
    FILE *ve_epoch_file;
    FILE *ve_blacklist_file;
    FILE *ve_log_requests_file;

    uint8_t pbRecvBuffer[MAX_APDU_LENGTH_T0] = {0};
    uint32_t dwRecvLength;
    reader_t reader;

# ifdef RKVAC_PROTOCOL_REMOTE
    int server_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    uint16_t port = SRV_PORT;
    char ipv4_address[16] = SRV_IPV4_ADDRESS;
# endif


    /// directories check
    // check if the default Issuer directory has already exist
    strcpy(temp, DEFAULT_DIRECTORY_FOR_ISSUER_DATA);
    if (!is_dir_exists(DEFAULT_DIRECTORY_FOR_ISSUER_DATA))
    {
        if (!recursive_mkdir(temp, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)))
        {
            return 1;
        }
    }

    // check if the default RA directory has already exist
    strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
    if (!is_dir_exists(DEFAULT_DIRECTORY_FOR_RA_DATA))
    {
        if (!recursive_mkdir(temp, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)))
        {
            return 1;
        }
    }

    // check if the default Verifier directory has already exist
    strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
    if (!is_dir_exists(DEFAULT_DIRECTORY_FOR_VERIFIER_DATA))
    {
        if (!recursive_mkdir(temp, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)))
        {
            return 1;
        }
    }

# ifdef RKVAC_PROTOCOL_REMOTE
    // assign IP, PORT
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(ipv4_address);
    server_address.sin_port = htons(port);
# endif

    if ((opt = getopt_long(argc, argv, "privh", long_options, NULL)) != -1)
    {
        switch (opt)
        {
            /// help
            case 'h':
            {
                fprintf(stderr, SERVICE_HELP, argv[0]);
                exit(0);
            }

            /// Card personalization part
            case 'p':
            {
                // load arguments
                while ((opt = getopt_long(argc, argv, "n:s:", long_options, NULL)) != -1)
                {
                    switch (opt)
                    {
                        // set user name to a variable
                        case 'n':
                        {
                            if (strlen(optarg) > USER_NAME_MAX_LENGTH)
                            {
                                fprintf(stderr, "Too long user name: %s\n", optarg);
                                exit(1);
                            }

                            strcpy(str_ue_name, optarg);
                            break;
                        }

                        // set user surname to a variable
                        case 's':
                        {
                            if (strlen(optarg) > USER_NAME_MAX_LENGTH)
                            {
                                fprintf(stderr, "Too long user surname: %s\n", optarg);
                                exit(1);
                            }

                            strcpy(str_ue_surname, optarg);
                            break;
                        }

                        default :
                        {
                            fprintf(stderr, "Press -h for help.\n");
                            return 1;
                        }
                    }
                }

                fprintf(stdout, TERMINAL_COLOR_CYN "[i] Card personalization started.\n" TERMINAL_COLOR_RESET);

                // check if the default Issuer directory has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_ISSUER_DATA);
                if (!is_dir_exists(DEFAULT_DIRECTORY_FOR_ISSUER_DATA))
                {
                    if (!recursive_mkdir(temp, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)))
                    {
                        return 1;
                    }
                }

                // check if the user list has already exist
                strcat(temp, IE_USER_LIST_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", IE_USER_LIST_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // create the new user list
                    fprintf(stdout, "file does not exist, creating %s\n", IE_USER_LIST_FILENAME);
                    user_list = fopen(temp, "w+");
                    if (user_list == NULL)
                    {
                        fprintf(stderr, "Error: cannot create %s!\n", IE_USER_LIST_FILENAME);
                        return 1;
                    }
                }
                else
                {
                    // open the user list in "r" mode
                    fprintf(stdout, "file exists, opening %s\n", IE_USER_LIST_FILENAME);
                    user_list = fopen(temp, "r");
                    if (user_list == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", IE_USER_LIST_FILENAME);
                        return 1;
                    }
                }

                // read user name from terminal
                if (strlen(str_ue_name) == 0 || strlen(str_ue_surname) == 0)
                {
                    fprintf(stdout, "[!] Enter user name for card personalization> ");
                    fflush(stdout);

                    if(fgets (str_ue_name, USER_NAME_MAX_LENGTH, stdin) == NULL)
                    {
                        fprintf(stderr, "Error: user name\n");
                        return 1;
                    }
                    // remove \n character from the end of string
                    str_ue_name[strlen(str_ue_name) - 1 ] = 0;

                    // read user surname
                    fprintf(stdout, "[!] Enter user surname for card personalization> ");
                    fflush(stdout);

                    if(fgets (str_ue_surname, USER_NAME_MAX_LENGTH, stdin) == NULL)
                    {
                        fprintf(stderr, "Error: user surname!\n");
                        return 1;
                    }
                    // remove \n character from the end of string
                    str_ue_surname[strlen(str_ue_surname) - 1 ] = 0;
                }

                // generate user identifier
                r = ie_generate_user_identifier(&ue_identifier, user_list);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot generate user identifier!\n");
                    return 1;
                }

                /// load the user identifier to the smart card
# ifndef RKVAC_PROTOCOL_REMOTE
                fprintf(stdout, "[+] Loading the user identifier to the smart card.\n");

                // open card connection
                r = sc_get_card_connection(&reader);
                if (r < 0)
                {
                    fprintf(stderr, "Error: %s\n", sc_get_error(r));
                    return 1;
                }
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: APDU_SCARD_SELECT_APPLICATION\n");
# endif

                dwRecvLength = sizeof(pbRecvBuffer);
                r = sc_transmit_data(reader, APDU_SCARD_SELECT_APPLICATION, sizeof(APDU_SCARD_SELECT_APPLICATION), pbRecvBuffer, &dwRecvLength, NULL);
                if (r < 0)
                {
                    fprintf(stderr, "Error: %s\n", sc_get_error(r));
                    return 1;
                }

                // set user identifier to the card
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_SET_USER_IDENTIFIER\n");
# endif
                r = ue_set_user_identifier(reader, &ue_identifier);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot set the user identifier to the card!\n");
                    return 1;
                }

                // close card connection
                sc_cleanup(reader);
# else
                /// load the user identifier to the remote card
                fprintf(stdout, "[+] Loading the user identifier to the remote card.\n");

                // open remote connection
                r = ntw_ipv4_server_open_connection(SOCK_STREAM, IPPROTO_TCP, &server_socket, &server_address);
                if (r < 0){
                    fprintf(stderr, "[!] Connection error!\n");
                    exit(EXIT_FAILURE);
                }

                // accept remote connection
                r = ntw_ipv4_server_accept_connection(server_socket, &client_socket, &client_address);
                if (r < 0){
                    fprintf(stderr, "[!] Connection error!\n");
                    exit(EXIT_FAILURE);
                }

                // select remote card app
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: APDU_SCARD_SELECT_APPLICATION\n");
# endif

                dwRecvLength = sizeof(pbRecvBuffer);
                r = ntw_transmit_data(client_socket, APDU_SCARD_SELECT_APPLICATION, sizeof(APDU_SCARD_SELECT_APPLICATION), pbRecvBuffer, &dwRecvLength, NULL);
                if (r != SCARD_S_SUCCESS)
                {
                    ntw_close_connection(client_socket);
                    fprintf(stderr, "Error: %s\n", sc_get_error(r));
                    exit(EXIT_FAILURE);
                }

                // set user identifier to the card
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_SET_USER_IDENTIFIER\n");
# endif
                r = ue_remote_set_user_identifier(client_socket, &ue_identifier);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot set the user identifier to the card!\n");
                    fprintf(stderr, "Error: %s\n", sc_get_error(r));
                    ntw_close_connection(client_socket);
                    return 1;
                }

                // close remote connection
                ntw_close_connection(client_socket);
# endif

                fprintf(stdout, "[+] Loading successful.\n");

                // open user list file in mode "a+"
                user_list = fopen(temp, "a+");

                // store user identifier to the user list
                fprintf(stdout, "[+] Writing to the %s ... ", IE_USER_LIST_FILENAME);
                fflush(stdout);
                r = ie_set_user_identifier(&ue_identifier, user_list, str_ue_name, str_ue_surname);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot set user identifier to the user list!\n");
                    return 1;
                }

                mem2hex(str_ue_identifier, ue_identifier.buffer, ue_identifier.buffer_length);
                fprintf(stdout, "User %s %s with id %s was successfully added to the user list.\n", str_ue_name, str_ue_surname, str_ue_identifier);
                fprintf(stdout, TERMINAL_COLOR_CYN "[i] Card personalization successful.\n" TERMINAL_COLOR_RESET);

                exit(0);
            }

            /// Revocation authority part
            case 'r':
            {
                fprintf(stdout, TERMINAL_COLOR_CYN "[i] Revocation authority part started.\n" TERMINAL_COLOR_RESET);

                // load arguments
                while ((opt = getopt_long(argc, argv, "e::b:B:", long_options, NULL)) != -1)
                {
                    switch (opt)
                    {
                        // new epoch
                        case 'e':
                        {

                            if (optarg)
                            {
                                if (strlen(optarg) > PATH_MAX)
                                {
                                    fprintf(stderr, "Too long filename %s\n", optarg);
                                    exit(1);
                                }

                                strcpy(epoch_temp, optarg);

                                // check if the epoch file has already exists
                                fprintf(stdout, "[+] Checking the %s ... ", epoch_temp);
                                fflush(stdout);
                                if (!is_file_exists(epoch_temp))
                                {
                                    // Error
                                    fprintf(stdout, "given file does not exist!\n");
                                    exit(1);
                                }
                                else
                                {
                                    // copy given epoch file to ra_epoch file
                                    fprintf(stdout, "file exists, copying it to %s (create or rewrite) ... ", DEFAULT_DIRECTORY_FOR_RA_DATA RA_EPOCH_FILENAME);
                                    fflush(stdout);
                                    r = copy_file(epoch_temp, DEFAULT_DIRECTORY_FOR_RA_DATA RA_EPOCH_FILENAME);
                                    if (r <= 0)
                                    {
                                        fprintf(stderr, "Error: cannot copy %s to %s\n", epoch_temp, DEFAULT_DIRECTORY_FOR_RA_DATA RA_EPOCH_FILENAME);
                                        exit(1);
                                    }
                                    fprintf(stdout, "done.\n");
                                }
                            }

                            strcpy(epoch_temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            strcat(epoch_temp, RA_EPOCH_FILENAME);


                            // check if the epoch file has already exists
                            fprintf(stdout, "[+] Checking the %s ... ", epoch_temp);
                            fflush(stdout);
                            if (!is_file_exists(epoch_temp))
                            {
                                fprintf(stderr, "file %s does not exist. Copy it from verifier!\n", epoch_temp);
                                exit(1);
                            }
                            else
                            {
                                // open the epoch file "r" mode
                                fprintf(stdout, "file exists, opening %s\n", epoch_temp);
                                ve_epoch_file = fopen(epoch_temp, "r");
                                if (ve_epoch_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", epoch_temp);
                                    return 1;
                                }
                            }

                            // load epoch
                            r = ra_get_epoch(epoch, sizeof(epoch), ve_epoch_file);
                            if (r < 0)
                            {
                                fprintf(stderr, "Error: cannot load epoch from file!\n");
                            }

                            // check if the RA parameters file has already exist
                            strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            strcat(temp, RA_PARAMETERS_FILENAME);
                            fprintf(stdout, "[+] Checking the %s ... ", RA_PARAMETERS_FILENAME);
                            fflush(stdout);
                            if (!is_file_exists(temp))
                            {
                                // error file does not exist
                                fprintf(stdout, "file does not exist!\n");
                                fprintf(stdout, "You have to setup Revocation authority at first! (-r)");
                                exit(1);
                            }
                            else
                            {
                                // open RA parameters file "r" mode
                                fprintf(stdout, "file exists, opening %s\n", RA_PARAMETERS_FILENAME);
                                ra_parameters_file = fopen(temp, "r");
                                if (ra_parameters_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", RA_PARAMETERS_FILENAME);
                                    return 1;
                                }
                            }

                            // check if the RA revocation handlers file has already exist
                            strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            strcat(temp, RA_REVOCATION_HANDLER_FILENAME);
                            fprintf(stdout, "[+] Checking the %s ... ", RA_REVOCATION_HANDLER_FILENAME);
                            fflush(stdout);
                            if (!is_file_exists(temp))
                            {
                                // error file does not exist
                                fprintf(stderr, "file does not exist!\n");
                                fprintf(stdout, "Revocation handler has not been issued to any user yet! Issue revocation handler at first. (-r)\n");
                                fclose(ra_parameters_file);
                                exit(1);
                            }
                            else
                            {
                                // open RA revocation handlers file "r" mode
                                fprintf(stdout, "file exists, opening %s\n", RA_REVOCATION_HANDLER_FILENAME);
                                ra_rh_file = fopen(temp, "r");
                                if (ra_rh_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", RA_REVOCATION_HANDLER_FILENAME);
                                    fclose(ra_parameters_file);
                                    exit(1);
                                }
                            }

                            // system - setup
                            if (sys_parameters.curve != 0)
                            {
                                r = sys_setup(&sys_parameters);
                                if (r < 0)
                                {
                                    fprintf(stderr, "Error: cannot initialize the system!\n");
                                    fclose(ra_parameters_file);
                                    fclose(ra_rh_file);
                                    exit(1);
                                }
                            }

                            // load RA parameters from file
                            r = ra_get_parameters(&ra_parameters, ra_parameters_file);
                            if (r < 0)
                            {
                                fprintf(stderr, "Error: cannot load RA parameters!\n");
                                fclose(ra_rh_file);
                                exit(1);
                            }

                            // generate pseudonyms for all m_rs
                            fprintf(stdout, "[+] Generate revoke RHS.\n");
                            r = ra_gen_pseudonyms_for_rhs(sys_parameters, ra_parameters, epoch, sizeof(epoch),
                                                          ra_rh_file, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            if (r < 0)
                            {
                                fprintf(stderr, "Error: cannot generate revoke RHS!\n");
                            }

                            // create revocation database
                            fprintf(stdout, "[+] Generate revocation database.\n");
                            r = ra_gen_rd_for_epoch(epoch, sizeof(epoch), DEFAULT_DIRECTORY_FOR_RA_DATA);
                            if (r < 0)
                            {
                                fprintf(stderr, "Error: cannot generate revocation database!\n");
                            }

                            // check if the revoked revocation handler file exist
                            strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            strcat(temp, RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                            fprintf(stdout, "[+] Checking the %s ... ", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                            fflush(stdout);
                            if (!is_file_exists(temp))
                            {
                                // create empty revoked revocation handler file
                                fprintf(stdout, "file does not exist, creating %s\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                ra_revoked_rh_file = fopen(temp, "w+");
                                if (ra_revoked_rh_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot create %s!\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                    return 1;
                                }
                            }
                            else
                            {
                                // open revoked revocation handler file "r" mode
                                fprintf(stdout, "file exists, opening %s\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                ra_revoked_rh_file = fopen(temp, "r");
                                if (ra_revoked_rh_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                    return 1;
                                }
                            }

                            // create BL for revoked users
                            fprintf(stdout, "[+] Generate blacklist for new epoch.\n");
                            r = ra_gen_bl_for_epoch(epoch, sizeof(epoch), ra_revoked_rh_file, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            if (r < 0)
                            {
                                fprintf(stderr, "Error: cannot generate blacklist for new epoch!\n");
                            }

                            mem2hex(str_epoch, epoch, sizeof(epoch));

                            fprintf(stdout, TERMINAL_COLOR_CYN "[i] Switch to the new epoch successful.\n" TERMINAL_COLOR_RESET);
                            fprintf(stdout, TERMINAL_COLOR_RED "[!] Move ra_BL_epoch_%s_C_for_verifier.dat file to the Verifier! "
                                            "(e.g. mv %sra_BL_epoch_%s_C_for_verifier.dat %sra_BL_epoch_%s_C_for_verifier.dat)\n" TERMINAL_COLOR_RESET,
                                    str_epoch, DEFAULT_DIRECTORY_FOR_RA_DATA, str_epoch, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA, str_epoch);
                            fprintf(stdout, TERMINAL_COLOR_RED "[!] Rewrite Verifier blacklist (-v -w %sra_BL_epoch_%s_C_for_verifier.dat)!\n" TERMINAL_COLOR_RESET,
                                    DEFAULT_DIRECTORY_FOR_VERIFIER_DATA, str_epoch);

                            exit(0);
                        }

                        // revoke user C
                        case 'b':
                        {
                            // system - setup
                            if (sys_parameters.curve != 0)
                            {
                                r = sys_setup(&sys_parameters);
                                if (r < 0)
                                {
                                    fprintf(stderr, "Error: cannot initialize the system!\n");
                                    exit(1);
                                }
                            }

                            // set epoch to string
                            strncpy(str_epoch, optarg, 2 * EPOCH_LENGTH);

                            // add pseudonyms to black list
                            fprintf(stdout, "[+] Adding revocation handler to the epoch black list.\n");
                            fflush(stdout);
                            r = ra_revokeC(&ra_signature.mr ,optarg, sizeof(epoch), DEFAULT_DIRECTORY_FOR_RA_DATA);
                            if (r < 0)
                            {
                                fprintf(stderr, "Error: cannot create epoch blacklist!\n");
                                return 1;
                            }

                            // check if the revoked revocation handler file exist
                            strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            strcat(temp, RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                            fprintf(stdout, "[+] Checking the %s ... ", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                            fflush(stdout);
                            if (!is_file_exists(temp))
                            {
                                // create new revoked revocation handler file
                                fprintf(stdout, "file does not exist, creating %s\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                ra_revoked_rh_file = fopen(temp, "w");
                                if (ra_revoked_rh_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot create %s!\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                    return 1;
                                }
                            }
                            else
                            {
                                // open revoked revocation handler file "a" mode
                                fprintf(stdout, "file exists, opening %s\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                ra_revoked_rh_file = fopen(temp, "a");
                                if (ra_revoked_rh_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                    return 1;
                                }
                            }

                            // update list of revoked users
                            fprintf(stdout, "[+] Updating list of revoked users.\n");
                            fflush(stdout);
                            r = ra_revoke_user_rh(ra_signature.mr, ra_revoked_rh_file);
                            if (r < 0)
                            {
                                fprintf(stderr, "Error: cannot update list of revoked users!\n");
                                return 1;
                            }

                            fprintf(stdout, TERMINAL_COLOR_CYN "[i] User revoke for epoch successful.\n" TERMINAL_COLOR_RESET);
                            fprintf(stdout, TERMINAL_COLOR_RED "[!] Move ra_BL_epoch_%s_C_for_verifier.dat file to the Verifier! "
                                                               "(e.g. mv %sra_BL_epoch_%s_C_for_verifier.dat %sra_BL_epoch_%s_C_for_verifier.dat)\n" TERMINAL_COLOR_RESET,
                                                               str_epoch, DEFAULT_DIRECTORY_FOR_RA_DATA, str_epoch, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA, str_epoch);
                            fprintf(stdout, TERMINAL_COLOR_RED "[!] Update Verifier blacklist (-v -u %sra_BL_epoch_%s_C_for_verifier.dat)!\n" TERMINAL_COLOR_RESET,
                                                                DEFAULT_DIRECTORY_FOR_VERIFIER_DATA, str_epoch);

                            exit(0);
                        }

                        // revoke user id
                        case 'B':
                        {
                            // system - setup
                            if (sys_parameters.curve != 0)
                            {
                                r = sys_setup(&sys_parameters);
                                if (r < 0)
                                {
                                    fprintf(stderr, "Error: cannot initialize the system!\n");
                                    exit(1);
                                }
                            }

                            // set epoch to string
                            strncpy(str_epoch, optarg, 2 * EPOCH_LENGTH);

                            /* current epoch load
                            strcpy(epoch_temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            strcat(epoch_temp, RA_EPOCH_FILENAME);


                            // check if the epoch file has already exists
                            fprintf(stdout, "[+] Checking the %s ... ", epoch_temp);
                            fflush(stdout);
                            if (!is_file_exists(epoch_temp))
                            {
                                fprintf(stderr, "file %s does not exist. Copy it from verifier!\n", epoch_temp);
                                exit(1);
                            }
                            else
                            {
                                // open the epoch file "r" mode
                                fprintf(stdout, "file exists, opening %s\n", epoch_temp);
                                ve_epoch_file = fopen(epoch_temp, "r");
                                if (ve_epoch_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", epoch_temp);
                                    return 1;
                                }
                            }

                            // load epoch
                            r = ra_get_epoch(epoch, sizeof(epoch), ve_epoch_file);
                            if (r < 0)
                            {
                                fprintf(stderr, "Error: cannot load epoch from file!\n");
                            }
                            */

                            // check if the RA revocation handlers file has already exist
                            strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            strcat(temp, RA_REVOCATION_HANDLER_FILENAME);
                            fprintf(stdout, "[+] Checking the %s ... ", RA_REVOCATION_HANDLER_FILENAME);
                            fflush(stdout);
                            if (!is_file_exists(temp))
                            {
                                // Error
                                fprintf(stdout, "file does not exist!\n");

                                exit(1);
                            }
                            else
                            {
                                // open RA revocation handlers file "r" mode
                                fprintf(stdout, "file exists, opening %s\n", RA_REVOCATION_HANDLER_FILENAME);
                                ra_rh_file = fopen(temp, "r");
                                if (ra_rh_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", RA_REVOCATION_HANDLER_FILENAME);
                                    return 1;
                                }
                            }

                            // add id to black list
                            fprintf(stdout, "[+] Adding user identifier to the epoch black list.\n");
                            fflush(stdout);

                            r = ra_revokeID(&ra_signature.mr ,optarg, sizeof(epoch), ra_rh_file, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            if (r < 0)
                            {
                                fprintf(stderr, "Error: cannot create epoch blacklist!\n");
                                return 1;
                            }

                            // check if the revoked revocation handler file exist
                            strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                            strcat(temp, RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                            fprintf(stdout, "[+] Checking the %s ... ", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                            fflush(stdout);
                            if (!is_file_exists(temp))
                            {
                                // create new revoked revocation handler file
                                fprintf(stdout, "file does not exist, creating %s\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                ra_revoked_rh_file = fopen(temp, "a");
                                if (ra_revoked_rh_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot create %s!\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                    return 1;
                                }
                            }
                            else
                            {
                                // open revoked revocation handler file "a" mode
                                fprintf(stdout, "file exists, opening %s\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                ra_revoked_rh_file = fopen(temp, "a");
                                if (ra_revoked_rh_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", RA_REVOKED_REVOCATION_HANDLER_FILENAME);
                                    return 1;
                                }
                            }

                            // update list of revoked users
                            fprintf(stdout, "[+] Updating list of revoked users.\n");
                            fflush(stdout);
                            r = ra_revoke_user_rh(ra_signature.mr, ra_revoked_rh_file);
                            if (r < 0)
                            {
                                fprintf(stderr, "Error: cannot update list of revoked users!\n");
                                return 1;
                            }

                            fprintf(stdout, TERMINAL_COLOR_CYN "[i] User revoke for epoch successful.\n" TERMINAL_COLOR_RESET);
                            fprintf(stdout, TERMINAL_COLOR_RED "[!] Move ra_BL_epoch_%s_C_for_verifier.dat file to the Verifier! "
                                            "(e.g. mv %sra_BL_epoch_%s_C_for_verifier.dat %sra_BL_epoch_%s_C_for_verifier.dat)\n" TERMINAL_COLOR_RESET,
                                    str_epoch, DEFAULT_DIRECTORY_FOR_RA_DATA, str_epoch, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA, str_epoch);
                            fprintf(stdout, TERMINAL_COLOR_RED "[!] Update Verifier blacklist (-v -u %sra_BL_epoch_%s_C_for_verifier.dat)!\n" TERMINAL_COLOR_RESET,
                                    DEFAULT_DIRECTORY_FOR_VERIFIER_DATA, str_epoch);

                            exit(0);
                        }

                        default :
                        {
                            fprintf(stderr, "Press -h for help.\n");
                            exit(1);
                        }
                    }
                }

                // check if the default RA directory has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                if (!is_dir_exists(DEFAULT_DIRECTORY_FOR_RA_DATA))
                {
                    if (!recursive_mkdir(temp, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)))
                    {
                        return 1;
                    }
                }

                // system - setup
                if (sys_parameters.curve != 0)
                {
                    r = sys_setup(&sys_parameters);
                    if (r < 0)
                    {
                        fprintf(stderr, "Error: cannot initialize the system!\n");
                        return 1;
                    }
                }

                // check if the RA parameters file has already exist
                strcat(temp, RA_PARAMETERS_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", RA_PARAMETERS_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // create new RA parameters file
                    first_usage = true;
                    fprintf(stdout, "file does not exist, creating %s\n", RA_PARAMETERS_FILENAME);
                    ra_parameters_file = fopen(temp, "w+");
                    if (ra_parameters_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot create %s!\n", RA_PARAMETERS_FILENAME);
                        return 1;
                    }
                }
                else
                {
                    // open RA parameters file "r+" mode
                    fprintf(stdout, "file exists, opening %s\n", RA_PARAMETERS_FILENAME);
                    ra_parameters_file = fopen(temp, "r+");
                    if (ra_parameters_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", RA_PARAMETERS_FILENAME);
                        return 1;
                    }
                }

                // check if the RA public parameters file has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                strcat(temp, RA_PUBLIC_PARAMETERS_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", RA_PUBLIC_PARAMETERS_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // create new RA public parameters file
                    fprintf(stdout, "file does not exist, creating %s\n", RA_PUBLIC_PARAMETERS_FILENAME);
                    ra_public_parameters_file = fopen(temp, "w+");
                    if (ra_public_parameters_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot create %s!\n", RA_PUBLIC_PARAMETERS_FILENAME);
                        fclose(ra_parameters_file);
                        return 1;
                    }
                }
                else
                {
                    // open RA public parameters file "r+" mode
                    fprintf(stdout, "file exists, opening %s\n", RA_PUBLIC_PARAMETERS_FILENAME);
                    ra_public_parameters_file = fopen(temp, "r+");
                    if (ra_public_parameters_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", RA_PUBLIC_PARAMETERS_FILENAME);
                        fclose(ra_parameters_file);
                        return 1;
                    }
                }

                // check if the RA public key file has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                strcat(temp, RA_PUBLIC_KEY_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", RA_PUBLIC_KEY_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // create new RA public key file
                    fprintf(stdout, "file does not exist, creating %s\n", RA_PUBLIC_KEY_FILENAME);
                    ra_public_keys_file = fopen(temp, "w+");
                    if (ra_public_keys_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot create %s!\n", RA_PUBLIC_KEY_FILENAME);
                        fclose(ra_parameters_file);
                        fclose(ra_public_parameters_file);
                        return 1;
                    }
                }
                else
                {
                    // open RA public key file "r+" mode
                    fprintf(stdout, "file exists, opening %s\n", RA_PUBLIC_KEY_FILENAME);
                    ra_public_keys_file = fopen(temp, "r+");
                    if (ra_public_keys_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", RA_PUBLIC_KEY_FILENAME);
                        fclose(ra_parameters_file);
                        fclose(ra_public_parameters_file);
                        return 1;
                    }
                }

                // check if the RA private key file has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                strcat(temp, RA_PRIVATE_KEY_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", RA_PRIVATE_KEY_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // create new RA public key file
                    fprintf(stdout, "file does not exist, creating %s\n", RA_PRIVATE_KEY_FILENAME);
                    ra_private_key_file = fopen(temp, "w+");
                    if (ra_private_key_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot create %s!\n", RA_PRIVATE_KEY_FILENAME);
                        fclose(ra_parameters_file);
                        fclose(ra_public_parameters_file);
                        fclose(ra_public_keys_file);
                        return 1;
                    }
                }
                else
                {
                    // open RA private key file "r+" mode
                    fprintf(stdout, "file exists, opening %s\n", RA_PRIVATE_KEY_FILENAME);
                    ra_private_key_file = fopen(temp, "r+");
                    if (ra_private_key_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", RA_PRIVATE_KEY_FILENAME);
                        fclose(ra_parameters_file);
                        fclose(ra_public_parameters_file);
                        fclose(ra_public_keys_file);
                        return 1;
                    }
                }

                // revocation authority - setup
                r = ra_setup(sys_parameters, &ra_parameters, &ra_keys, ra_parameters_file, ra_public_parameters_file, ra_public_keys_file, ra_private_key_file);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot initialize the revocation authority!\n");
                    return 1;
                }


# ifndef RKVAC_PROTOCOL_REMOTE
                /// Get user identifier from card
                fprintf(stdout, "[+] Get the user identifier from smart card.\n");

                // open card connection
                r = sc_get_card_connection(&reader);
                if (r < 0) {
                    fprintf(stderr, "Error: %s\n", sc_get_error(r));
                    return 1;
                }

# ifndef NDEBUG
                fprintf(stdout, "[-] Command: APDU_SCARD_SELECT_APPLICATION\n");
# endif

                dwRecvLength = sizeof(pbRecvBuffer);
                r = sc_transmit_data(reader, APDU_SCARD_SELECT_APPLICATION, sizeof(APDU_SCARD_SELECT_APPLICATION),
                                     pbRecvBuffer, &dwRecvLength, NULL);
                if (r < 0) {
                    return 1;
                }

                // user - get user identifier
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_GET_USER_IDENTIFIER\n");
# endif
                r = ue_get_user_identifier(reader, &ue_identifier);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot get the user identifier!\n");
                    return 1;
                }
# else
                /// Get user identifier from remote card
                fprintf(stdout, "[+] Get the user identifier from a remote card.\n");

                // open remote connection
                r = ntw_ipv4_server_open_connection(SOCK_STREAM, IPPROTO_TCP, &server_socket, &server_address);
                if (r < 0){
                    fprintf(stderr, "[!] Connection error!\n");
                    exit(EXIT_FAILURE);
                }

                // accept remote connection
                r = ntw_ipv4_server_accept_connection(server_socket, &client_socket, &client_address);
                if (r < 0){
                    fprintf(stderr, "[!] Connection error!\n");
                    exit(EXIT_FAILURE);
                }

# ifndef NDEBUG
                fprintf(stdout, "[-] Command: APDU_SCARD_SELECT_APPLICATION\n");
# endif

                dwRecvLength = sizeof(pbRecvBuffer);
                r = ntw_transmit_data(client_socket, APDU_SCARD_SELECT_APPLICATION, sizeof(APDU_SCARD_SELECT_APPLICATION),
                                      pbRecvBuffer, &dwRecvLength, NULL);
                if (r != SCARD_S_SUCCESS)
                {
                    ntw_close_connection(client_socket);
                    exit(EXIT_FAILURE);
                }

                // user - get user identifier
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_GET_USER_IDENTIFIER\n");
# endif
                r = ue_remote_get_user_identifier(client_socket, &ue_identifier);
                if (r != SCARD_S_SUCCESS)
                {
                    fprintf(stderr, "Error: cannot get the user identifier!\n");
                    exit(EXIT_FAILURE);
                }
# endif
                // check if the RA revocation handlers file has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                strcat(temp, RA_REVOCATION_HANDLER_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", RA_REVOCATION_HANDLER_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // create new RA revocation handlers file
                    fprintf(stdout, "file does not exist, creating %s\n", RA_REVOCATION_HANDLER_FILENAME);
                    ra_rh_file = fopen(temp, "w+");
                    if (ra_rh_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot create %s!\n", RA_REVOCATION_HANDLER_FILENAME);
# ifndef RKVAC_PROTOCOL_REMOTE
                        sc_cleanup(reader);
# else
                        ntw_close_connection(client_socket);
# endif
                        return 1;
                    }
                }
                else
                {
                    // open RA revocation handlers file "r" mode
                    fprintf(stdout, "file exists, opening %s\n", RA_REVOCATION_HANDLER_FILENAME);
                    ra_rh_file = fopen(temp, "r");
                    if (ra_rh_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", RA_REVOCATION_HANDLER_FILENAME);
# ifndef RKVAC_PROTOCOL_REMOTE
                        sc_cleanup(reader);
# else
                        ntw_close_connection(client_socket);
# endif
                        return 1;
                    }
                }

                // revocation authority - mr
                r = ra_gen_rev_handler(&ra_signature.mr, ra_rh_file);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot generate revocation handler!\n");
# ifndef RKVAC_PROTOCOL_REMOTE
                    sc_cleanup(reader);
# else
                    ntw_close_connection(client_socket);
# endif
                    return 1;
                }

                // revocation authority - mac
                r = ra_mac(sys_parameters, ra_keys.private_key, ue_identifier, &ra_signature);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot compute the revocation authority MAC!\n");
# ifndef RKVAC_PROTOCOL_REMOTE
                    sc_cleanup(reader);
# else
                    ntw_close_connection(client_socket);
# endif
                    return 1;
                }

# ifndef RKVAC_PROTOCOL_REMOTE
                /// user - set revocation authority data
                fprintf(stdout, "[+] Set the revocation authority data to smart card.\n");

# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_SET_REVOCATION_AUTHORITY_DATA\n");
# endif
                r = ue_set_revocation_authority_data(reader, ra_parameters, ra_signature);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot set the revocation authority data!\n");
                    return 1;
                }

                // close card connection
                sc_cleanup(reader);
# else
                /// user - set revocation authority data to the remote card
                fprintf(stdout, "[+] Set the revocation authority data to remote card.\n");

# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_SET_REVOCATION_AUTHORITY_DATA\n");
# endif

                r = ue_remote_set_revocation_authority_data(client_socket, ra_parameters, ra_signature);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot set the revocation authority data!\n");
                    ntw_close_connection(client_socket);
                    exit(EXIT_FAILURE);
                }

                // close remote connection
                ntw_close_connection(client_socket);
# endif

                // open ra_rh file
                ra_rh_file = fopen(temp, "a+");

                // set user identifier and revocation handler to the revocation handler list
                fprintf(stdout, "[+] Set the user identifier and revocation handler to the revocation handlers list.\n");
                r = ra_set_rev_handler(ue_identifier, ra_signature.mr, ra_rh_file);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot set the revocation handler to the revocation handler list!\n");
                    return 1;
                }

                // current epoch load
                strcpy(epoch_temp, DEFAULT_DIRECTORY_FOR_RA_DATA);
                strcat(epoch_temp, RA_EPOCH_FILENAME);

                // check if the epoch file has already exists
                fprintf(stdout, "[+] Checking the %s ... ", epoch_temp);
                fflush(stdout);
                if (!is_file_exists(epoch_temp))
                {
                    fprintf(stderr, "file does not exist.\n");
                }
                else
                {
                    // open the epoch file "r" mode
                    fprintf(stdout, "file exists, opening %s\n", epoch_temp);
                    ve_epoch_file = fopen(epoch_temp, "r");
                    if (ve_epoch_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", epoch_temp);
                        return 1;
                    }

                    // load current epoch
                    r = ra_get_epoch(epoch, sizeof(epoch), ve_epoch_file);
                    if (r < 0)
                    {
                        fprintf(stderr, "Error: cannot load epoch from file!\n");
                    }

                    // generate pseudonyms for current m_r
                    fprintf(stdout, "[+] Generate pseudonyms for current revocation handler.\n");
                    r = ra_gen_pseudonyms_for_rh(sys_parameters, ra_parameters,epoch, sizeof(epoch), ra_signature.mr, DEFAULT_DIRECTORY_FOR_RA_DATA);
                    if (r < 0)
                    {
                        fprintf(stderr, "Error: cannot update revoke RHS!\n");
                        exit(1);
                    }

                    // update rd for for current m_r
                    fprintf(stdout, "[+] Update RD for current revocation handler.\n");
                    r = ra_update_rd_for_epoch(epoch, sizeof(epoch), ra_signature.mr, DEFAULT_DIRECTORY_FOR_RA_DATA);
                    if (r < 0)
                    {
                        fprintf(stderr, "Error: cannot update RD!\n");
                        exit(1);
                    }
                }

                fprintf(stdout, TERMINAL_COLOR_CYN "[i] Revocation authority part complete.\n" TERMINAL_COLOR_RESET);
                if (first_usage)
                {
                    fprintf(stdout, "[i] In case of first usage copy %s file to the Issuer! (i.g. cp %s %s)\n",
                            RA_PUBLIC_KEY_FILENAME, DEFAULT_DIRECTORY_FOR_RA_DATA RA_PUBLIC_KEY_FILENAME, DEFAULT_DIRECTORY_FOR_ISSUER_DATA RA_PUBLIC_KEY_FILENAME);
                    fprintf(stdout, "[i] In case of first usage copy %s and %s files to the Verifier! (e.g. cp %s %s)\n",
                            RA_PUBLIC_KEY_FILENAME, RA_PUBLIC_PARAMETERS_FILENAME, DEFAULT_DIRECTORY_FOR_RA_DATA RA_PUBLIC_PARAMETERS_FILENAME,
                            DEFAULT_DIRECTORY_FOR_VERIFIER_DATA RA_PUBLIC_PARAMETERS_FILENAME);
                }

                exit(0);
            }

            /// Issuer part
            case 'i':
            {
                fprintf(stdout, TERMINAL_COLOR_CYN "[i] Issuer part started.\n" TERMINAL_COLOR_RESET);
                fflush(stdout);

                // system - setup
                if (sys_parameters.curve != 0)
                {
                    r = sys_setup(&sys_parameters);
                    if (r < 0)
                    {
                        fprintf(stderr, "Error: cannot initialize the system!\n");
                        return 1;
                    }
                }

                // check if the default Issuer directory has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_ISSUER_DATA);
                if (!is_dir_exists(DEFAULT_DIRECTORY_FOR_ISSUER_DATA))
                {
                    if (!recursive_mkdir(temp, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)))
                    {
                        return 1;
                    }
                }

                // load arguments
                opt = getopt_long(argc, argv, "a:", long_options, NULL);

                // check if the file name was passed
                switch (opt)
                {
                    // default user attributes filename
                    case -1:
                    {
                        fprintf(stderr, "Error: option -a is obligatory for Issuer. Please run Issuer with option -a (e.g. -i -a %s)\n", IE_USER_ATTRIBUTES_FILENAME);
                        exit(1);
                    }

                    // defined attributes filename
                    case 'a':
                    {

                        if (strlen(optarg) > PATH_MAX)
                        {
                            fprintf(stderr, "Too long filename %s\n", optarg);
                            exit(1);
                        }

                        if (!is_file_exists(optarg))
                        {
                            ptr = strrchr(optarg, '/');
                            if (ptr)
                            {
                                it = ptr - optarg + 1;
                                memcpy(temp, optarg, it);
                                temp[it] = '\0';
                                if (!is_dir_exists(temp))
                                {
                                    fprintf(stderr, "Error: given directory %s does not exist!\n", temp);
                                    exit(1);
                                }
                                else
                                {
                                    strcpy(temp, optarg);
                                }
                            }
                            else
                            {
                                strcpy(temp, DEFAULT_DIRECTORY_FOR_ISSUER_DATA);
                                strcat(temp, optarg);
                            }
                        }
                        else
                        {
                            strcpy(temp, optarg);
                        }

                        break;
                    }

                    default :
                    {
                        fprintf(stderr, "Press -h for help.\n");
                        exit(1);
                    }
                }

                // check if the user attributes file has already exist
                fprintf(stdout, "[+] Checking the %s ... ", temp);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    fprintf(stdout, "file does not exist, creating %s\n", temp);

                    // Choose type of credentials
                    fprintf(stdout, "[+] Choose type of credentials (e.g. 1):\n");
                    fflush(stdout);

                    for (it = 0; it < NUMBER_OF_CREDENTIALS_TYPES; it++)
                    {
                        fprintf(stdout, " [%d] %s\n", it + 1, cr[it].credentials_type_name);
                    }

                    fprintf(stdout, "> ");
                    fflush(stdout);

                    // read number from stdin
                    while (true)
                    {
                        fgets (str_credentials, sizeof(str_credentials), stdin);
                        no = strtol(str_credentials, NULL, 10);
                        if (no > 0 && no <= NUMBER_OF_CREDENTIALS_TYPES)
                        {
                            break;
                        }

                        fprintf(stderr, "Error: the number has to be 1..%d, you set %d\n", NUMBER_OF_CREDENTIALS_TYPES, no);
                        fprintf(stdout, "> ");
                        fflush(stdout);
                    }
                    no--;

                    if (no == NUMBER_OF_CREDENTIALS_TYPES - 1)
                    {
                        fprintf(stdout, "  [+] Set number of user attributes (1..%d)> ", USER_MAX_NUM_ATTRIBUTES);
                        fflush(stdout);

                        // read number from stdin
                        while (true)
                        {
                            // read number from stdin
                            fgets (str_credentials, sizeof(str_credentials), stdin);
                            cr[no].ie_credentials_details.ue_attributes.num_attributes = strtol(str_credentials, NULL, 10);
                            if (cr[no].ie_credentials_details.ue_attributes.num_attributes > 0 && cr[no].ie_credentials_details.ue_attributes.num_attributes <= USER_MAX_NUM_ATTRIBUTES)
                            {
                                break;
                            }

                            fprintf(stderr, "Error: the number has to be 1..%d, you set %d\n", USER_MAX_NUM_ATTRIBUTES, cr[no].ie_credentials_details.ue_attributes.num_attributes);
                        }
                    }

                    fprintf(stdout, "[+] Enter %s credentials\n", cr[no].credentials_type_name);
                    fflush(stdout);

                    // issuer - generate user attributes
                    for (it = 0; it < cr[no].ie_credentials_details.ue_attributes.num_attributes; it++)
                    {
                        fprintf(stdout, " [%d] %s> ", it + 1, cr[no].ie_credentials_details.ie_credentials_name[it].name);
                        fflush(stdout);

                        if(fgets (str_credentials, MAX_INPUT, stdin) == NULL)
                        {
                            fprintf(stderr, "Error: %s\n", cr[no].ie_credentials_details.ie_credentials_name[it].name);
                            return 1;
                        }

                        // remove \n character from the end of string
                        str_credentials[strlen(str_credentials) - 1 ] = 0;

                        if (strlen(str_credentials) == 0)
                        {
                            strcat(str_credentials, CREDENTIALS_DEFAULT_VALUE);
                        }

                        // set string value
                        strcpy(cr[no].ie_credentials_details.ue_attributes.ie_attributes_str_value[it].str_value, str_credentials);

                        // generate user attributes
                        r = ie_generate_user_attribute(cr[no].ie_credentials_details.ue_attributes.ie_attributes_str_value[it], ue_attributes.attributes[it].value);
                        if (r != 0)
                        {
                            fprintf(stderr, "Error: generate user attribute failed!");
                            return 1;
                        }

                    }

                    // create new user attributes file
                    ie_issuer_attributes_file = fopen(temp, "w");
                    if (ie_issuer_attributes_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot create %s!\n", IE_USER_ATTRIBUTES_FILENAME);
                        return 1;
                    }

                    // issuer - set user attributes
                    r = ie_set_user_attributes(cr[no], ue_attributes, ie_issuer_attributes_file);
                    if (r < 0)
                    {
                        fprintf(stderr, "Error: cannot set the user attributes to file!\n");
                        return 1;
                    }

                    ue_attributes.num_attributes = cr[no].ie_credentials_details.ue_attributes.num_attributes;
                }
                else
                {
                    // open user attributes file "r" mode
                    fprintf(stdout, "file exists, opening %s\n", temp);
                    ie_issuer_attributes_file = fopen(temp, "r");
                    if (ie_issuer_attributes_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", temp);
                        return 1;
                    }

                    // issuer - load user attributes
                    fprintf(stdout, "[+] Reading user attributes from file.\n");
                    r = ie_get_user_attributes(&cr[no], &ue_attributes, ie_issuer_attributes_file);
                    if (r < 0)
                    {
                        fprintf(stderr, "Error: cannot load the user attributes!\n");
                        return 1;
                    }
                }
                ie_parameters.num_attributes = cr[no].ie_credentials_details.ue_attributes.num_attributes;

                // check if the RA public key file has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_ISSUER_DATA);
                strcat(temp, RA_PUBLIC_KEY_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", RA_PUBLIC_KEY_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // error file does not exist
                    fprintf(stdout, "file does not exist!\n");
                    fprintf(stdout, "You have to copy %s file from RA!\n", RA_PUBLIC_KEY_FILENAME);
                    exit(1);
                }
                else
                {
                    // open RA public key file "r" mode
                    fprintf(stdout, "file exists, opening %s\n", RA_PUBLIC_KEY_FILENAME);
                    ra_public_keys_file = fopen(temp, "r");
                    if (ra_public_keys_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", RA_PUBLIC_KEY_FILENAME);
                        exit(1);
                    }
                }

                // check if the ie_private_keys file has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_ISSUER_DATA);
                strcat(temp, IE_PRIVATE_KEYS_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", IE_PRIVATE_KEYS_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // create new ie_private_keys file
                    first_usage = true;
                    fprintf(stdout, "file does not exist, creating %s\n", IE_PRIVATE_KEYS_FILENAME);
                    ie_private_keys_file = fopen(temp, "w");
                    if (ie_private_keys_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot create %s!\n", IE_PRIVATE_KEYS_FILENAME);
                        fclose(ra_public_keys_file);
                        return 1;
                    }
                }
                else
                {
                    // open ie_private_keys file in "r+" mode
                    fprintf(stdout, "file exists, opening %s\n", IE_PRIVATE_KEYS_FILENAME);
                    ie_private_keys_file = fopen(temp, "r+");
                    if (ie_private_keys_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", IE_PRIVATE_KEYS_FILENAME);
                        fclose(ra_public_keys_file);
                        return 1;
                    }
                }

                // issuer - setup
                fprintf(stdout, "[+] Issuer setup ... \n");
                fflush(stdout);
                r = ie_setup(ie_parameters, &ie_keys, &ra_keys.public_key, ie_private_keys_file, ra_public_keys_file);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot initialize the issuer!\n");
                    return 1;
                }

# ifndef RKVAC_PROTOCOL_REMOTE
                /// Get user identifier attributes (ID, Sigma_RA) from smart card.
                // card connection
                r = sc_get_card_connection(&reader);
                if (r < 0)
                {
                    fprintf(stderr, "Error: %s\n", sc_get_error(r));
                    return 1;
                }

# ifndef NDEBUG
                fprintf(stdout, "[-] Command: APDU_SCARD_SELECT_APPLICATION\n");
# endif

                dwRecvLength = sizeof(pbRecvBuffer);
                r = sc_transmit_data(reader, APDU_SCARD_SELECT_APPLICATION, sizeof(APDU_SCARD_SELECT_APPLICATION), pbRecvBuffer, &dwRecvLength, NULL);
                if (r < 0)
                {
                    fprintf(stderr, "Error: %s\n", sc_get_error(r));
                    return 1;
                }

                fprintf(stdout, "[+] Get user identifier attributes (ID, Sigma_RA) from smart card.\n");
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_GET_USER_IDENTIFIER_ATTRIBUTES\n");
# endif
                // user - get user attributes and identifier
                r = ue_get_user_attributes_identifier(reader, NULL, &ue_identifier, &ra_signature);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot get the user information!\n");
                    return 1;
                }
# else
                /// Get user identifier attributes (ID, Sigma_RA) from remote card.
                // open remote connection
                r = ntw_ipv4_server_open_connection(SOCK_STREAM, IPPROTO_TCP, &server_socket, &server_address);
                if (r < 0){
                    fprintf(stderr, "[!] Connection error!\n");
                    exit(EXIT_FAILURE);
                }

                // accept remote connection
                r = ntw_ipv4_server_accept_connection(server_socket, &client_socket, &client_address);
                if (r < 0){
                    fprintf(stderr, "[!] Connection error!\n");
                    exit(EXIT_FAILURE);
                }

# ifndef NDEBUG
                fprintf(stdout, "[-] Command: APDU_SCARD_SELECT_APPLICATION\n");
# endif

                dwRecvLength = sizeof(pbRecvBuffer);
                r = ntw_transmit_data(client_socket, APDU_SCARD_SELECT_APPLICATION, sizeof(APDU_SCARD_SELECT_APPLICATION),
                                      pbRecvBuffer, &dwRecvLength, NULL);
                if (r != SCARD_S_SUCCESS)
                {
                    ntw_close_connection(client_socket);
                    exit(EXIT_FAILURE);
                }

                fprintf(stdout, "[+] Get user identifier attributes (ID, Sigma_RA) from remote card.\n");
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_GET_USER_IDENTIFIER_ATTRIBUTES\n");
# endif
                // user - get user attributes and identifier
                r = ue_remote_get_user_attributes_identifier(client_socket, NULL, &ue_identifier, &ra_signature);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot get the user information!\n");
                    exit(EXIT_FAILURE);
                }
# endif
                // check if the user list has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_ISSUER_DATA);
                strcat(temp, IE_USER_LIST_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", IE_USER_LIST_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // error
                    fprintf(stdout, "file does not exist, cannot get the cardholder information!\n");
# ifndef RKVAC_PROTOCOL_REMOTE
                    sc_cleanup(reader);
# else
                    ntw_close_connection(client_socket);
# endif
                    exit(1);
                }
                else
                {
                    // open the user list in "r" mode
                    fprintf(stdout, "file exists, opening %s\n", IE_USER_LIST_FILENAME);
                    user_list = fopen(temp, "r");
                    if (user_list == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", IE_USER_LIST_FILENAME);
# ifndef RKVAC_PROTOCOL_REMOTE
                        sc_cleanup(reader);
# else
                        ntw_close_connection(client_socket);
# endif
                        exit(1);
                    }
                }

                // verify the cardholder
                fprintf(stdout, "[+] Checking cardholder identity ... ");
                fflush(stdout);
                r = ie_get_user_full_name(ue_identifier, user_list, str_ue_name, str_ue_surname);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot get the cardholder information from %s!\n", temp);
# ifndef RKVAC_PROTOCOL_REMOTE
                    sc_cleanup(reader);
# else
                    ntw_close_connection(client_socket);
# endif
                    return 1;
                }
                fprintf(stdout, "\n");
                fprintf(stdout, "[!] Verify cardholder %s %s identity.\n", str_ue_name, str_ue_surname);
                fprintf(stdout, "[?] Is identity verified? Set Y to load attributes to the card or N to cancel Issuer part. > ");
                fflush(stdout);

                while (true)
                {
                   r = toupper(fgetc(stdin));
                   if (r == 'Y')
                   {
                       fprintf(stdout, "\n");
                       break;
                   }

                   if (r == 'N')
                   {
# ifndef RKVAC_PROTOCOL_REMOTE
                       sc_cleanup(reader);
# else
                       ntw_close_connection(client_socket);
# endif
                       exit(1);
                   }
                }

# ifndef RKVAC_PROTOCOL_REMOTE
                // user - set user attributes to the smart card
                fprintf(stdout, "[+] Set user attributes to the smart card.\n");
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_SET_USER_ATTRIBUTES\n");
# endif
                r = ue_set_user_attributes(reader, ue_attributes);
                if (r != 0)
                {
                    fprintf(stderr, "Error: cannot set the user attributes!\n");
                    return 1;
                }
# else
                // user - set user attributes to the remote card
                fprintf(stdout, "[+] Set user attributes to the remote card.\n");
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_SET_USER_ATTRIBUTES\n");
# endif
                r = ue_remote_set_user_attributes(client_socket, ue_attributes);
                if (r != 0)
                {
                    fprintf(stderr, "Error: cannot set the user attributes!\n");
                    ntw_close_connection(client_socket);
                    return 1;
                }
# endif

                // issuer - user attributes signature
                fprintf(stdout, "[+] Issue user credentials.\n");
                r = ie_issue(sys_parameters, ie_parameters, ie_keys, ra_keys.public_key, ue_identifier, ue_attributes, ra_signature, &ie_signature);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot compute the user attributes signature!\n");
# ifndef RKVAC_PROTOCOL_REMOTE
                    sc_cleanup(reader);
# else
                    ntw_close_connection(client_socket);
# endif
                    return 1;
                }

# ifndef RKVAC_PROTOCOL_REMOTE
                // user - set issuer signature of the user's attributes to the smart card
                fprintf(stdout, "[+] Set user credentials to the smart card.\n");
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_SET_ISSUER_SIGNATURES \n");
# endif
                r = ue_set_issuer_signatures(reader, ie_parameters, ie_signature);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot set the issuer signature of the user's attributes!\n");
                    sc_cleanup(reader);
                    return 1;
                }

                sc_cleanup(reader);
# else
                // user - set issuer signature of the user's attributes to the remote card
                fprintf(stdout, "[+] Set user credentials to the remote card.\n");
# ifndef NDEBUG
                fprintf(stdout, "[-] Command: INS_SET_ISSUER_SIGNATURES \n");
# endif
                r = ue_remote_set_issuer_signatures(client_socket, ie_parameters, ie_signature);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot set the issuer signature of the user's attributes!\n");
                    ntw_close_connection(client_socket);
                    return 1;
                }

                ntw_close_connection(client_socket);
# endif

                fprintf(stdout, TERMINAL_COLOR_CYN "[i] Issuer part complete.\n" TERMINAL_COLOR_RESET);
                if (first_usage)
                {
                    fprintf(stdout, "[i] In case of first usage copy %s file to the Verifier! (e.g. cp %s %s)\n",
                            IE_PRIVATE_KEYS_FILENAME, DEFAULT_DIRECTORY_FOR_ISSUER_DATA IE_PRIVATE_KEYS_FILENAME, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA IE_PRIVATE_KEYS_FILENAME);
                }

                exit(0);
            }
            /// Verifier part
            case 'v':
            {
                fprintf(stdout, TERMINAL_COLOR_CYN "[i] Verifier part started.\n" TERMINAL_COLOR_RESET);

                // check if the default Verifier directory has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                if (!is_dir_exists(DEFAULT_DIRECTORY_FOR_VERIFIER_DATA))
                {
                    if (!recursive_mkdir(temp, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)))
                    {
                        return 1;
                    }
                }

                //strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                //strcat(temp, IE_USER_ATTRIBUTES_FILENAME);
                verifier_attributes_given = false;
                strcpy(epoch_temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                strcat(epoch_temp, VE_EPOCH_FILENAME);

                // load arguments
                while ((opt = getopt_long(argc, argv, "e::a:d:u:w:c:", long_options, NULL)) != -1)
                {
                    switch (opt)
                    {
                        // set number of disclosed attributes
                        case 'd':
                        {
                            if (strlen(optarg) >= sizeof(str_disclosed_attributes))
                            {
                                fprintf(stderr, "Too long string of disclosed attributes %s\n", optarg);
                                exit(1);
                            }
                            else
                            {
                                strcpy(str_disclosed_attributes, optarg);
                            }

                            break;
                        }

                        // new epoch
                        case 'e':
                        {
                            if (optarg)
                            {
                                if (strlen(optarg) > PATH_MAX)
                                {
                                    fprintf(stderr, "Too long filename %s\n", optarg);
                                    exit(1);
                                }
                                strcpy(epoch_temp, optarg);

                                // check if the epoch file has already exists
                                fprintf(stdout, "[+] Checking the %s ... ", epoch_temp);
                                fflush(stdout);
                                if (!is_file_exists(epoch_temp))
                                {
                                    // Error
                                    fprintf(stdout, "given file does not exist!\n");
                                    exit(1);
                                }
                                else
                                {
                                    // copy given epoch file to ve_epoch file
                                    fprintf(stdout, "file exists, copying it to %s (create or rewrite) ... ", DEFAULT_DIRECTORY_FOR_VERIFIER_DATA VE_EPOCH_FILENAME);
                                    fflush(stdout);
                                    r = copy_file(epoch_temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA VE_EPOCH_FILENAME);
                                    if (r <= 0)
                                    {
                                        fprintf(stderr, "Error: cannot copy %s to %s\n", epoch_temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA VE_EPOCH_FILENAME);
                                        exit(1);
                                    }
                                    fprintf(stdout, "done.\n");

                                    // copy epoch to ve_epoch_for_RA file
                                    fprintf(stdout, "[+] Copying %s to the %s ... ",epoch_temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA RA_EPOCH_FILENAME);
                                    fflush(stdout);
                                    r = copy_file(epoch_temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA RA_EPOCH_FILENAME);
                                    if (r <= 0)
                                    {
                                        fprintf(stderr, "Error: cannot copy %s\n", epoch_temp);
                                        exit(1);
                                    }
                                    fprintf(stdout, "done.\n");
                                }
                            }
                            else
                            {
                                strcpy(epoch_temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                                strcat(epoch_temp, VE_EPOCH_FILENAME);

                                fprintf(stdout, "[+] Checking the %s ... ", epoch_temp);
                                fflush(stdout);
                                // create or rewrite epoch file
                                if (is_file_exists(epoch_temp))
                                {
                                    fprintf(stdout, "file exists, rewriting %s\n", epoch_temp);

                                    // open epoch file
                                    ve_epoch_file = fopen(epoch_temp, "r");
                                    if (ve_epoch_file != NULL)
                                    {
                                        // verifier - load epoch
                                        r = ve_get_epoch(&epoch, sizeof(epoch), ve_epoch_file);
                                    }
                                }
                                else
                                {
                                    fprintf(stdout, "file does not exist, creating %s\n", epoch_temp);
                                }

                                ve_epoch_file = fopen(epoch_temp, "w");
                                if (ve_epoch_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot create %s!\n", VE_EPOCH_FILENAME);
                                    return 1;
                                }

                                // verifier - generate epoch
                                fprintf(stdout, "[+] Generating new epoch (ccDDMMYY).\n");
                                r = ve_generate_epoch(epoch, sizeof(epoch), ve_epoch_file);
                                if (r < 0)
                                {
                                    fprintf(stderr, "Error: cannot generate epoch!\n");
                                }

                                // copy epoch to ve_epoch_for_RA file
                                fprintf(stdout, "[+] Copying %s to the %s ... ",epoch_temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA RA_EPOCH_FILENAME);
                                fflush(stdout);
                                r = copy_file(epoch_temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA RA_EPOCH_FILENAME);
                                if (r <= 0)
                                {
                                    fprintf(stderr, "Error: cannot copy %s\n", epoch_temp);
                                    exit(1);
                                }
                                fprintf(stdout, "done.\n");

                            }
                            fprintf(stdout, TERMINAL_COLOR_CYN "[i] Switch to the new epoch successful.\n" TERMINAL_COLOR_RESET);
                            fprintf(stdout, TERMINAL_COLOR_RED "[!] Move %s file to RA (e.g. mv %s %s)!\n" TERMINAL_COLOR_RESET,
                                    RA_EPOCH_FILENAME, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA RA_EPOCH_FILENAME, DEFAULT_DIRECTORY_FOR_RA_DATA RA_EPOCH_FILENAME);
                            fprintf(stdout, TERMINAL_COLOR_RED "[!] Initialize new epoch (-r -e)!\n" TERMINAL_COLOR_RESET);

                            exit(0);
                        }

                        // set user attributes filename
                        case 'a':
                        {
                            if (strlen(optarg) > PATH_MAX)
                            {
                                fprintf(stderr, "Too long filename %s\n", optarg);
                                exit(1);
                            }

                            if (!is_file_exists(optarg))
                            {
                                ptr = strrchr(optarg, '/');
                                if (ptr)
                                {
                                    it = ptr - optarg + 1;
                                    memcpy(temp, optarg, it);
                                    temp[it] = '\0';
                                    if (!is_dir_exists(temp))
                                    {
                                        fprintf(stderr, "Error: given directory %s does not exist!\n", temp);
                                        exit(1);
                                    }
                                    else
                                    {
                                        strcpy(temp, optarg);
                                    }
                                }
                                else
                                {
                                    strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                                    strcat(temp, optarg);
                                }
                            }
                            else
                            {
                                strcpy(temp, optarg);
                            }

                            verifier_attributes_given = true;
                            break;
                        }

                        // update blacklist
                        case 'u':
                        {

                            if (strlen(optarg) > PATH_MAX) {
                                fprintf(stderr, "Too long filename %s\n", optarg);
                                exit(1);
                            }
                            strcpy(temp, optarg);

                            // check if the ra blacklist has already exists
                            fprintf(stdout, "[+] Checking the %s ... ", temp);
                            fflush(stdout);
                            if (!is_file_exists(temp)) {
                                // Error
                                fprintf(stderr, "given file does not exist!\n");
                                exit(1);
                            }
                            else
                            {
                                // open blacklist file from ra
                                fprintf(stdout, "file exists, opening.\n");

                                ra_blacklist_file = fopen(temp, "r");
                                if (ra_blacklist_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", temp);
                                    return 1;
                                }
                            }

                            // check if the Verifier blacklist has already exists
                            strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                            strcat(temp, VE_BLACKLIST_FILENAME);
                            fprintf(stdout, "[+] Checking the %s ... ", temp);
                            fflush(stdout);
                            if (!is_file_exists(temp)) {
                                // Create Verifier blacklist file
                                fprintf(stderr, "file does not exist, creating %s\n", VE_BLACKLIST_FILENAME);

                                ve_blacklist_file = fopen(temp, "w");
                                if (ve_blacklist_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", temp);
                                    fclose(ra_blacklist_file);
                                    return 1;
                                }
                            }
                            else
                            {
                                // open Verifier blacklist file
                                fprintf(stdout, "file exists, opening.\n");

                                ve_blacklist_file = fopen(temp, "a");
                                if (ve_blacklist_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", temp);
                                    fclose(ra_blacklist_file);
                                    return 1;
                                }
                            }

                            // update Verifier blacklist file
                            fprintf(stdout, "[+] Updating %s ... ", VE_BLACKLIST_FILENAME);
                            fflush(stdout);
                            r = ve_update_blacklist(ra_blacklist_file, ve_blacklist_file);
                            if (r != 0)
                            {
                                fprintf(stderr, "Error: cannot update %s!\n", VE_BLACKLIST_FILENAME);
                                return 1;
                            }
                            fprintf(stdout, "done.\n");

                            fprintf(stdout, TERMINAL_COLOR_CYN "[i] Blacklist was successfully updated!\n" TERMINAL_COLOR_RESET);

                            exit(0);
                        }

                        // rewrite blacklist
                        case 'w':
                        {

                            if (strlen(optarg) > PATH_MAX) {
                                fprintf(stderr, "Too long filename %s\n", optarg);
                                exit(1);
                            }
                            strcpy(temp, optarg);

                            // check if the ra blacklist has already exists
                            fprintf(stdout, "[+] Checking the %s ... ", temp);
                            fflush(stdout);
                            if (!is_file_exists(temp)) {
                                // Error
                                fprintf(stderr, "given file does not exist!\n");
                                exit(1);
                            }
                            else
                            {
                                // open blacklist file from ra
                                fprintf(stdout, "file exists, opening.\n");

                                ra_blacklist_file = fopen(temp, "r");
                                if (ra_blacklist_file == NULL)
                                {
                                    fprintf(stderr, "Error: cannot open %s!\n", temp);
                                    return 1;
                                }
                            }

                            // open Verifier blacklist file
                            strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                            strcat(temp, VE_BLACKLIST_FILENAME);

                            ve_blacklist_file = fopen(temp, "w");
                            if (ve_blacklist_file == NULL)
                            {
                                fprintf(stderr, "Error: cannot open %s!\n", temp);
                                fclose(ra_blacklist_file);
                                return 1;
                            }

                            // rewrite Verifier blacklist file
                            fprintf(stdout, "[+] Rewriting %s ... ", VE_BLACKLIST_FILENAME);
                            fflush(stdout);
                            r = ve_update_blacklist(ra_blacklist_file, ve_blacklist_file);
                            if (r != 0)
                            {
                                fprintf(stderr, "Error: cannot update %s!\n", VE_BLACKLIST_FILENAME);
                                return 1;
                            }
                            fprintf(stdout, "done.\n");

                            fprintf(stdout, TERMINAL_COLOR_CYN "[i] Blacklist was successfully rewrite!\n" TERMINAL_COLOR_RESET);

                            exit(0);
                        }

                        // create credentials
                        case 'c':
                        {
                            if (strlen(optarg) > PATH_MAX)
                            {
                                fprintf(stderr, "Too long filename %s\n", optarg);
                                exit(1);
                            }
                            else
                            {
                                ptr = strrchr(optarg, '/');
                                if (ptr)
                                {
                                    it = ptr - optarg + 1;
                                    memcpy(temp, optarg, it);
                                    temp[it] = '\0';
                                    if (!is_dir_exists(temp))
                                    {
                                        fprintf(stderr, "Error: given directory %s does not exist!\n", temp);
                                        exit(1);
                                    }
                                    else
                                    {
                                        strcpy(temp, optarg);
                                    }
                                }
                                else
                                {
                                    strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                                    strcat(temp, optarg);
                                }
                            }

                            // system - setup
                            if (sys_parameters.curve != 0)
                            {
                                r = sys_setup(&sys_parameters);
                                if (r < 0)
                                {
                                    fprintf(stderr, "Error: cannot initialize the system!\n");
                                    return 1;
                                }
                            }

                            // Choose type of credentials
                            fprintf(stdout, "[+] Choose type of credentials (e.g. 1):\n");
                            fflush(stdout);

                            for (it = 0; it < NUMBER_OF_CREDENTIALS_TYPES; it++) {
                                fprintf(stdout, " [%d] %s\n", it + 1, cr[it].credentials_type_name);
                            }

                            fprintf(stdout, "> ");
                            fflush(stdout);

                            // read number from stdin
                            while (true) {
                                fgets(str_credentials, sizeof(str_credentials), stdin);
                                no = (int) strtol(str_credentials, NULL, 10);
                                if (no > 0 && no <= NUMBER_OF_CREDENTIALS_TYPES) {
                                    break;
                                }

                                fprintf(stderr, "Error: the number has to be 1..%d, you set %d\n",
                                        NUMBER_OF_CREDENTIALS_TYPES, no);
                                fprintf(stdout, "> ");
                                fflush(stdout);
                            }
                            no--;

                            if (no == NUMBER_OF_CREDENTIALS_TYPES - 1) {
                                fprintf(stdout, "  [+] Set number of user attributes (1..%d)> ", USER_MAX_NUM_ATTRIBUTES);
                                fflush(stdout);

                                // read number from stdin
                                while (true) {
                                    // read number from stdin
                                    fgets(str_credentials, sizeof(str_credentials), stdin);
                                    cr[no].ie_credentials_details.ue_attributes.num_attributes = strtol(str_credentials,
                                                                                                        NULL, 10);
                                    if (cr[no].ie_credentials_details.ue_attributes.num_attributes > 0 &&
                                        cr[no].ie_credentials_details.ue_attributes.num_attributes <=
                                        USER_MAX_NUM_ATTRIBUTES) {
                                        break;
                                    }

                                    fprintf(stderr, "Error: the number has to be 1..%d, you set %d\n",
                                            USER_MAX_NUM_ATTRIBUTES,
                                            (int) cr[no].ie_credentials_details.ue_attributes.num_attributes);
                                }
                            }

                            fprintf(stdout, "[+] Enter %s credentials\n", cr[no].credentials_type_name);
                            fflush(stdout);

                            // verifier - generate user attributes
                            for (it = 0; it < cr[no].ie_credentials_details.ue_attributes.num_attributes; it++) {
                                fprintf(stdout, " [%d] %s> ", it + 1,
                                        cr[no].ie_credentials_details.ie_credentials_name[it].name);
                                fflush(stdout);

                                if (fgets(str_credentials, MAX_INPUT, stdin) == NULL) {
                                    fprintf(stderr, "Error: %s\n",
                                            cr[no].ie_credentials_details.ie_credentials_name[it].name);
                                    return 1;
                                }

                                // remove \n character from the end of string
                                str_credentials[strlen(str_credentials) - 1] = 0;

                                if (strlen(str_credentials) == 0) {
                                    strcat(str_credentials, CREDENTIALS_DEFAULT_VALUE);
                                }

                                // set string value
                                strcpy(cr[no].ie_credentials_details.ue_attributes.ie_attributes_str_value[it].str_value,
                                       str_credentials);

                                // generate user attributes
                                r = ve_generate_user_attribute(
                                        cr[no].ie_credentials_details.ue_attributes.ie_attributes_str_value[it],
                                        ue_attributes.attributes[it].value);
                                if (r != 0) {
                                    fprintf(stderr, "Error: generate user attribute failed!");
                                    return 1;
                                }
                            }
                            // create new user attributes file
                            ie_issuer_attributes_file = fopen(temp, "w");
                            if (ie_issuer_attributes_file == NULL) {
                                fprintf(stderr, "Error: cannot create %s!\n", IE_USER_ATTRIBUTES_FILENAME);
                                return 1;
                            }

                            // verifier - set user attributes
                            r = ve_set_user_attributes(cr[no], ue_attributes, ie_issuer_attributes_file);
                            if (r < 0) {
                                fprintf(stderr, "Error: cannot set the user attributes to file!\n");
                                return 1;
                            }

                            fprintf(stdout, TERMINAL_COLOR_CYN "[i] User credentials created.\n" TERMINAL_COLOR_RESET);
                            exit(0);
                        }

                        default :
                        {
                            fprintf(stderr, "Press -h for help.\n");
                            exit(1);
                        }
                    }
                }

                // system - setup
                if (sys_parameters.curve != 0)
                {
                    r = sys_setup(&sys_parameters);
                    if (r < 0)
                    {
                        fprintf(stderr, "Error: cannot initialize the system!\n");
                        return 1;
                    }
                }

                if (verifier_attributes_given)
                {
                    // check if the user attributes file has already exist
                    fprintf(stdout, "[+] Checking the %s ... ", temp);
                    fflush(stdout);
                    if (!is_file_exists(temp)) {
                        fprintf(stdout, "file does not exist.\n");

                        // Choose type of credentials
                        fprintf(stdout, "[+] Choose type of credentials (e.g. 1):\n");
                        fflush(stdout);

                        for (it = 0; it < NUMBER_OF_CREDENTIALS_TYPES; it++) {
                            fprintf(stdout, " [%d] %s\n", it + 1, cr[it].credentials_type_name);
                        }

                        fprintf(stdout, "> ");
                        fflush(stdout);

                        // read number from stdin
                        while (true) {
                            fgets(str_credentials, sizeof(str_credentials), stdin);
                            no = strtol(str_credentials, NULL, 10);
                            if (no > 0 && no <= NUMBER_OF_CREDENTIALS_TYPES) {
                                break;
                            }

                            fprintf(stderr, "Error: the number has to be 1..%d, you set %d\n",
                                    NUMBER_OF_CREDENTIALS_TYPES, no);
                            fprintf(stdout, "> ");
                            fflush(stdout);
                        }
                        no--;

                        if (no == NUMBER_OF_CREDENTIALS_TYPES - 1) {
                            fprintf(stdout, "  [+] Set number of user attributes (1..%d)> ", USER_MAX_NUM_ATTRIBUTES);
                            fflush(stdout);

                            // read number from stdin
                            while (true) {
                                // read number from stdin
                                fgets(str_credentials, sizeof(str_credentials), stdin);
                                cr[no].ie_credentials_details.ue_attributes.num_attributes = strtol(str_credentials,
                                                                                                    NULL, 10);
                                if (cr[no].ie_credentials_details.ue_attributes.num_attributes > 0 &&
                                    cr[no].ie_credentials_details.ue_attributes.num_attributes <=
                                    USER_MAX_NUM_ATTRIBUTES) {
                                    break;
                                }

                                fprintf(stderr, "Error: the number has to be 1..%d, you set %d\n",
                                        USER_MAX_NUM_ATTRIBUTES,
                                        cr[no].ie_credentials_details.ue_attributes.num_attributes);
                            }
                        }

                        fprintf(stdout, "[+] Enter %s credentials\n", cr[no].credentials_type_name);
                        fflush(stdout);

                        // verifier - generate user attributes
                        for (it = 0; it < cr[no].ie_credentials_details.ue_attributes.num_attributes; it++) {
                            fprintf(stdout, " [%d] %s> ", it + 1,
                                    cr[no].ie_credentials_details.ie_credentials_name[it].name);
                            fflush(stdout);

                            if (fgets(str_credentials, MAX_INPUT, stdin) == NULL) {
                                fprintf(stderr, "Error: %s\n",
                                        cr[no].ie_credentials_details.ie_credentials_name[it].name);
                                return 1;
                            }

                            // remove \n character from the end of string
                            str_credentials[strlen(str_credentials) - 1] = 0;

                            if (strlen(str_credentials) == 0) {
                                strcat(str_credentials, CREDENTIALS_DEFAULT_VALUE);
                            }

                            // set string value
                            strcpy(cr[no].ie_credentials_details.ue_attributes.ie_attributes_str_value[it].str_value,
                                   str_credentials);

                            // generate user attributes
                            r = ve_generate_user_attribute(
                                    cr[no].ie_credentials_details.ue_attributes.ie_attributes_str_value[it],
                                    ue_attributes.attributes[it].value);
                            if (r != 0) {
                                fprintf(stderr, "Error: generate user attribute failed!");
                                return 1;
                            }
                        }
                        // create new user attributes file
                        ie_issuer_attributes_file = fopen(temp, "w");
                        if (ie_issuer_attributes_file == NULL) {
                            fprintf(stderr, "Error: cannot create %s!\n", IE_USER_ATTRIBUTES_FILENAME);
                            return 1;
                        }

                        // verifier - set user attributes
                        r = ve_set_user_attributes(cr[no], ue_attributes, ie_issuer_attributes_file);
                        if (r < 0) {
                            fprintf(stderr, "Error: cannot set the user attributes to file!\n");
                            return 1;
                        }
                        ue_attributes.num_attributes = cr[no].ie_credentials_details.ue_attributes.num_attributes;
                    } else {
                        // open user attributes file "r" mode
                        fprintf(stdout, "file exists, opening %s\n", temp);
                        ie_issuer_attributes_file = fopen(temp, "r");
                        if (ie_issuer_attributes_file == NULL) {
                            fprintf(stderr, "Error: cannot open %s!\n", temp);
                            return 1;
                        }

                        // verifier - load user attributes
                        fprintf(stdout, "[+] Reading user attributes from file.\n");
                        r = ve_get_user_attributes(&cr[no], &ue_attributes, ie_issuer_attributes_file);
                        if (r < 0) {
                            fprintf(stderr, "Error: cannot load the user attributes!\n");
                            return 1;
                        }
                    }
                } else
                    ue_attributes.num_attributes = 0;

                // select disclosed attributes
                if (strlen(str_disclosed_attributes) == 0)
                {
                    fprintf(stdout, "[!] Select disclosed attributes (e.g. 1 or set of attributes, 1,2,3)> ");
                    fflush(stdout);

                    if(fgets (str_disclosed_attributes, MAX_INPUT, stdin) == NULL)
                    {
                        fprintf(stderr, "Error: disclosed attributes\n");
                        return 1;
                    }
                    // remove \n character from the end of string
                    str_disclosed_attributes[strlen(str_disclosed_attributes) - 1 ] = 0;
                }
                else
                {
                    printf("[!] Disclosed attributes: %s\n\n", str_disclosed_attributes);
                }

                // check if the RA public key file has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                strcat(temp, RA_PUBLIC_KEY_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", RA_PUBLIC_KEY_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // error file does not exist
                    fprintf(stdout, "file does not exist!\n");
                    fprintf(stdout, "You have to copy %s file from RA!", RA_PUBLIC_KEY_FILENAME);
                    exit(1);
                }
                else
                {
                    // open RA public key file "r" mode
                    fprintf(stdout, "file exists, opening %s\n", RA_PUBLIC_KEY_FILENAME);
                    ra_public_keys_file = fopen(temp, "r");
                    if (ra_public_keys_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", RA_PUBLIC_KEY_FILENAME);
                        exit(1);
                    }
                }

                // check if the RA public parameters file has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                strcat(temp, RA_PUBLIC_PARAMETERS_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", RA_PUBLIC_PARAMETERS_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // error file does not exist
                    fprintf(stdout, "file does not exist!\n");
                    fprintf(stdout, "You have to copy %s file from RA!", RA_PUBLIC_PARAMETERS_FILENAME);
                    fclose(ra_public_keys_file);
                    exit(1);
                }
                else
                {
                    // open RA public parameters file "r" mode
                    fprintf(stdout, "file exists, opening %s\n", RA_PUBLIC_PARAMETERS_FILENAME);
                    ra_public_parameters_file = fopen(temp, "r");
                    if (ra_public_parameters_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", RA_PUBLIC_PARAMETERS_FILENAME);
                        fclose(ra_public_keys_file);
                        exit(1);
                    }
                }

                // check if the ie_private_keys file has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                strcat(temp, IE_PRIVATE_KEYS_FILENAME);
                fprintf(stdout, "[+] Checking the %s ... ", IE_PRIVATE_KEYS_FILENAME);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // error file does not exist
                    fprintf(stdout, "file does not exist!\n");
                    fprintf(stdout, "You have to copy %s file from Issuer!", IE_PRIVATE_KEYS_FILENAME);
                    fclose(ra_public_keys_file);
                    fclose(ra_public_parameters_file);
                    exit(1);
                }
                else
                {
                    // open ie_private_keys file in "r" mode
                    fprintf(stdout, "file exists, opening %s\n", IE_PRIVATE_KEYS_FILENAME);
                    ie_private_keys_file = fopen(temp, "r");
                    if (ie_private_keys_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", IE_PRIVATE_KEYS_FILENAME);
                        fclose(ra_public_keys_file);
                        fclose(ra_public_parameters_file);
                        return 1;
                    }
                }

                // load ra public key and ie private keys
                r = ve_setup(&ra_keys.public_key, &ra_parameters, &ie_keys, ue_attributes, ra_public_keys_file, ra_public_parameters_file, ie_private_keys_file);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot load revocation authority parameters or revocation authority key or issuer keys!\n");
                }

                // check if the epoch file has already exist
                fprintf(stdout, "[+] Checking the %s ... ", epoch_temp);
                fflush(stdout);
                if (!is_file_exists(epoch_temp))
                {
                    // error file does not exist
                    fprintf(stdout, "file does not exist!\n");
                    fprintf(stdout, "You have to generate new epoch at first (e.g. -v -e)!\n");
                    exit(1);
                }
                else
                {
                    // open epoch file in "r" mode
                    fprintf(stdout, "file exists, opening %s\n", VE_EPOCH_FILENAME);
                    ve_epoch_file = fopen(epoch_temp, "r");
                    if (ve_epoch_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", VE_EPOCH_FILENAME);
                        return 1;
                    }
                }

                // verifier - load epoch
                r = ve_get_epoch(&epoch, sizeof(epoch), ve_epoch_file);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot load epoch from file!\n");
                }

                // verifier - generate nonce
                fprintf(stdout, "[+] Generating nonce.\n");
                r = ve_generate_nonce(nonce, sizeof(nonce));
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot generate nonce!\n");
                    return 1;
                }
# ifndef RKVAC_PROTOCOL_REMOTE
                // card connection
                r = sc_get_card_connection(&reader);
                if (r < 0)
                {
                    fprintf(stderr, "Error: %s\n", sc_get_error(r));
                    return 1;
                }

# ifndef NDEBUG
                fprintf(stdout, "[-] Command: APDU_SCARD_SELECT_APPLICATION\n");
# endif

                dwRecvLength = sizeof(pbRecvBuffer);
                r = sc_transmit_data(reader, APDU_SCARD_SELECT_APPLICATION, sizeof(APDU_SCARD_SELECT_APPLICATION), pbRecvBuffer, &dwRecvLength, NULL);
                if (r < 0)
                {
                    fprintf(stderr, "Error: %s\n", sc_get_error(r));
                    return 1;
                }

                // user - compute proof of knowledge
                fprintf(stdout, "[+] user - compute proof of knowledge\n");
                r = ue_compute_proof_of_knowledge_seq_disclosing(reader, sys_parameters, ra_parameters, ra_signature, ie_signature, 0, 0, nonce, sizeof(nonce), epoch, sizeof(epoch), &ue_attributes, str_disclosed_attributes, &ue_credential, &ue_pi);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot compute the user proof of knowledge!\n");
                    return 1;
                }
#ifndef NDEBUG
                /* user - display proof of knowledge
                r = ue_display_proof_of_knowledge(reader);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot display the user proof of knowledge!\n");
                    return 1;
                }
                mcl_display_Fr("multos e", ue_pi.e);
                fprintf(stdout, "\n");
                */
#endif
                sc_cleanup(reader);
# else
                // open remote connection
                r = ntw_ipv4_server_open_connection(SOCK_STREAM, IPPROTO_TCP, &server_socket, &server_address);
                if (r < 0){
                    fprintf(stderr, "[!] Connection error!\n");
                    exit(EXIT_FAILURE);
                }

                // accept remote connection
                r = ntw_ipv4_server_accept_connection(server_socket, &client_socket, &client_address);
                if (r < 0){
                    fprintf(stderr, "[!] Connection error!\n");
                    exit(EXIT_FAILURE);
                }

# ifndef NDEBUG
                fprintf(stdout, "[-] Command: APDU_SCARD_SELECT_APPLICATION\n");
# endif

                dwRecvLength = sizeof(pbRecvBuffer);
                r = ntw_transmit_data(client_socket, APDU_SCARD_SELECT_APPLICATION, sizeof(APDU_SCARD_SELECT_APPLICATION),
                                      pbRecvBuffer, &dwRecvLength, NULL);
                if (r != SCARD_S_SUCCESS)
                {
                    ntw_close_connection(client_socket);
                    exit(EXIT_FAILURE);
                }

                // user - compute proof of knowledge
                fprintf(stdout, "[+] user - compute proof of knowledge (remote card)\n");
                r = ue_remote_compute_proof_of_knowledge_seq_disclosing(client_socket, sys_parameters, ra_parameters, ra_signature, ie_signature, 0, 0, nonce, sizeof(nonce), epoch, sizeof(epoch), &ue_attributes, str_disclosed_attributes, &ue_credential, &ue_pi);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot compute the user proof of knowledge!\n");
                    ntw_close_connection(client_socket);
                    return 1;
                }
#ifndef NDEBUG
                /* user - display proof of knowledge
                r = ue_remote_display_proof_of_knowledge(client_socket);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot display the user proof of knowledge!\n");
                    ntw_close_connection(client_socket);
                    return 1;
                }
                mcl_display_Fr("multos e", ue_pi.e);
                fprintf(stdout, "\n");
                 */
#endif
                ntw_close_connection(client_socket);
# endif
                // check if the blacklist file has already exist
                strcpy(temp, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                strcat(temp, VE_BLACKLIST_FILENAME);

                fprintf(stdout, "[+] Checking the %s ... ", temp);
                fflush(stdout);
                if (!is_file_exists(temp))
                {
                    // error file does not exist
                    ve_blacklist_file = NULL;
                    fprintf(stdout, "file does not exist!\n");
                    fprintf(stdout, "You can create blacklist at first (e.g. -v -u ./filename.csv)!\n");
                }
                else
                {
                    // open blacklist file in "r" mode
                    fprintf(stdout, "file exists, opening %s\n", VE_BLACKLIST_FILENAME);
                    ve_blacklist_file = fopen(temp, "r");
                    if (ve_blacklist_file == NULL)
                    {
                        fprintf(stderr, "Error: cannot open %s!\n", VE_BLACKLIST_FILENAME);
                        return 1;
                    }
                }

                // check or create ve_log_requests file
                r = check_data_file(VE_LOG_FILENAME, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA);
                if (r < 0)
                {
                    fprintf(stderr, "Error: cannot create %s!\n", VE_LOG_FILENAME);
                }

                // open ve_log_requests file
                ve_log_requests_file = open_data_file(VE_LOG_FILENAME, DEFAULT_DIRECTORY_FOR_VERIFIER_DATA, "a+");

                // verifier - verify proof of knowledge
                fprintf(stdout, "[+] verifier - verify proof of knowledge\n");
                r = ve_verify_proof_of_knowledge(sys_parameters, ra_parameters, ra_keys.public_key, ie_keys, nonce, sizeof(nonce), epoch, sizeof(epoch), ue_attributes, ue_credential, ue_pi, ve_blacklist_file);
                fprintf(stdout, "\n[i] Disclosed attributes:\n");
                for (it = 0; it < ue_attributes.num_attributes; it++)
                {
                    if (ue_attributes.attributes[it].disclosed)
                    {
                        fprintf(stdout, " [%d] ", (int) it + 1);
                        for (no = 0; no < EC_SIZE; no++)
                        {
                            fprintf(stdout, "%02X", ue_attributes.attributes[it].value[no]);
                        }
                        fprintf(stdout, "\n");
                    }
                }
                if (r < 0)
                {
                    fprintf(stderr, TERMINAL_COLOR_RED "Error: ACCESS DENIED (cannot verify the user proof of knowledge)\n" TERMINAL_COLOR_RESET);
                    ve_log_requests(epoch, sizeof(epoch), ue_credential.pseudonym, false, ve_log_requests_file);
                    return 1;
                }

                // log requests
                ve_log_requests(epoch, sizeof(epoch), ue_credential.pseudonym, true, ve_log_requests_file);


                fprintf(stdout, TERMINAL_COLOR_GRN "\nACCESS ALLOWED\n\n" TERMINAL_COLOR_RESET);
                fprintf(stdout, TERMINAL_COLOR_CYN "[i] Verifier part complete.\n" TERMINAL_COLOR_RESET);
                break;
            }
            default:
            {
                return 1;
            }
        }
    }
    else
    {
        fprintf(stderr, "You must select the entity (e.g. -v for verifier). Or write -h to show help.\n");
    }
    return 0;
}
