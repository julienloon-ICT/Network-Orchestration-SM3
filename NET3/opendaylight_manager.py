# OpenDaylight Management by Julian Loontjens

# Import needed packages
import httplib2
import json
import logging
from subprocess import Popen, PIPE
import csv

# Main variables
baseIP = '192.168.1.7'
baseUrl = 'http://192.168.1.7:8181/restconf'
h = httplib2.Http(".cache")
h.add_credentials('admin', 'admin')

# Setup logging
logging.basicConfig(filename='opendaylight_manager.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def request_data(endpoint, attribute):
    # Make HTTP get-call to the controller and returns asked dara
    url = f"{baseUrl}{endpoint}"
    logging.debug('Requesting URL: %s', url)
    try:
        response, content = h.request(url, "GET")
        if response.status != 200:
            print(f"Error whilst receiving data: HTTP Status {response.status}")
            return {}
        if not content:
            print("Error: Empty response.")
            return {}
        
        data = json.loads(content)
        return data.get(attribute, [])
    except json.JSONDecodeError as e:
        print(f"Error has occurred whilst decoding JSON: {e}")
        logging.error(f"JSON decode error: {e}")
        return {}
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")
        return {}

def execute_command(cmd):
    # Runs a terminal command and returns output
    process = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
    output, error = process.communicate()
    if error:
        print("Error executing command:", error.decode())
        logging.error(f"Error: {error.decode()}")
    return output.decode()

def print_header(option_name):
    # Print a centered heading with current option
    width = 68
    header = f"--- OpenDayLight Management | {option_name} ---"
    print("=" * width)
    print(header.center(width))
    print("=" * width)

def print_table(headers, rows):
    # Prints data to table
    print(' '.join(f"{header:20}" for header in headers))
    for row in rows:
        print(' '.join(f"{str(item):20}" for item in row))

def get_node_details(node_id):
    # Retrieves and prints detailed information for a specific node, focusing on connector details
    node_data = next((node for node in get_node_list().get('node', []) if node['id'] == node_id), None)
    if not node_data:
        print("Node not found.")
        return

    print(f"\nDetails for Node: {node_id}")
    print("=" * 55)

    # Display details of each connector, excluding detailed flow statistics
    print("Connectors:")

    print("-" * 50)

    for connector in node_data.get('node-connector', []):
        connector_id = connector.get('id', 'Unknown')
        print(f"  Connector ID: {connector_id}")
        
        # Detailed port information
        port_number = connector.get('flow-node-inventory:port-number', 'Unknown')
        name = connector.get('flow-node-inventory:name', 'Unknown')
        admin_status = connector.get('flow-node-inventory:admin-status', 'Unknown')
        oper_status = connector.get('flow-node-inventory:oper-status', 'Unknown')
        current_speed = connector.get('flow-node-inventory:current-speed', 'N/A')
        max_speed = connector.get('flow-node-inventory:maximum-speed', 'N/A')
        
        print(f"    Port Number: {port_number}")
        print(f"    Port Name: {name}")
        print(f"    Admin Status: {admin_status}")
        print(f"    Operational Status: {oper_status}")
        print(f"    Current Speed: {current_speed} bps")
        print(f"    Max Speed: {max_speed} bps")
        
        # MAC and IP addresses
        mac_address = connector.get('flow-node-inventory:hardware-address', 'Unknown')
        ip_address = connector.get('host', {}).get('ip', 'N/A')
        print(f"    MAC Address: {mac_address}")
        print(f"    IP Address: {ip_address}")
        
        # Additional statistics for the connector
        stats = connector.get('opendaylight-port-statistics:flow-capable-node-connector-statistics', {})
        packets = stats.get('packets', {})
        bytes_count = stats.get('bytes', {})
        collision_count = stats.get('collision-count', 'N/A')
        error_count = stats.get('receive-crc-error', 'N/A')
        duration_sec = stats.get('duration', {}).get('second', 'N/A')
        duration_nsec = stats.get('duration', {}).get('nanosecond', 'N/A')

        print(f"    TX Packets: {packets.get('transmitted', 'N/A')}")
        print(f"    RX Packets: {packets.get('received', 'N/A')}")
        print(f"    TX Bytes: {bytes_count.get('transmitted', 'N/A')}")
        print(f"    RX Bytes: {bytes_count.get('received', 'N/A')}")
        print(f"    Collision Count: {collision_count}")
        print(f"    CRC Errors: {error_count}")
        print(f"    Duration: {duration_sec} seconds, {duration_nsec} nanoseconds")
        print("-" * 50)

def get_node_list():
    logging.info("Fetching node list from OpenDaylight controller.")
    nodes = request_data('/operational/opendaylight-inventory:nodes', 'nodes')
    if nodes:
        logging.info(f"Successfully retrieved {len(nodes.get('node', []))} nodes.")
    else:
        logging.warning("No nodes found or an error occurred while fetching nodes.")
    return nodes

def list_nodes():
    print("\nList of the available nodes:")
    nodes = get_node_list()
    if nodes:
        for node in nodes.get('node', []):
            print(node['id'])
    else:
        print("No nodes found.")

def list_flows():
    # Gets and prints all active flows
    print("\nActive flows:")
    flows = []
    nodes = get_node_list()
    for node in nodes.get('node', []):
        for table in node.get("flow-node-inventory:table", []):
            if table['opendaylight-flow-table-statistics:flow-table-statistics']['active-flows'] > 0:
                for flow in table.get('flow', []):
                    flows.append({
                        "node": node['id'],
                        "flow_id": flow['id'],
                        "statistics": flow.get('opendaylight-flow-statistics:flow-statistics', {})
                    })
    if flows:
        for flow in flows:
            print(f"Node: {flow['node']}, Flow ID: {flow['flow_id']}")
            stats = flow['statistics']
            for stat in ["duration", "byte-count", "packet-count"]:
                stat_value = stats.get(stat, "Not available")
                if stat == "duration" and isinstance(stat_value, dict):
                    seconds = stat_value.get('second', 0)
                    nanoseconds = stat_value.get('nanosecond', 0)
                    print(f"  {stat} : {seconds} s {nanoseconds} ms")
                else:
                    print(f"  {stat} : {stat_value}")
            print("-" * 41)
    else:
        print("No active flows found.")

def print_node_stats():
    # Get statistics of a node and print them to debug
    node_id = input('Enter node ID: ')
    node_data = next((node for node in get_node_list().get('node', []) if node['id'] == node_id), None)
    if not node_data:
        print("Node not found.")
        return

    headers = ['NODE', 'PORT', 'TXPKTCNT', 'TXBYTES', 'RXPKTCNT', 'RXBYTES']
    rows = []
    for connector in node_data.get('node-connector', []):
        stats = connector.get('opendaylight-port-statistics:flow-capable-node-connector-statistics', {})
        packets = stats.get('packets', {})
        bytes_count = stats.get('bytes', {})
        rows.append([
            node_id,
            connector.get('flow-node-inventory:port-number', 'Unknown'),
            packets.get('transmitted', 0),
            bytes_count.get('transmitted', 0),
            packets.get('received', 0),
            bytes_count.get('received', 0)
        ])
    print_table(headers, rows)

def export_data_to_csv(data, filename):
    # Exports data to CSV-file
    """Exporteert data naar een CSV-bestand."""
    keys = data[0].keys() if data else []
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)
    print(f"Data exported to {filename}")

def export_flows():
    # Exports detailed flow information of all nodes to a CSV file
    logging.info("Starting the export of detailed flow information.")
    flows = []
    nodes = get_node_list()
    if not nodes.get('node', []):
        logging.warning("No nodes found. Exiting export_flows function.")
        print("No nodes available for exporting flows.")
        return

    for node in nodes.get('node', []):
        logging.info(f"Processing node: {node['id']}")
        for table in node.get("flow-node-inventory:table", []):
            logging.info(f"Processing table: {table.get('id', 'N/A')} in node: {node['id']}")
            for flow in table.get('flow', []):
                flow_id = flow.get('id', 'N/A')
                logging.debug(f"Processing flow ID: {flow_id} in table {table.get('id', 'N/A')} of node {node['id']}")
                
                # Extracting and adding more flow details
                flow_data = {
                    "node": node['id'],
                    "flow_id": flow_id,
                    "table_id": table.get('id', 'N/A'),
                    "priority": flow.get("priority", "N/A"),
                    "hard_timeout": flow.get("hard-timeout", "N/A"),
                    "idle_timeout": flow.get("idle-timeout", "N/A"),
                    "flags": flow.get("flags", "N/A"),
                }
                
                # Adding statistics if available
                statistics = flow.get('opendaylight-flow-statistics:flow-statistics', {})
                flow_data.update({
                    "duration_sec": statistics.get("duration", {}).get("second", "N/A"),
                    "duration_nsec": statistics.get("duration", {}).get("nanosecond", "N/A"),
                    "byte_count": statistics.get("byte-count", "N/A"),
                    "packet_count": statistics.get("packet-count", "N/A")
                })
                
                # Adding match criteria if available
                match = flow.get("match", {})
                flow_data.update({
                    "in_port": match.get("in-port", "N/A"),
                    "ethernet_type": match.get("ethernet-match", {}).get("ethernet-type", {}).get("type", "N/A"),
                    "ipv4_source": match.get("ipv4-source", "N/A"),
                    "ipv4_destination": match.get("ipv4-destination", "N/A")
                })

                # Adding actions if available
                instructions = flow.get("instructions", {}).get("instruction", [])
                actions = []
                for instruction in instructions:
                    actions.extend(instruction.get("apply-actions", {}).get("action", []))
                flow_data["actions"] = [action.get("output-action", {}).get("output-node-connector", "N/A") for action in actions]

                flows.append(flow_data)
                logging.debug(f"Flow data appended for flow ID: {flow_id}.")

    # Writing to CSV
    if flows:
        try:
            export_data_to_csv(flows, 'detailed_flows.csv')
            logging.info("Flow data successfully exported to detailed_flows.csv.")
            print("Flow data exported to detailed_flows.csv")
        except Exception as e:
            logging.error(f"Error while exporting data to CSV: {e}")
            print(f"Failed to export flow data: {e}")
    else:
        logging.warning("No flow data collected. Nothing to export.")
        print("No flow data collected.")

def check_controller_connection():
    logging.info(f"Checking connection to OpenDayLight Controller at {baseIP}.")
    print(f"Checking connection to OpenDayLight Controller at {baseIP}")
    try:
        response, _ = h.request(f"{baseUrl}/", "GET")
        if response.status == 200 or response.status == 204:
            logging.info(f"Successfully connected to OpenDayLight Controller: {baseIP}")
            print(f"\nSuccesfully connected to OpenDayLight Controller: {baseIP}")
        else:
            logging.warning(f"Failed to connect OpenDayLight Controller: {baseIP}. HTTP Status {response.status}")
            print(f"\nFailed to connect OpenDayLight Controller: {baseIP}. HTTP Status {response.status}")
    except Exception as e:
        logging.error(f"Connection error: {e}")
        print(f"\nConnection error: {e}")

def exit_program():
    print("Thank you for using OpenDayLight Management by Julian Loontjens!")
    print("Exiting OpenDayLight Management now...")
    exit()

# Menu options
menu_options = {
    '1': ("List all available nodes", lambda: (print_header("List all available nodes"), list_nodes())),
    '2': ("List active flows and details", lambda: (print_header("List active flows and details"), list_flows())),
    '3': ("Print node statistics", lambda: (print_header("Print node statistics"), print_node_stats())),
    '4': ("Export all flows to CSV", lambda: (print_header("Export all flows to CSV"), export_flows())),   
    '5': ("Get detailed information of node", lambda: (print_header("Get detailed information of node"), get_node_details(input('Enter node ID: ')))),
    '6': ("Check controller connection", lambda: (print_header("Check controller connection"), check_controller_connection())),
    '0': ("Exit", lambda: (print_header("Exit"), exit_program())),
}

# Menu loop
while True:
    print("\n")
    width = 68
    header = f"--- OpenDayLight Management | Main Menu ---"
    print("=" * width)
    print(header.center(width))
    print("=" * width)

    message = f"Select an option"
    print(message.center(width))

    print("-" * width)
    
    # Sort nummeric, except for the exit option '0'. That stays as last.
    sorted_keys = sorted((int(k) for k in menu_options if k != '0'))  # Nummeric sort, excl. option '0'.
    
    # Print sorted menu
    for key in sorted_keys:
        print(f"{key}. {menu_options[str(key)][0]}")
    
    print("-" * width)

    # Put exit option as last
    print(f"0. {menu_options['0'][0]}")
    
    footer = f"© 2024 Julian Loontjens"
    print("=" * width)
    print(footer)
    print("=" * width)
    
    option = input("Enter option: ")

    if option in menu_options:
        logging.info(f"User selected option: {menu_options[option][0]}")
        print("\n")
        menu_options[option][1]()
    else:
        logging.warning(f"Invalid menu option selected: {option}")
        print("Invalid option. Please try again.")