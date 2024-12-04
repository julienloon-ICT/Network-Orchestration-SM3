# OpenDayLight Management

**Author:** Julian Loontjens  
**Version:** 1.0  
**Date:** 2024  

## Overview
OpenDayLight Management is a Python-based tool designed to interact with an OpenDayLight SDN (Software-Defined Networking) controller. It provides functionalities for managing nodes, flows, and other network elements via REST API calls. This application logs all activities, exports data, and offers a command-line interface for convenience.

---

## Features
- **List Available Nodes:** View all nodes managed by the OpenDayLight controller.
- **View Active Flows:** Retrieve and display detailed information about active flows.
- **Export Flow Data:** Export flow data to a CSV file for further analysis.
- **Node Statistics:** Display detailed statistics of a selected node, including port and traffic data.
- **Detailed Node Information:** Examine node connectors, including port speeds, statuses, and statistics.
- **Controller Connection Check:** Verify the connection to the OpenDayLight controller.
- **Logging:** All actions and errors are logged for auditing and debugging purposes.

---

## Requirements
- **Python Version:** Python 3.7 or higher  
- **Libraries:**  
  - `httplib2`  
  - `json`  
  - `logging`  
  - `subprocess`  
  - `csv`  

To install the required libraries, run:  
```bash
pip install httplib2
```
---

## Setup and Usage

### 1\. Modify Configuration

Update the following variables in the script to match your environment:

*   **baseIP**: The IP address of the OpenDayLight controller.
    
*   **baseUrl**: The base URL of the OpenDayLight REST API.Example: http://:8181/restconf
    
*   **Default Credentials:** admin/admin.
    
### 2\. Run the Script

Run the Python script using:
```bash
python opendaylight_manager.py
```

### 3\. Menu Options

After starting the script, you will see a menu with the following options:

1.  **List all available nodes**
    
2.  **List active flows and details**
    
3.  **Print node statistics**
    
4.  **Export all flows to CSV**
    
5.  **Get detailed information of a node**
    
6.  **Check controller connection**
    
7.  **Exit**
    

Select an option by entering the corresponding number.

---

## Logging

The application logs all operations in a log file (opendaylight\_manager.log). Logs include details about API calls, errors, and user-selected actions.

### Log Levels

*   **DEBUG:** Detailed information about API requests and responses.
    
*   **INFO:** General operational updates, such as successfully retrieved data.
    
*   **WARNING:** Notices about issues like invalid input or empty responses.
    
*   **ERROR:** Critical errors, such as connectivity issues or JSON decoding problems.
    

## Exported Data

Data can be exported to a CSV file for offline analysis. Exported files include:

*   **Flows:** Detailed information about active flows (saved as detailed\_flows.csv).
    
---

## Troubleshooting

1.  **Connection Issues:**Ensure the OpenDayLight controller is reachable at the IP address and port specified in baseUrl.
    
2.  **Invalid Menu Option:**If an invalid option is selected, the application will display a warning and prompt again.
    
3.  **Empty Node or Flow Data:**Verify the OpenDayLight controller is configured correctly and managing nodes/flows.
    
4.  **Errors in Logs:**Check the opendaylight\_manager.log file for detailed error messages.
    
---

## Contributing

If you would like to contribute to this project:

1.  Fork the repository.
    
2.  Create a new branch for your feature or bug fix.
    
3.  Submit a pull request.

---

© 2024 Julian Loontjens