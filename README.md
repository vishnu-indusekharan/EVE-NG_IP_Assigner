# EVE-NG_IP_Assigner

The boring part while doing networking labs is assinging point to point IP address on all the links in the topology. This script helps to assign ip address to all point to point interfaces in the given topology in EVE-NG.

## Usage: 
assigner.py [-h] -u USERNAME -i EVE_IP -l LAB_PATH
```
optional arguments:
  -h  : show this help message and exit
  -u  : eve-ng gui USERNAME
  -i  : IP address of the EVE-NG host
  -l  : Lab Name
```
## Example: 
python assigner.py -u admin -i 10.197.200.11 -l sample_lab.unl

## Logic:
If there is a link between router **Rx** and **Ry**, where x and y are router numbers when x < y,
- The ip address on Rx router will be 10.x.y.x/24 
- The ip address on Ry router will be 10.x.y.y/24
- Loopback address on the Rx will be x.x.x.x/32
- Loopback address on the Ry will be y.y.y.y/32

## Limitations: 
- Two links between same router is not supported.
- Topology with xrv, csr1000v, and XRv are supported.
- Multi axis netwrok is not supported.
- Script will work only if all devices are booted.
