- ipfix-decorder
  - Decode ipfix
    - assume only 1 template in 1 packet(multipule flow data is ok)
    - enterprise items are not supported
    - support data type : unsigned and dateTimeMilliseconds
    - output  : stdout, elasticsearch, influxdb(v6 only)
    - I use Juniper to check
  - Usage
    - put ipfixdecorder.py and ipfixdef.py and config.yaml at same directory
    - do "python3 ipfixdecorder.py

