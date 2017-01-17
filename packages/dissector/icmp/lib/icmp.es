import {Layer, Item, Value} from 'dripcap';
import Enum from 'driptool/enum';

export default class ARPDissector {
  static get namespaces() {
    return [/::Ethernet::\w+::<ICMP>/];
  }

  analyze(packet, parentLayer) {
    let layer = {
      items: [],
      namespace: parentLayer.namespace.replace('<ICMP>', 'ICMP'),
      name: 'ICMP',
      id: 'icmp'
    };

    let typeNumber = parentLayer.payload.readUInt8(0);
    let type = new Enum(typeTable, typeNumber);
    layer.items.push({
      name: 'Type',
      id: 'type',
      range: '0:1',
      value: typeNumber,
      summary: type.toString(),
      items: [
        {
          name: 'Name',
          id: 'name',
          range: '0:1',
          value: type.toString()
        }
      ]
    });

    let codeNumber = parentLayer.payload.readUInt8(1);
    let codeItem = {
      name: 'Code',
      id: 'code',
      range: '1:2',
      value: codeNumber
    };

    let codeTable;
    switch (typeNumber) {
      case 3:
        codeTable = unreachableTbale;
      break;
      case 5:
        codeTable = redirectTable;
      break;
      case 11:
        codeTable = timeExceededTable;
      break;
    }

    if (codeTable != null) {
      let code = new Enum(codeTable, codeNumber);
      codeItem.summary = code.toString();
      codeItem.items = [
        {
          name: 'Name',
          id: 'name',
          range: '1:2',
          value: code.toString()
        }
      ];
    }

    layer.items.push(codeItem);

    let checksum = parentLayer.payload.readUInt16BE(2);
    layer.items.push({
      name: 'Checksum',
      id: 'checksum',
      range: '2:4',
      value: checksum
    });

    layer.items.push({
      name: 'Rest of Header',
      id: 'rest',
      range: '4:8',
      value: parentLayer.payload.slice(4, 8)
    });

    layer.payload = parentLayer.payload.slice(8);
    layer.items.push({
      name: 'Payload',
      id: 'payload',
      range: '8:',
      value: layer.payload
    });

    layer.summary = `ICMP`;
    return new Layer(layer);
  }
}

let typeTable = {
  0: 'Echo Reply',
  3: 'Destination Unreachable',
  4: 'Source Quench',
  5: 'Redirect Message',
  6: 'Alternate Host Address',
  8: 'Echo Request',
  9: 'Router Advertisement',
  10: 'Router Solicitation',
  11: 'Time Exceeded',
  12: 'Parameter Problem',
  13: 'Timestamp',
  14: 'Timestamp Reply',
  15: 'Information Request',
  16: 'Information Reply',
  17: 'Address Mask Request',
  18: 'Address Mask Reply',
  30: 'Traceroute',
  31: 'Datagram Conversion Error',
  32: 'Mobile Host Redirect',
  33: 'Where-Are-You',
  34: 'Here-I-Am',
  35: 'Mobile Registration Request',
  36: 'Mobile Registration Reply',
  37: 'Domain Name Request',
  38: 'Domain Name Reply',
  39: 'SKIP Algorithm Discovery Protocol',
  40: 'Photuris',
  41: 'Seamoby',
  253: 'RFC3692-style Experiment 1',
  254: 'RFC3692-style Experiment 2'
};

let unreachableTbale = {
  0: 'Destination network unreachable',
  1: 'Destination host unreachable',
  2: 'Destination protocol unreachable',
  3: 'Destination port unreachable',
  4: 'Fragmentation required',
  5: 'Source route failed',
  6: 'Destination network unknown',
  7: 'Destination host unknown',
  8: 'Source host isolated',
  9: 'Network administratively prohibited',
  10:	'Host administratively prohibited',
  11:	'Network unreachable for ToS',
  12:	'Host unreachable for ToS',
  13:	'Communication administratively prohibited',
  14:	'Host Precedence Violation',
  15:	'Precedence cutoff in effect'
};

let redirectTable = {
  0: 'Redirect for Network',
  1: 'Redirect for Host',
  2: 'Redirect for Type of Service and Network',
  3: 'Redirect for Type of Service and Host'
};

let timeExceededTable = {
  0: 'Time-to-live exceeded in transit',
  1: 'Fragment reassembly time exceeded'
};
