import {Layer, Item, Value} from 'dripcap';
import Enum from 'driptool/enum';

export default class DNSDissector {
  static get namespaces() {
    return ['::Ethernet::IPv4::UDP'];
  }

  analyze(packet, parentLayer) {
    if (parentLayer.getValue('srcPort').data !== 53 && parentLayer.getValue('dstPort').data !== 53) {
      return;
    }

    let layer = {
      items: [],
      namespace: parentLayer.namespace + '::DNS',
      name: 'DNS',
      id: 'dns',
      confidence: 0.8
    };

    let id = parentLayer.payload.readUInt16BE(0);
    let flags0 = parentLayer.payload.readUInt8(2);
    let flags1 = parentLayer.payload.readUInt8(3);
    let qr = !!(flags0 >> 7);

    let opcodeNumber = (flags0 >> 3) & 0b00001111;
    if (!(opcodeNumber in operationTable)) {
      throw new Error('wrong DNS opcode');
    }
    let opcode = new Enum(operationTable, opcodeNumber);

    let aa = !!((flags0 >> 2) & 1);
    let tc = !!((flags0 >> 1) & 1);
    let rd = !!((flags0 >> 0) & 1);
    let ra = !!(flags1 >> 7);

    if (flags1 & 0b01110000) {
      throw new Error('reserved bits must be zero');
    }

    let rcodeNumber = flags1 & 0b00001111;
    if (!(rcodeNumber in recordTable)) {
      throw new Error('wrong DNS rcode');
    }
    let rcode = new Enum(recordTable, rcodeNumber);

    let qdCount = parentLayer.payload.readUInt16BE(4);
    let anCount = parentLayer.payload.readUInt16BE(6);
    let nsCount = parentLayer.payload.readUInt16BE(8);
    let arCount = parentLayer.payload.readUInt16BE(10);

    layer.items.push({
      name: 'ID',
      id: 'id',
      range: '0:2',
      value: id
    });

    layer.items.push({
      name: 'Query/Response Flag',
      id: 'qr',
      range: '2:3',
      value: qr
    });

    layer.items.push({
      name: 'Operation Code',
      id: 'opcode',
      range: '2:3',
      value: opcodeNumber,
      summary: opcode.toString(),
      items: [
        {
          name: 'Name',
          id: 'name',
          range: '2:3',
          value: opcode.toString()
        }
      ]
    });

    layer.items.push({
      name: 'Authoritative Answer Flag',
      id: 'aa',
      range: '2:3',
      value: aa
    });

    layer.items.push({
      name: 'Truncation Flag',
      id: 'tc',
      range: '2:3',
      value: tc
    });

    layer.items.push({
      name: 'Recursion Desired',
      id: 'rd',
      range: '2:3',
      value: rd
    });

    layer.items.push({
      name: 'Recursion Available',
      id: 'ra',
      range: '3:4',
      value: ra
    });

    layer.items.push({
      name: 'Response Code',
      id: 'rcode',
      range: '3:4',
      value: rcodeNumber,
      summary: rcode.toString(),
      items: [
        {
          name: 'Name',
          id: 'name',
          range: '3:4',
          value: rcode.toString()
        }
      ]
    });

    layer.items.push({
      name: 'Question Count',
      id: 'qdCount',
      range: '4:6',
      value: qdCount
    });

    layer.items.push({
      name: 'Answer Record Count',
      id: 'anCount',
      range: '6:8',
      value: anCount
    });

    layer.items.push({
      name: 'Authority Record Count',
      id: 'nsCount',
      range: '8:10',
      value: nsCount
    });

    layer.items.push({
      name: 'Additional Record Count',
      id: 'arCount',
      range: '10:12',
      value: arCount
    });

    layer.payload = parentLayer.payload.slice(12);
    layer.items.push({
      name: 'Payload',
      id: 'payload',
      range: '12:',
      value: layer.payload
    });

    layer.summary = `[${opcode.toString()}] [${rcode.toString()}] qd:${qdCount} an:${anCount} ns:${nsCount} ar:${arCount}`;
    return new Layer(layer);
  }
}

let operationTable = {
  0: 'QUERY',
  1: 'IQUERY',
  2: 'STATUS',
  4: 'NOTIFY',
  5: 'UPDATE',
};

let recordTable = {
  0: 'No Error',
  1: 'Format Error',
  2: 'Server Failure',
  3: 'Name Error',
  4: 'Not Implemented',
  5: 'Refused',
  6: 'YX Domain',
  7: 'YX RR Set',
  8: 'NX RR Set',
  9: 'Not Auth',
  10: 'Not Zone',
};
