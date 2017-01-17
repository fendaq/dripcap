import { Session } from 'dripcap';

export default class ICMP {
  activate() {
    Session.registerDissector(`${__dirname}/icmp.es`);
    Session.registerFilterHints('icmp', [
      {filter: 'icmp', description: 'ICMP'}
    ]);
  }

  deactivate() {
    Session.unregisterDissector(`${__dirname}/icmp.es`);
    Session.unregisterFilterHints('icmp');
  }
}
