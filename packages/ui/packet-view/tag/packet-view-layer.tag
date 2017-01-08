<packet-view-layer>
  <p class="layer-name list-item" oncontextmenu={ layerContext } onclick={ toggleLayer } onmouseover={ layerRange } onmouseout={ rangeOut }>
    <i class={ fa: true, 'fa-arrow-circle-right': !visible, 'fa-arrow-circle-down': visible }></i>
    <i class="fa fa-question-circle" if={ layer.confidence < 1.0 }></i>
    { layer.name }
    <i class="text-summary">{ layer.summary }</i>
  </p>
  <ul if={ visible }>
    <packet-view-item each={ field in layer.items } layer={ parent.layer } parentObject={ parent.layer } path={ parent.layer.id }></packet-view-item>
    <li if={ layer.error }>
      <a class="text-label">Error:</a>
      { layer.error }
    </li>
  </ul>
  <packet-view-layer each={ layer, ns in rootLayers } layer={ layer } range={ parent.range } packet={ parent.opts.packet }></packet-view-layer>

  <script>
    const { Menu, PubSub } = require('dripcap');
    const { remote } = require('electron');
    this.visible = true;

    this.on('before-mount', () => {
      this.reset();
    });

    this.on('update', () => {
      this.reset();
    });

    reset() {
      this.range = (opts.range != null) ? (opts.range + ' ' + this.layer.range) : this.layer.range;
      this.rootLayers = this.layer.layers;
    }

    layerContext(e) {
      this.clickedLayerId = this.layer.id;
      e.filterText = this.layer.id;
      Menu.popup('packet-view:layer-menu', this, remote.getCurrentWindow(), {event: e});
      e.stopPropagation();
    };

    rangeOut(e) {
      PubSub.pub('packet-view:range', []);
    }

    fieldRange(e) {
      let range = this.range.split(' ');
      range.pop();
      range = range.concat((e.currentTarget.getAttribute('range') || '').split(' '));
      PubSub.pub('packet-view:range', range);
    }

    layerRange(e) {
      let range = this.range.split(' ');
      range.pop();
      PubSub.pub('packet-view:range', range);
    }

    toggleLayer(e) {
      this.visible = !this.visible;
      e.stopPropagation();
    };
  </script>

  <style type="text/less">
    :scope {
      display: block;
      padding-left: 8px;
    }
  </style>
</packet-view-layer>
