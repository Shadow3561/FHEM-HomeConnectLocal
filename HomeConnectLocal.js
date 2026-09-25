(function(){
  'use strict';
  if (window.HomeConnectLocalPopupLoaded) return;
  window.HomeConnectLocalPopupLoaded = true;

  function cmd(command){
    return new Promise(function(resolve,reject){
      if(typeof FW_cmd !== 'function'){ reject(new Error('FHEMWEB FW_cmd ist nicht verfuegbar.')); return; }
      var root=(typeof FW_root!=='undefined'&&FW_root)?FW_root:'/fhem';
      try{
        FW_cmd(root+'?cmd='+encodeURIComponent(command)+'&XHR=1',function(t){
          t=(t==null)?'':String(t);
          if(t && /^(Unknown argument|Usage:|Ungueltiger|Option |Programmstart|Kein Programm|Programm ')/.test(t)) reject(new Error(t));
          else resolve(t);
        });
      }catch(e){ reject(e); }
    });
  }
  function getConfig(dev){ return cmd('get '+dev+' programConfig').then(function(t){return JSON.parse(t);}); }
  function sleep(ms){return new Promise(function(r){setTimeout(r,ms);});}
  function findOption(c,name){ return (c.options||[]).find(function(o){return o.name===name;}); }
  function hasValue(o,v){return o && (o.values||[]).some(function(x){return String(x).toLowerCase()===String(v).toLowerCase();});}
  function esc(s){return String(s==null?'':s).replace(/[&<>\"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c];});}
  function prettyName(name){
    var fixed={ProgramMode:'Program mode',SpinSpeed:'Spin speed',DryingTarget:'Drying target'};
    if(fixed[name]) return fixed[name];
    var s=String(name||'').replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g,'$1 $2').toLowerCase();
    return s ? s.charAt(0).toUpperCase()+s.slice(1) : s;
  }
  function prettyValue(v){
    var s=String(v==null?'':v);
    if(s.toLowerCase()==='off') return 'Off';
    if(s.toLowerCase()==='on') return 'On';
    return s;
  }
  function waitForRevision(dev,baseline,test,tries){
    if(tries<=0) return getConfig(dev);
    return sleep(250).then(function(){return getConfig(dev);}).then(function(c){
      var newer=Number(c.runtimeRevision||0)>Number(baseline||0);
      if(newer && (!test || test(c))) return c;
      return waitForRevision(dev,baseline,test,tries-1);
    });
  }

  function openPopup(dev){
    cmd('set '+dev+' programConfigSession begin').then(function(){return getConfig(dev);}).then(function(cfg){
      if(cfg.running) throw new Error('Waerend eines laufenden Programms kann keine neue Programmkonfiguration vorbereitet werden.');
      var overlay=document.createElement('div'); overlay.className='hcl-overlay';
      overlay.innerHTML='<div class="hcl-dialog" role="dialog" aria-modal="true" aria-label="Programm vorbereiten">'+
        '<div class="hcl-head"><strong>Programm vorbereiten</strong><button type="button" class="hcl-x" aria-label="Schliessen">×</button></div>'+
        '<div class="hcl-body"><label><span>Programm</span><select class="hcl-program"></select></label><div class="hcl-status"></div><div class="hcl-core"></div>'+
        '<details class="hcl-more"><summary>Weitere Optionen</summary><div class="hcl-extra"></div></details><div class="hcl-note"></div></div>'+
        '<div class="hcl-actions"><button type="button" class="hcl-cancel">Abbrechen</button><button type="button" class="hcl-send">An das Gerät senden</button></div></div>';
      document.body.appendChild(overlay);
      var sel=overlay.querySelector('.hcl-program'),core=overlay.querySelector('.hcl-core'),extra=overlay.querySelector('.hcl-extra'),status=overlay.querySelector('.hcl-status'),send=overlay.querySelector('.hcl-send'),more=overlay.querySelector('.hcl-more'),note=overlay.querySelector('.hcl-note');
      var busy=false,draft={},generation=0;
      function fillPrograms(c){sel.innerHTML='';(c.programs||[]).forEach(function(p){var o=document.createElement('option');o.value=p;o.textContent=(c.programLabels&&c.programLabels[p])?c.programLabels[p]:p;if(p===c.selectedProgram)o.selected=true;sel.appendChild(o);});}
      function setBusy(v,msg){busy=v;sel.disabled=v;send.disabled=v;Array.prototype.forEach.call(overlay.querySelectorAll('.hcl-core select,.hcl-core input,.hcl-extra select,.hcl-extra input'),function(x){x.disabled=v;});if(msg!==undefined)status.textContent=msg;}
      function makeField(o,target){
        var lab=document.createElement('label'),title=document.createElement('span'),input;
        title.textContent=o.label||prettyName(o.name);lab.appendChild(title);
        if(o.type==='enum'||o.type==='bool'){
          input=document.createElement('select');(o.values||[]).forEach(function(v){var x=document.createElement('option');x.value=v;var label=(o.valueLabels&&o.valueLabels[v])?o.valueLabels[v]:prettyValue(v);if(o.name==='Temperature'){var m=String(v).match(/^GC(\d+)$/i);if(m)label=m[1]+' \u00B0C';else if(String(v).toLowerCase()==='cold')label=(o.valueLabels&&o.valueLabels[v])?o.valueLabels[v]:'Cold';}x.textContent=label;input.appendChild(x);});
        }else{input=document.createElement('input');input.type='number';input.min=o.min;input.max=o.max;input.step=o.step;}
        input.dataset.name=o.name;
        var chosen;
        if(Object.prototype.hasOwnProperty.call(draft,o.name)) chosen=draft[o.name];
        else if(['ProgramMode','Temperature','SpinSpeed','DryingTarget'].indexOf(o.name)<0){
          var off=(o.values||[]).find(function(v){return String(v).toLowerCase()==='off';});
          // Zusatzoptionen starten im Popup weiterhin lokal mit Off, werden aber
          // erst nach einer echten Benutzeränderung in draft aufgenommen und gesendet.
          chosen=(off!==undefined)?off:o.current;
        } else chosen=o.current;
        if(chosen!==undefined&&chosen!==null&&chosen!=='') input.value=chosen;
        input.addEventListener('change',function(){draft[o.name]=input.value;});
        lab.appendChild(input);target.appendChild(lab);
      }
      function render(c,resetDraft){
        cfg=c;if(resetDraft) draft={};core.innerHTML='';extra.innerHTML='';fillPrograms(c);
        var coreNames=['ProgramMode','Temperature','SpinSpeed','DryingTarget'];
        var pmDraft=Object.prototype.hasOwnProperty.call(draft,'ProgramMode')?draft.ProgramMode:(findOption(c,'ProgramMode')||{}).current;
        (c.options||[]).forEach(function(o){
          if(o.name==='DryingTarget' && String(pmDraft||'').toLowerCase()==='washing') return;
          makeField(o,coreNames.indexOf(o.name)>=0?core:extra);
        });
        more.open=false; more.style.display=extra.children.length?'block':'none';
        var pmInput=core.querySelector('[data-name="ProgramMode"]');
        if(pmInput) pmInput.addEventListener('change',function(){draft.ProgramMode=pmInput.value;render(c,false);});
        note.innerHTML='<strong>Hinweis:</strong> Die Einstellungen werden an <strong>'+esc(c.displayName||c.device)+'</strong> übertragen, das Programm wird dabei noch nicht gestartet.<br>Start anschließend in FHEM mit: <code>set '+esc(c.device)+' start</code>';
        status.textContent='';
      }
      function selectProgram(p){
        var myGen=++generation; setBusy(true,'Programm wird vorbereitet …');core.innerHTML='';extra.innerHTML='';draft={};
        var baseline=Number(cfg.runtimeRevision||0);
        return cmd('set '+dev+' program '+p)
          .then(function(){return waitForRevision(dev,baseline,function(c){return c.selectedProgram===p;},40);})
          .then(function(c){
            if(myGen!==generation) return null;
            cfg=c; var pm=findOption(c,'ProgramMode');
            if(pm && hasValue(pm,'Washing') && String(pm.current||'').toLowerCase()!=='washing'){
              status.textContent='Program mode wird auf Washing gesetzt …';
              var rev=Number(c.runtimeRevision||0);
              return cmd('set '+dev+' ProgramMode Washing').then(function(){
                return waitForRevision(dev,rev,function(x){var o=findOption(x,'ProgramMode');return !o||String(o.current||'').toLowerCase()==='washing';},40);
              });
            }
            return c;
          }).then(function(c){if(!c||myGen!==generation)return;cfg=c;render(c,true);setBusy(false,'');})
          .catch(function(e){if(myGen===generation)setBusy(false,'Fehler: '+e.message);});
      }
      function close(){generation++;cmd('set '+dev+' programConfigSession end').catch(function(){});overlay.remove();}
      fillPrograms(cfg);render(cfg,true);
      overlay.querySelector('.hcl-x').addEventListener('click',close);overlay.querySelector('.hcl-cancel').addEventListener('click',close);overlay.addEventListener('click',function(e){if(e.target===overlay)close();});
      sel.addEventListener('change',function(){if(!busy)selectProgram(sel.value);});
      send.addEventListener('click',function(){
        if(busy)return;setBusy(true,'Einstellungen werden an das Gerät gesendet …');
        var order=['ProgramMode','Temperature','SpinSpeed','DryingTarget'];
        var names=Object.keys(draft).sort(function(a,b){var ia=order.indexOf(a),ib=order.indexOf(b);ia=ia<0?999:ia;ib=ib<0?999:ib;return ia-ib||a.localeCompare(b);});
        names.reduce(function(p,name){return p.then(function(){var oo=findOption(cfg,name);status.textContent=((oo&&oo.label)||prettyName(name))+' wird gesetzt …';return cmd('set '+dev+' '+name+' '+draft[name]).then(function(){return sleep(300);});});},Promise.resolve())
          .then(function(){return cmd('set '+dev+' programConfigSession end');})
          .then(function(){setBusy(false,'✓ Einstellungen wurden an das Gerät übertragen. Das Programm wurde nicht gestartet.');send.disabled=true;})
          .catch(function(e){setBusy(false,'Fehler: '+e.message);});
      });
    }).catch(function(e){cmd('set '+dev+' programConfigSession end').catch(function(){});alert('HomeConnectLocal: '+e.message);});
  }

  var style=document.createElement('style');
  style.textContent='.hcl-overlay{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px}.hcl-dialog{background:#fff;color:#222;border-radius:8px;max-width:620px;width:100%;max-height:90%;overflow:auto;box-shadow:0 8px 30px rgba(0,0,0,.35)}.hcl-head,.hcl-actions{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid #ddd}.hcl-actions{border-top:1px solid #ddd;border-bottom:0;justify-content:flex-end;gap:10px}.hcl-body{padding:16px}.hcl-body label{display:grid;grid-template-columns:minmax(160px,1fr) minmax(190px,1.4fr);gap:12px;align-items:center;margin:0 0 10px}.hcl-body select,.hcl-body input{width:100%;box-sizing:border-box}.hcl-x{font-size:24px;border:0;background:transparent;cursor:pointer}.hcl-status{margin:8px 0;min-height:1.2em}.hcl-more{margin-top:14px;border-top:1px solid #ddd;padding-top:12px}.hcl-more summary{cursor:pointer;font-weight:600;margin-bottom:12px}.hcl-note{margin-top:18px;padding:12px;background:#f5f5f5;border-radius:6px;line-height:1.5}.hcl-note code{white-space:normal}.hcl-actions button{min-width:120px}@media(max-width:520px){.hcl-body label{grid-template-columns:1fr;gap:4px}.hcl-actions{flex-wrap:wrap}.hcl-actions button{flex:1}}';
  document.head.appendChild(style);
  document.addEventListener('click',function(e){var b=e.target.closest('.homeconnectlocal-config-open');if(!b)return;e.preventDefault();openPopup(b.dataset.device);});
})();
