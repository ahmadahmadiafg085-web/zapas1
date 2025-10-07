const tg = window.Telegram?.WebApp;
if(tg) tg.expand();

const i18n = JSON.parse(document.getElementById('i18n-data').textContent);
const langSelect = document.getElementById('langSelect');
Object.keys(i18n).forEach(k=>{
  const o = document.createElement('option'); o.value=k; o.textContent = k.toUpperCase(); langSelect.appendChild(o);
});
langSelect.value = 'fa';

function t(key){
  const lang = langSelect.value || 'fa';
  return i18n[lang][key] || i18n['en'][key] || key;
}
document.getElementById('startBtn').textContent = t('start');
document.getElementById('demoBtn').textContent = t('demo');

langSelect.onchange = ()=>{
  document.getElementById('startBtn').textContent = t('start');
  document.getElementById('demoBtn').textContent = t('demo');
};

document.getElementById('startBtn').onclick = ()=>{
  document.getElementById('hero').classList.add('hidden');
  document.getElementById('hub').classList.remove('hidden');
  populateScenarios();
};

document.getElementById('closeSettings').onclick = ()=>{
  document.getElementById('settingsModal').classList.add('hidden');
};
document.getElementById('openSettings').onclick = ()=>{
  document.getElementById('settingsModal').classList.remove('hidden');
};
document.getElementById('saveSettings').onclick = ()=>{
  // save to localstorage as quick placeholder
  const brand = document.getElementById('brandName').value;
  const base = document.getElementById('baseUrl').value;
  localStorage.setItem('cybersmart_brand', brand);
  localStorage.setItem('cybersmart_base', base);
  alert('تنظیمات ذخیره شد (موقت). برای تولید نهایی در backend وارد کن.');
  document.getElementById('settingsModal').classList.add('hidden');
};

function populateScenarios(){
  const list = ['تست داده','تست نفوذ وب','تست ویندوز','تست شبکه','لودر زنجیره‌ای','سفارشی'];
  const scenarioList = document.getElementById('scenarioList');
  const scenarioSelect = document.getElementById('scenarioSelect');
  scenarioList.innerHTML=''; scenarioSelect.innerHTML='';
  list.forEach(s=>{
    const li = document.createElement('li');
    li.textContent = s;
    scenarioList.appendChild(li);
    const opt = document.createElement('option');
    opt.value = s; opt.textContent = s;
    scenarioSelect.appendChild(opt);
  });
}

document.getElementById('consent').onchange = ()=>{
  document.getElementById('runScenario').disabled = !document.getElementById('consent').checked;
};

document.getElementById('runScenario').onclick = async ()=>{
  const payload = {
    scenario: document.getElementById('scenarioSelect').value,
    repo: document.getElementById('repoInput').value,
    notes: document.getElementById('notes').value,
    user: tg?.initDataUnsafe?.user || null,
    modules: []
  };
  const base = localStorage.getItem('cybersmart_base') || '';
  if(!base) { alert('Base URL backend not set. Open Settings and enter Base URL.'); return; }
  try {
    const r = await fetch(base.replace(/\/+$/,'') + '/api/start-scenario', {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({...payload, consent:true})
    });
    const j = await r.json();
    document.getElementById('statusBox').textContent = j.message || JSON.stringify(j);
  } catch(e){
    document.getElementById('statusBox').textContent = 'خطا: '+e.message;
  }
};

// Shorten (simple)
document.getElementById('shortenLink').onclick = async ()=>{
  const base = localStorage.getItem('cybersmart_base') || '';
  const url = prompt('آدرس اصلی را وارد کنید:');
  if(!url) return;
  try{
    const r = await fetch(base.replace(/\/+$/,'') + '/api/shorten', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const j = await r.json();
    alert('لینک کوتاه: ' + (j.short || j.error));
  }catch(e){ alert('خطا: '+e.message); }
};

// Share button: builds a ready-to-send message for Telegram
document.getElementById('shareBtn').onclick = ()=>{
  const title = localStorage.getItem('cybersmart_brand') || 'CyberSmart Hub';
  const msg = `${title} — اجرا و تست سریع: ${document.getElementById('repoInput').value || ''}`;
  if(tg && tg.sendData) tg.sendData(JSON.stringify({share:msg}));
  else navigator.clipboard.writeText(msg).then(()=>alert('متن کپی شد برای ارسال.'));
};

// Upload via Telegram (uses WebApp api sendData or file input - placeholder)
