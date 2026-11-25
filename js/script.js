/* VaultKey — cofre de senhas. A parte de criptografia está em js/cripto.js */

const CHAVE = 'vaultkey_cofre';
const AUTO_TRAVA_MS = 5 * 60 * 1000;
const $ = (s) => document.querySelector(s);
const escapar = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const armazenamento = {
  ler() { try { return JSON.parse(localStorage.getItem(CHAVE)); } catch { return null; } },
  salvar(v) { try { localStorage.setItem(CHAVE, JSON.stringify(v)); } catch { /* sem storage */ } },
  apagar() { try { localStorage.removeItem(CHAVE); } catch { /* sem storage */ } }
};

let sessao = null;   // { chave, sal, itens } enquanto o cofre está aberto
let editando = null;
let timerTrava = null;

/* ---------- Força da senha (estimativa por entropia) ---------- */
function forca(senha) {
  if (!senha) return { pct: 0, nome: '', cor: 'transparent' };
  let tam = 0;
  if (/[a-z]/.test(senha)) tam += 26;
  if (/[A-Z]/.test(senha)) tam += 26;
  if (/\d/.test(senha)) tam += 10;
  if (/[^a-zA-Z\d]/.test(senha)) tam += 32;
  let bits = senha.length * Math.log2(tam || 1);
  if (/(.)\1{2,}/.test(senha) || /^(123|abc|qwe|senha|password)/i.test(senha)) bits *= 0.6;
  if (bits < 40) return { pct: 25, nome: 'Fraca', cor: '#f85149', bits };
  if (bits < 60) return { pct: 50, nome: 'Razoável', cor: '#e3b341', bits };
  if (bits < 80) return { pct: 75, nome: 'Boa', cor: '#58a6ff', bits };
  return { pct: 100, nome: 'Forte', cor: '#3ddc97', bits };
}
function pintarMedidor(el, senha) {
  const f = forca(senha);
  el.querySelector('i').style.cssText = `width:${f.pct}%;background:${f.cor}`;
  el.querySelector('span').textContent = f.nome ? `${f.nome}${f.bits ? ` · ~${Math.round(f.bits)} bits` : ''}` : '';
}

/* ---------- Gerador ---------- */
const CONJUNTOS = { mai: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', min: 'abcdefghijklmnopqrstuvwxyz', num: '0123456789', sim: '!@#$%&*()-_=+[]{};:,.?' };
function aleatorio(max) { // número aleatório criptográfico sem viés
  const lim = Math.floor(0x100000000 / max) * max; const b = new Uint32Array(1);
  do crypto.getRandomValues(b); while (b[0] >= lim);
  return b[0] % max;
}
function gerarSenha() {
  const tamanho = Number($('#tamanho').value);
  let grupos = ['mai', 'min', 'num', 'sim'].filter((g) => $(`#op-${g}`).checked).map((g) => CONJUNTOS[g]);
  if (!grupos.length) { $('#op-min').checked = true; grupos = [CONJUNTOS.min]; }
  if ($('#op-amb').checked) grupos = grupos.map((g) => g.replace(/[lI1O0o]/g, ''));
  // Garante pelo menos um caractere de cada grupo escolhido
  const chars = grupos.map((g) => g[aleatorio(g.length)]);
  const todos = grupos.join('');
  while (chars.length < tamanho) chars.push(todos[aleatorio(todos.length)]);
  for (let i = chars.length - 1; i > 0; i--) { const j = aleatorio(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join('');
}
function atualizarGerador() {
  $('#tam-valor').textContent = $('#tamanho').value;
  const s = gerarSenha();
  $('#gerada').textContent = s;
  pintarMedidor($('#medidor-ger'), s);
}
['#tamanho', '#op-mai', '#op-min', '#op-num', '#op-sim', '#op-amb'].forEach((id) => $(id).addEventListener('input', atualizarGerador));
$('#regerar').addEventListener('click', atualizarGerador);
$('#copiar-gerada').addEventListener('click', () => copiar($('#gerada').textContent, 'Senha gerada copiada'));

/* ---------- Trava / desbloqueio ---------- */
function prepararTrava() {
  const existe = Boolean(armazenamento.ler());
  $('#campo-confirma').hidden = existe;
  $('#medidor-mestra').hidden = existe;
  $('#apagar-cofre').hidden = !existe;
  $('#mestra').autocomplete = existe ? 'current-password' : 'new-password';
  $('#trava-sub').textContent = existe ? 'Digite sua senha mestra para abrir o cofre.' : 'Crie uma senha mestra para proteger o seu cofre.';
  $('#btn-trava').textContent = existe ? 'Desbloquear' : 'Criar cofre';
  $('#nota-trava').textContent = existe ? '' : 'Guarde bem esta senha: ela não fica salva em lugar nenhum e não pode ser recuperada.';
  $('#tela-trava').hidden = false; $('#tela-cofre').hidden = true;
  $('#mestra').value = ''; $('#confirma').value = ''; $('#erro-trava').textContent = '';
  $('#mestra').focus();
}
$('#mestra').addEventListener('input', () => { if (!$('#medidor-mestra').hidden) pintarMedidor($('#medidor-mestra'), $('#mestra').value); });

$('#form-trava').addEventListener('submit', async (e) => {
  e.preventDefault();
  const senha = $('#mestra').value;
  const erro = $('#erro-trava');
  const salvo = armazenamento.ler();
  $('#btn-trava').disabled = true; $('#btn-trava').textContent = 'Aguarde...';
  try {
    if (!salvo) {
      if (senha.length < 8) throw new Error('Use pelo menos 8 caracteres.');
      if (senha !== $('#confirma').value) throw new Error('As senhas não são iguais.');
      const sal = Cripto.novoSal();
      const chave = await Cripto.derivarChave(senha, Cripto.deB64(sal));
      sessao = { chave, sal, itens: [] };
      await gravar();
    } else {
      const chave = await Cripto.derivarChave(senha, Cripto.deB64(salvo.sal));
      try { sessao = { chave, sal: salvo.sal, itens: await Cripto.decifrar(chave, salvo) }; }
      catch { throw new Error('Senha mestra incorreta.'); }
    }
    abrirCofre();
  } catch (err) {
    erro.textContent = err.message;
    $('#btn-trava').disabled = false; prepararTrava(); erro.textContent = err.message;
  }
  $('#btn-trava').disabled = false;
});

$('#apagar-cofre').addEventListener('click', (e) => {
  const b = e.currentTarget;
  if (!b.dataset.ok) { b.dataset.ok = '1'; b.textContent = 'Isso apaga todas as senhas salvas. Clique de novo para confirmar.'; return; }
  armazenamento.apagar(); delete b.dataset.ok; b.textContent = 'Esqueci a senha mestra (apagar cofre)';
  prepararTrava();
});

async function gravar() {
  const pacote = await Cripto.cifrar(sessao.chave, sessao.itens);
  armazenamento.salvar({ versao: 1, sal: sessao.sal, ...pacote });
}

function trancar() {
  sessao = null; clearTimeout(timerTrava);
  if ($('#modal').open) $('#modal').close();
  $('#lista').innerHTML = '';
  prepararTrava();
}
$('#trancar').addEventListener('click', trancar);
function reiniciarTimer() { if (!sessao) return; clearTimeout(timerTrava); timerTrava = setTimeout(() => { trancar(); $('#erro-trava').textContent = 'Cofre trancado por inatividade.'; }, AUTO_TRAVA_MS); }
['click', 'keydown', 'mousemove', 'touchstart'].forEach((ev) => document.addEventListener(ev, reiniciarTimer, { passive: true }));

/* ---------- Cofre ---------- */
function abrirCofre() {
  $('#tela-trava').hidden = true; $('#tela-cofre').hidden = false;
  $('#busca').value = '';
  render(); atualizarGerador(); reiniciarTimer();
}

function iniciais(nome) { return nome.trim().split(/\s+/).slice(0, 2).map((p) => p[0]).join('').toUpperCase(); }
function corDe(nome) { let h = 0; for (const c of nome) h = (h * 31 + c.charCodeAt(0)) % 360; return `hsl(${h} 55% 45%)`; }

function render() {
  const termo = $('#busca').value.trim().toLowerCase();
  const itens = sessao.itens
    .filter((i) => !termo || [i.site, i.usuario, i.url, i.notas].some((c) => c.toLowerCase().includes(termo)))
    .sort((a, b) => a.site.localeCompare(b.site, 'pt-BR'));

  const contagem = {}; sessao.itens.forEach((i) => { contagem[i.senha] = (contagem[i.senha] || 0) + 1; });
  const fracas = sessao.itens.filter((i) => forca(i.senha).pct <= 25).length;
  const repetidas = sessao.itens.filter((i) => contagem[i.senha] > 1).length;
  $('#resumo').innerHTML = `
    <div><b>${sessao.itens.length}</b><span>credenciais</span></div>
    <div class="${fracas ? 'alerta' : ''}"><b>${fracas}</b><span>senhas fracas</span></div>
    <div class="${repetidas ? 'alerta' : ''}"><b>${repetidas}</b><span>senhas repetidas</span></div>`;

  $('#lista').innerHTML = itens.length ? itens.map((i) => {
    const f = forca(i.senha);
    return `<li class="item" data-id="${i.id}">
      <span class="avatar" style="background:${corDe(i.site)}">${escapar(iniciais(i.site))}</span>
      <div class="item__info">
        <b>${escapar(i.site)}</b>
        <span>${escapar(i.usuario)}</span>
        <code class="senha" data-oculta="1">••••••••••</code>
        <span class="selo" style="--cor:${f.cor}">${f.nome}${contagem[i.senha] > 1 ? ' · repetida' : ''}</span>
      </div>
      <div class="item__acoes">
        <button class="mini" data-acao="ver">Mostrar</button>
        <button class="mini" data-acao="usuario">Copiar usuário</button>
        <button class="mini mini--forte" data-acao="senha">Copiar senha</button>
        <button class="mini" data-acao="editar">Editar</button>
      </div>
    </li>`;
  }).join('') : `<li class="vazio">${termo ? 'Nenhuma credencial encontrada.' : 'Seu cofre está vazio. Clique em “+ Nova credencial” para guardar a primeira senha.'}</li>`;
}
$('#busca').addEventListener('input', render);

$('#lista').addEventListener('click', (e) => {
  const b = e.target.closest('[data-acao]'); if (!b) return;
  const li = b.closest('.item');
  const item = sessao.itens.find((i) => i.id === Number(li.dataset.id));
  const acao = b.dataset.acao;
  if (acao === 'ver') {
    const code = li.querySelector('.senha');
    const oculta = code.dataset.oculta === '1';
    code.textContent = oculta ? item.senha : '••••••••••';
    code.dataset.oculta = oculta ? '0' : '1';
    b.textContent = oculta ? 'Ocultar' : 'Mostrar';
  }
  if (acao === 'usuario') copiar(item.usuario, 'Usuário copiado');
  if (acao === 'senha') copiar(item.senha, 'Senha copiada');
  if (acao === 'editar') abrirModal(item);
});

async function copiar(texto, msg) {
  try { await navigator.clipboard.writeText(texto); toast(msg); }
  catch { toast('Não foi possível copiar neste navegador'); }
}
let timerToast;
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.hidden = false;
  clearTimeout(timerToast); timerToast = setTimeout(() => { t.hidden = true; }, 2200);
}

/* ---------- Modal ---------- */
function abrirModal(item) {
  editando = item ? item.id : null;
  $('#modal-titulo').textContent = item ? 'Editar credencial' : 'Nova credencial';
  $('#f-site').value = item?.site || ''; $('#f-url').value = item?.url || '';
  $('#f-usuario').value = item?.usuario || ''; $('#f-senha').value = item?.senha || '';
  $('#f-notas').value = item?.notas || '';
  $('#f-senha').type = 'password'; $('#f-ver').textContent = 'Mostrar';
  $('#f-excluir').hidden = !item; delete $('#f-excluir').dataset.ok; $('#f-excluir').textContent = 'Excluir';
  $('#erro').textContent = '';
  pintarMedidor($('#medidor-form'), $('#f-senha').value);
  $('#modal').showModal(); $('#f-site').focus();
}
$('#nova').addEventListener('click', () => abrirModal());
$('#f-cancelar').addEventListener('click', () => $('#modal').close());
$('#f-ver').addEventListener('click', () => {
  const v = $('#f-senha').type === 'password';
  $('#f-senha').type = v ? 'text' : 'password'; $('#f-ver').textContent = v ? 'Ocultar' : 'Mostrar';
});
$('#f-gerar').addEventListener('click', () => {
  $('#f-senha').value = gerarSenha(); $('#f-senha').type = 'text'; $('#f-ver').textContent = 'Ocultar';
  pintarMedidor($('#medidor-form'), $('#f-senha').value);
});
$('#f-senha').addEventListener('input', () => pintarMedidor($('#medidor-form'), $('#f-senha').value));

$('#form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const dados = { site: $('#f-site').value.trim(), url: $('#f-url').value.trim(), usuario: $('#f-usuario').value.trim(), senha: $('#f-senha').value, notas: $('#f-notas').value.trim() };
  if (!dados.site || !dados.usuario || !dados.senha) return ($('#erro').textContent = 'Preencha site, usuário e senha.');
  if (editando) Object.assign(sessao.itens.find((i) => i.id === editando), dados, { atualizado: Date.now() });
  else sessao.itens.push({ id: Date.now(), ...dados, criado: Date.now() });
  await gravar();
  $('#modal').close(); render(); toast('Credencial salva e criptografada');
});

$('#f-excluir').addEventListener('click', async (e) => {
  const b = e.currentTarget;
  if (!b.dataset.ok) { b.dataset.ok = '1'; b.textContent = 'Confirmar exclusão'; return; }
  sessao.itens = sessao.itens.filter((i) => i.id !== editando);
  await gravar(); $('#modal').close(); render(); toast('Credencial excluída');
});

if (!window.crypto?.subtle) {
  $('#erro-trava').textContent = 'Este navegador não oferece criptografia segura aqui. Abra o site por HTTPS.';
  $('#btn-trava').disabled = true;
}
prepararTrava();
