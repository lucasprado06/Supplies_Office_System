from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file
from functools import wraps
from openpyxl import Workbook
import io
import json
from datetime import datetime
import os
import secrets
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Use uma chave secreta mais segura e configurável
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# --- Funções de Carregamento e Salvamento de Dados ---
def carregar_dados(caminho_arquivo, default_data):
    """
    Carrega dados de um arquivo JSON. Se o arquivo não existir ou estiver vazio,
    cria-o com os dados padrão e retorna os dados padrão.
    """
    os.makedirs(os.path.dirname(caminho_arquivo), exist_ok=True)
    
    if not os.path.exists(caminho_arquivo) or os.path.getsize(caminho_arquivo) == 0:
        with open(caminho_arquivo, 'w', encoding='utf-8') as f:
            json.dump(default_data, f, indent=4)
        return default_data
    
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Aviso: Arquivo {caminho_arquivo} está corrompido. Criando um novo.")
        with open(caminho_arquivo, 'w', encoding='utf-8') as f:
            json.dump(default_data, f, indent=4)
        return default_data

def salvar_dados(caminho_arquivo, data):
    """Salva dados em um arquivo JSON."""
    with open(caminho_arquivo, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def carregar_usuarios():
    return carregar_dados('data/usuarios.json', [])

def salvar_usuarios(usuarios):
    salvar_dados('data/usuarios.json', usuarios)

def carregar_materiais():
    return carregar_dados('data/materiais.json', [])

def salvar_materiais(materiais):
    salvar_dados('data/materiais.json', materiais)

def carregar_requisicoes():
    return carregar_dados('data/requisicoes.json', [])

def salvar_requisicoes(requisicoes):
    salvar_dados('data/requisicoes.json', requisicoes)

# --- Funções de Validação e Segurança ---
def validar_senha(senha):
    if len(senha) < 8:
        return 'A senha deve ter no mínimo 8 caracteres.'
    if not re.search(r'[A-Z]', senha):
        return 'A senha deve conter pelo menos uma letra maiúscula.'
    if not re.search(r'[a-z]', senha):
        return 'A senha deve conter pelo menos uma letra minúscula.'
    if not re.search(r'[0-9]', senha):
        return 'A senha deve conter pelo menos um número.'
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?`~|\\ ]', senha):
        return 'A senha deve conter pelo menos um caractere especial.'
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session['user']['permissao'] != 'administrador':
            flash('Você não tem permissão para acessar esta página.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- Rotas do Aplicativo ---
@app.route('/')
def home():
    if 'user' in session:
        if session['user'].get('forcar_troca_senha', False):
            flash('Por favor, defina uma nova senha.', 'info')
            return redirect(url_for('trocar_senha'))
        
        if session['user']['permissao'] == 'administrador':
            return redirect(url_for('pendentes'))
        else:
            return redirect(url_for('historico'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        registro = request.form.get('registro')
        senha = request.form.get('senha')
        
        users = carregar_usuarios()
        user = next((u for u in users if u['registro'] == registro), None)

        if user and check_password_hash(user['senha_hash'], senha):
            session['user'] = {
                'nome': user['nome'],
                'registro': user['registro'],
                'departamento': user['departamento'],
                'permissao': user['permissao'],
                'forcar_troca_senha': user.get('forcar_troca_senha', False)
            }
            if session['user'].get('forcar_troca_senha', False):
                flash('Por favor, defina uma nova senha para continuar.', 'info')
                return redirect(url_for('trocar_senha'))
            
            if user['permissao'] == 'administrador':
                return redirect(url_for('pendentes'))
            else:
                return redirect(url_for('historico'))
        
        flash('Registro ou senha incorretos!', 'danger')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Você foi desconectado com sucesso.', 'success')
    return redirect(url_for('login'))

@app.route('/trocar_senha', methods=['GET', 'POST'])
@login_required
def trocar_senha():
    if not session['user'].get('forcar_troca_senha', False):
        flash('Você não precisa trocar sua senha no momento.', 'success')
        return redirect(url_for('home'))

    if request.method == 'POST':
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')
        
        erro_senha = validar_senha(nova_senha)
        if erro_senha:
            flash(erro_senha, 'danger')
            return redirect(url_for('trocar_senha'))

        if nova_senha != confirmar_senha:
            flash('A nova senha e a confirmação de senha não coincidem.', 'danger')
            return redirect(url_for('trocar_senha'))
        
        usuarios = carregar_usuarios()
        for user in usuarios:
            if user['registro'] == session['user']['registro']:
                user['senha_hash'] = generate_password_hash(nova_senha)
                user['forcar_troca_senha'] = False
                session['user']['forcar_troca_senha'] = False
                break
        salvar_usuarios(usuarios)
        
        flash('Sua senha foi atualizada com sucesso!', 'success')
        return redirect(url_for('home'))

    return render_template('trocar_senha.html')

@app.route('/pendentes')
@login_required
@admin_required
def pendentes():
    requisicoes = carregar_requisicoes()
    
    for r in requisicoes:
        if isinstance(r.get('data'), str):
            r['data'] = datetime.strptime(r['data'], '%d/%m/%Y %H:%M')
            
    pendentes_list = [r for r in requisicoes if r.get('status') == 'pendente']
    
    return render_template('pendentes.html', requisicoes=pendentes_list)

# app.py

# app.py

@app.route('/requisicoes/<int:requisicao_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def ver_requisicao(requisicao_id):
    requisicoes = carregar_requisicoes()
    
    requisicao = next((r for r in requisicoes if r.get('id') == requisicao_id), None)
    
    if not requisicao:
        flash('Requisição não encontrada.', 'danger')
        return redirect(url_for('pendentes'))
    
    if request.method == 'POST':
        # Bloco para requisições POST (submissão do formulário)
        if requisicao.get('status') != 'pendente':
            flash('Esta requisição já foi processada.', 'warning')
            return redirect(url_for('pendentes'))

        observacao = request.form.get('observacao', '')
        data_retirada_str = request.form.get('data_retirada')
        
        if data_retirada_str:
            try:
                data_retirada_obj = datetime.strptime(data_retirada_str, '%Y-%m-%d')
                data_retirada_formatada = data_retirada_obj.strftime('%d/%m/%Y')
            except ValueError:
                data_retirada_formatada = data_retirada_str
        else:
            data_retirada_formatada = '-'

        requisicao['status'] = 'separado'
        requisicao['data_retirada'] = data_retirada_formatada
        requisicao['observacao'] = observacao
        
        for item in requisicao['itens']:
            quantidade_separada = request.form.get(f'quantidade_separada_{item["codigo"]}')
            if quantidade_separada is not None:
                item['quantidade_separada'] = int(quantidade_separada)
                
        salvar_requisicoes(requisicoes)
        flash('Requisição marcada como separada.', 'success')
        return redirect(url_for('pendentes'))

    # Bloco para requisições GET (exibição da página)
    else: # O `else` aqui é crucial para garantir que a função sempre retorne um template
        if isinstance(requisicao.get('data'), str):
            requisicao['data'] = datetime.strptime(requisicao['data'], '%d/%m/%Y %H:%M')
    
        return render_template('ver_requisicao.html', requisicao=requisicao)
@app.route('/separados')
@login_required
def separados():
    requisicoes = carregar_requisicoes()
    
    for r in requisicoes:
        if isinstance(r.get('data'), str):
            r['data'] = datetime.strptime(r['data'], '%d/%m/%Y %H:%M')
    
    separados_list = [r for r in requisicoes if r.get('status') == 'separado']
    
    return render_template('separados.html', requisicoes=separados_list)

# app.py

@app.route('/separados_detalhes/<int:requisicao_id>')
@login_required
@admin_required
def separados_detalhes(requisicao_id):
    requisicoes = carregar_requisicoes()
    requisicao = next((r for r in requisicoes if r.get('id') == requisicao_id), None)
    
    if not requisicao or requisicao.get('status') != 'separado':
        flash('Requisição não encontrada ou não está no status "separado".', 'danger')
        return redirect(url_for('separados'))
    
    # Adicione este bloco para converter a string de data em objeto datetime
    if isinstance(requisicao.get('data'), str):
        requisicao['data'] = datetime.strptime(requisicao['data'], '%d/%m/%Y %H:%M')
    
    return render_template('separados_detalhes.html', requisicao=requisicao)
@app.route('/enviar_requisicao', methods=['POST'])
@login_required
def enviar_requisicao():
    materiais_disponiveis = carregar_materiais()
    itens_requisicao = []

    for key, value in request.form.items():
        if key.startswith('materiais[') and key.endswith('][codigo]'):
            index = key.split('[')[1].split(']')[0]
            codigo_material = value
            quantidade = request.form.get(f'materiais[{index}][quantidade]')

            if not codigo_material or not quantidade:
                continue

            quantidade = int(quantidade)
            
            material_encontrado = next((m for m in materiais_disponiveis if m['codigo'] == codigo_material), None)
            
            if not material_encontrado:
                flash(f'Material com código {codigo_material} não encontrado.', 'danger')
                return redirect(url_for('fazer_requisicao'))

            if quantidade > material_encontrado['quantidade_maxima']:
                flash(f"A quantidade de '{material_encontrado['descricao']}' excede o limite de {material_encontrado['quantidade_maxima']} por requisição.", 'warning')
                return redirect(url_for('fazer_requisicao'))
            
            itens_requisicao.append({
                'codigo': codigo_material,
                'nome': material_encontrado['descricao'],
                'quantidade': quantidade
            })

    if not itens_requisicao:
        flash('Nenhum item foi adicionado à requisição.', 'warning')
        return redirect(url_for('fazer_requisicao'))

    requisicoes = carregar_requisicoes()
    
    nova_requisicao = {
        'id': len(requisicoes) + 1,
        'nome': session['user']['nome'],
        'registro': session['user']['registro'],
        'departamento': session['user']['departamento'],
        'data': datetime.now().strftime('%d/%m/%Y %H:%M'),
        'status': 'pendente',
        'itens': itens_requisicao
    }

    requisicoes.append(nova_requisicao)
    salvar_requisicoes(requisicoes)
    
    flash('Sua requisição foi enviada com sucesso e está pendente de aprovação!', 'success')
    return redirect(url_for('fazer_requisicao'))

@app.route('/finalizar_requisicao', methods=['POST'])
@login_required
@admin_required
def finalizar_requisicao():
    requisicao_id = request.form.get('requisicao_id')
    
    requisicoes = carregar_requisicoes()
    for r in requisicoes:
        if r['id'] == int(requisicao_id):
            r['status'] = 'concluida'
            r['data_conclusao'] = datetime.now().strftime('%d/%m/%Y %H:%M')
            break
    salvar_requisicoes(requisicoes)
    
    flash('Requisição finalizada e movida para o histórico.', 'success')
    return redirect(url_for('separados'))

@app.route('/excluir_usuario', methods=['POST'])
@login_required
@admin_required
def excluir_usuario():
    registro_usuario_excluir = request.form.get('registro_usuario')
    registro_usuario_logado = session['user']['registro']

    if registro_usuario_excluir == registro_usuario_logado:
        flash('Você não pode excluir a si mesmo.', 'warning')
        return redirect(url_for('gerenciar_usuarios'))

    usuarios = carregar_usuarios()
    usuarios_atualizados = [u for u in usuarios if u['registro'] != registro_usuario_excluir]
    salvar_usuarios(usuarios_atualizados)
    
    flash(f'Usuário com registro {registro_usuario_excluir} excluído com sucesso.', 'success')
    return redirect(url_for('gerenciar_usuarios'))

@app.route('/fazer_requisicao')
@login_required
def fazer_requisicao():
    materiais = carregar_materiais()
    return render_template('fazer_requisicao.html', materiais=materiais)

@app.route('/historico')
@login_required
def historico():
    requisicoes = carregar_requisicoes()
    
    # Adicione este loop para verificar o status de cada requisição
    print("\n--- Verificando Status das Requisições ---")
    for r in requisicoes:
        print(f"ID: {r.get('id')}, Status: {r.get('status')}, Solicitante: {r.get('nome')}")
        if isinstance(r.get('data'), str):
            r['data'] = datetime.strptime(r['data'], '%d/%m/%Y %H:%M')
    print("-------------------------------------------\n")

    if session['user']['permissao'] == 'administrador':
        requisicoes_a_exibir = requisicoes
    else:
        registro_usuario = session['user']['registro']
        requisicoes_a_exibir = [
            req for req in requisicoes
            if req.get('registro') == registro_usuario and req.get('status') != 'concluida'
        ]
        
    return render_template('historico.html', requisicoes=requisicoes_a_exibir)

@app.route('/historico_detalhes/<int:requisicao_id>')
@login_required
def historico_detalhes(requisicao_id):
    requisicoes = carregar_requisicoes()
    requisicao = next((r for r in requisicoes if r.get('id') == requisicao_id), None)
    
    if not requisicao:
        flash('Requisição não encontrada.', 'danger')
        return redirect(url_for('historico'))
    
    # Adicione a lógica de conversão de string para objeto datetime aqui
    if isinstance(requisicao.get('data'), str):
        requisicao['data'] = datetime.strptime(requisicao['data'], '%d/%m/%Y %H:%M')
    
    return render_template('historico_detalhes.html', requisicao=requisicao)
@app.route('/excluir_requisicao/<int:requisicao_id>', methods=['POST'])
@login_required
def excluir_requisicao(requisicao_id):
    requisicoes = carregar_requisicoes()
    requisicao_para_excluir = next((req for req in requisicoes if req['id'] == requisicao_id), None)
    
    if requisicao_para_excluir:
        registro_usuario = session['user']['registro']
        if requisicao_para_excluir['registro'] == registro_usuario and requisicao_para_excluir['status'] == 'pendente':
            requisicoes.remove(requisicao_para_excluir)
            salvar_requisicoes(requisicoes)
            flash('Requisição excluída com sucesso!', 'success')
        else:
            flash('Você não pode excluir esta requisição.', 'danger')
    else:
        flash('Requisição não encontrada.', 'danger')

    return redirect(url_for('historico'))

@app.route('/gerenciar_materiais', methods=['GET', 'POST'])
@login_required
@admin_required
def gerenciar_materiais():
    if request.method == 'POST':
        codigo = request.form.get('codigo')
        descricao = request.form.get('descricao')
        quantidade_maxima = request.form.get('quantidade_maxima')

        materiais = carregar_materiais()
        novo_material = {
            "codigo": codigo,
            "descricao": descricao,
            "quantidade_maxima": int(quantidade_maxima)
        }
        materiais.append(novo_material)
        salvar_materiais(materiais)
        flash('Material adicionado com sucesso!', 'success')
        return redirect(url_for('gerenciar_materiais'))
        
    materiais = carregar_materiais()
    return render_template('gerenciar_materiais.html', materiais=materiais)

@app.route('/editar_material', methods=['POST'])
@login_required
@admin_required
def editar_material():
    codigo = request.form.get('codigo_editar')
    nova_descricao = request.form.get('descricao_editar')
    nova_quantidade_maxima = request.form.get('quantidade_maxima_editar')

    materiais = carregar_materiais()
    for material in materiais:
        if material['codigo'] == codigo:
            material['descricao'] = nova_descricao
            material['quantidade_maxima'] = int(nova_quantidade_maxima)
            break
    
    salvar_materiais(materiais)
    flash(f'Material "{nova_descricao}" atualizado com sucesso!', 'success')
    return redirect(url_for('gerenciar_materiais'))

@app.route('/excluir_material', methods=['POST'])
@login_required
@admin_required
def excluir_material():
    codigo_material_excluir = request.form.get('codigo_material')
    materiais = carregar_materiais()
    
    materiais_atualizados = [m for m in materiais if m['codigo'] != codigo_material_excluir]
    
    salvar_materiais(materiais_atualizados)
    flash('Material excluído com sucesso!', 'success')
    return redirect(url_for('gerenciar_materiais'))

@app.route('/exportar_materiais_excel')
@login_required
@admin_required
def exportar_materiais_excel():
    materiais = carregar_materiais()

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Lista de Materiais"

    headers = ["Código", "Descrição", "Quantidade Máxima"]
    sheet.append(headers)

    for material in materiais:
        row_data = [
            material.get('codigo'),
            material.get('descricao'),
            material.get('quantidade_maxima')
        ]
        sheet.append(row_data)

    excel_file = io.BytesIO()
    workbook.save(excel_file)
    excel_file.seek(0)
    
    return send_file(
        excel_file,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='lista_de_materiais.xlsx'
    )

@app.route('/cadastro')
def cadastro():
    usuarios = carregar_usuarios()
    if not usuarios:
        return render_template('cadastro.html')
    
    if 'user' in session and session['user']['permissao'] == 'administrador':
        return render_template('cadastro.html')
    else:
        flash('Você não tem permissão para acessar a página de cadastro.', 'danger')
        return redirect(url_for('login'))

@app.route('/cadastrar_usuario', methods=['POST'])
def cadastrar_usuario():
    usuarios = carregar_usuarios()
    
    nome = request.form.get('nome')
    registro = request.form.get('registro')
    departamento = request.form.get('departamento')
    senha = request.form.get('senha')
    confirmar_senha = request.form.get('confirmar_senha')
    
    if not all([nome, registro, departamento, senha, confirmar_senha]):
        flash('Todos os campos são obrigatórios.', 'danger')
        return redirect(url_for('cadastro'))

    erro_senha = validar_senha(senha)
    if erro_senha:
        flash(erro_senha, 'danger')
        return redirect(url_for('cadastro'))

    if senha != confirmar_senha:
        flash('A senha e a confirmação de senha não coincidem.', 'danger')
        return redirect(url_for('cadastro'))

    if any(u.get('registro') == registro for u in usuarios):
        flash(f'O registro {registro} já está em uso.', 'danger')
        return redirect(url_for('cadastro'))

    if not usuarios:
        permissao = 'administrador'
        forcar_troca_senha = False
    else:
        permissao = request.form.get('permissao', 'usuario')
        forcar_troca_senha = True

    novo_usuario = {
        'nome': nome,
        'registro': registro,
        'departamento': departamento,
        'senha_hash': generate_password_hash(senha),
        'permissao': permissao,
        'forcar_troca_senha': forcar_troca_senha
    }
    usuarios.append(novo_usuario)
    salvar_usuarios(usuarios)
    
    flash(f'Usuário {nome} cadastrado com sucesso!', 'success')
    return redirect(url_for('login'))
    
@app.route('/gerenciar_usuarios')
@login_required
@admin_required
def gerenciar_usuarios():
    usuarios = carregar_usuarios()
    return render_template('gerenciar_usuarios.html', usuarios=usuarios)

@app.route('/exportar_historico_excel')
@login_required
@admin_required
def exportar_historico_excel():
    requisicoes = carregar_requisicoes()

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Histórico de Requisições"

    headers = ["ID", "Data da Requisição", "Status", "Solicitante", "Departamento", "Descrição do Item", "Quantidade Solicitada", "Quantidade Separada", "Data de Retirada", "Data de Conclusão", "Observação"]
    sheet.append(headers)

    for r in requisicoes:
        data_requisicao = r.get('data', '-')
        data_retirada = r.get('data_retirada', '-')
        data_conclusao = r.get('data_conclusao', '-')
        observacao = r.get('observacao', '-')
        
        for item in r['itens']:
            row_data = [
                r.get('id'),
                data_requisicao,
                r.get('status'),
                r.get('nome'),
                r.get('departamento'),
                item.get('nome'),
                item.get('quantidade'),
                item.get('quantidade_separada'),
                data_retirada,
                data_conclusao,
                observacao
            ]
            sheet.append(row_data)

    excel_file = io.BytesIO()
    workbook.save(excel_file)
    excel_file.seek(0)
    
    return send_file(
        excel_file,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='historico_de_requisicoes.xlsx'
    )

if __name__ == '__main__':
    app.run(debug=True)