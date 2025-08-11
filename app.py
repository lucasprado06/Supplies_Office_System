from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file
from functools import wraps
from openpyxl import Workbook
import io
import json
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'

# --- Funções de Carregamento e Salvamento de Dados ---
def carregar_dados(caminho_arquivo, default_data):
    os.makedirs(os.path.dirname(caminho_arquivo), exist_ok=True)
    if not os.path.exists(caminho_arquivo) or os.path.getsize(caminho_arquivo) == 0:
        with open(caminho_arquivo, 'w', encoding='utf-8') as f:
            json.dump(default_data, f)
    with open(caminho_arquivo, 'r', encoding='utf-8') as f:
        return json.load(f)

def salvar_dados(caminho_arquivo, data):
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

# --- Decoradores de Autenticação e Autorização ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Por favor, faça login para acessar esta página.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session['user']['permissao'] != 'administrador':
            flash('Você não tem permissão para acessar esta página.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Rotas do Aplicativo ---
@app.route('/')
def home():
    if 'user' in session:
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

        if user and user['senha'] == senha:
            session['user'] = user
            
            if user['permissao'] == 'administrador':
                return redirect(url_for('pendentes'))
            else:
                return redirect(url_for('historico'))
        else:
            flash('Registro ou senha incorretos!', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/pendentes')
@login_required
@admin_required
def pendentes():
    requisicoes = carregar_requisicoes()
    pendentes_list = [r for r in requisicoes if r['status'] == 'pendente']
    return render_template('pendentes.html', requisicoes=pendentes_list)

@app.route('/separados')
@login_required
def separados():
    requisicoes = carregar_requisicoes()
    requisicoes_separadas = [r for r in requisicoes if r['status'] == 'separado']
    return render_template('separados.html', requisicoes=requisicoes_separadas)

@app.route('/separados_detalhes/<int:requisicao_id>')
@login_required
@admin_required
def separados_detalhes(requisicao_id):
    requisicoes = carregar_requisicoes()
    requisicao = next((r for r in requisicoes if r['id'] == requisicao_id), None)
    
    if not requisicao or requisicao['status'] != 'separado':
        flash('Requisição não encontrada ou não está no status "separado".', 'danger')
        return redirect(url_for('separados'))
        
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

@app.route('/concluir_requisicao', methods=['POST'])
@login_required
@admin_required
def concluir_requisicao():
    requisicao_id = request.form.get('requisicao_id')
    data_retirada_str = request.form.get('data_retirada')
    
    # Converte a string de data (YYYY-MM-DD) para o formato brasileiro (DD/MM/YYYY)
    if data_retirada_str:
        try:
            data_retirada_obj = datetime.strptime(data_retirada_str, '%Y-%m-%d')
            data_retirada_formatada = data_retirada_obj.strftime('%d/%m/%Y')
        except ValueError:
            data_retirada_formatada = data_retirada_str
    else:
        data_retirada_formatada = '-'

    requisicoes = carregar_requisicoes()
    for r in requisicoes:
        if r['id'] == int(requisicao_id):
            r['status'] = 'separado'
            r['data_retirada'] = data_retirada_formatada
            for item in r['itens']:
                quantidade_separada = request.form.get(f'quantidade_separada_{item["codigo"]}')
                if quantidade_separada is not None:
                    item['quantidade_separada'] = int(quantidade_separada)
            break
    salvar_requisicoes(requisicoes)
    
    flash('Requisição marcada como separada.', 'success')
    return redirect(url_for('pendentes'))

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
    
    if session['user']['permissao'] == 'administrador':
        requisicoes_a_exibir = requisicoes
    else:
        registro_usuario = session['user']['registro']
        requisicoes_a_exibir = [
            req for req in requisicoes
            if req['registro'] == registro_usuario and req['status'] != 'concluida'
        ]
    return render_template('historico.html', requisicoes=requisicoes_a_exibir)

@app.route('/historico_detalhes/<int:requisicao_id>')
@login_required
def historico_detalhes(requisicao_id):
    requisicoes = carregar_requisicoes()
    requisicao = next((r for r in requisicoes if r['id'] == requisicao_id), None)
    
    if not requisicao:
        flash('Requisição não encontrada.', 'danger')
        return redirect(url_for('historico'))
        
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
@login_required
@admin_required
def cadastro():
    return render_template('cadastro.html')

@app.route('/cadastrar_usuario', methods=['POST'])
@login_required
@admin_required
def cadastrar_usuario():
    nome = request.form.get('nome')
    registro = request.form.get('registro')
    departamento = request.form.get('departamento')
    senha = request.form.get('senha')
    confirmar_senha = request.form.get('confirmar_senha')
    permissao = request.form.get('permissao')

    # Validação de senhas
    if senha != confirmar_senha:
        flash('A senha e a confirmação de senha não coincidem.', 'danger')
        return redirect(url_for('cadastro'))

    usuarios = carregar_usuarios()
    
    if any(u['registro'] == registro for u in usuarios):
        flash(f'O registro {registro} já está em uso.', 'danger')
        return redirect(url_for('cadastro'))

    novo_usuario = {
        'nome': nome,
        'registro': registro,
        'departamento': departamento,
        'senha': senha,
        'permissao': permissao
    }
    usuarios.append(novo_usuario)
    salvar_usuarios(usuarios)
    
    flash(f'Usuário {nome} cadastrado com sucesso!', 'success')
    return redirect(url_for('gerenciar_usuarios'))
    
@app.route('/gerenciar_usuarios')
@login_required
@admin_required
def gerenciar_usuarios():
    usuarios = carregar_usuarios()
    return render_template('gerenciar_usuarios.html', usuarios=usuarios)

@app.route('/trocar_senha', methods=['GET', 'POST'])
@login_required
def trocar_senha():
    if request.method == 'POST':
        senha_atual = request.form.get('senha_atual')
        nova_senha = request.form.get('nova_senha')
        confirmar_nova_senha = request.form.get('confirmar_nova_senha')

        usuarios = carregar_usuarios()
        registro_usuario_logado = session['user']['registro']
        
        usuario_encontrado = next((u for u in usuarios if u['registro'] == registro_usuario_logado), None)

        if usuario_encontrado and usuario_encontrado['senha'] == senha_atual:
            if nova_senha == confirmar_nova_senha:
                if len(nova_senha) >= 8:
                    usuario_encontrado['senha'] = nova_senha
                    salvar_usuarios(usuarios)
                    session['user']['senha'] = nova_senha
                    flash('Sua senha foi alterada com sucesso!', 'success')
                    return redirect(url_for('historico'))
                else:
                    flash('A nova senha deve ter no mínimo 8 caracteres.', 'danger')
            else:
                flash('As novas senhas não coincidem.', 'danger')
        else:
            flash('A senha atual está incorreta.', 'danger')

    return render_template('trocar_senha.html')

@app.route('/exportar_historico_excel')
@login_required
@admin_required
def exportar_historico_excel():
    requisicoes = carregar_requisicoes()

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Histórico de Requisições"

    headers = ["ID", "Data da Requisição", "Status", "Solicitante", "Departamento", "Descrição do Item", "Quantidade Solicitada", "Quantidade Separada", "Data de Retirada", "Data de Conclusão"]
    sheet.append(headers)

    for r in requisicoes:
        data_requisicao = r.get('data', '-')
        data_retirada = r.get('data_retirada', '-')
        data_conclusao = r.get('data_conclusao', '-')
        
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
                data_conclusao
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