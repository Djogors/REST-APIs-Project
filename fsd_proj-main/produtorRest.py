import json
from flask import Flask, jsonify, request
import requests
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
#Enviar dados para o Gestor de Produtos
URL = "http://193.136.11.170:5001"
URL2 = "http://127.0.0.1:6666"


#Funcao generate stock
def generate_stock():
    # Definir as categorias fixas para cada item
    categories = {
        'morangos': 'fruta',
        'martelos': 'ferramentas',
        'maçãs': 'fruta',
        'pêras': 'fruta',
        'serras': 'ferramentas',
    }

    items = list(categories.items())
    
    # Selecionar um número aleatório de itens
    num_items = random.randint(1, len(categories))

    selected_items = random.sample(items, num_items)
    
    # Criar o dicionário final com quantidades e preços aleatórios
    stock = {}
    
    for item, category in selected_items:
        # Gerar quantidade aleatória entre 50 e 500 kg
        qtty = random.randint(50, 500)
        # Gerar preço aleatório entre 1.00 e 10.00 euros
        price = round(random.uniform(1.00, 10.00), 2)
        # Adicionar ao dicionário com chave 'quantidade', 'preco' e 'categoria'
        stock[item] = {
            "quantidade": qtty,
            "preco": price,
            "categoria": category
        }
    
    return stock

# Stock inicial
stock = generate_stock()

#Generate key for producer
def generate_key():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,  # You can use 2048, 3072, or 4096 bits
    )

    # Extract public key from the private key
    public_key = private_key.public_key()
    # Conver the key to PEM e decode to utf-8
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,  # Or PKCS8, depending on your requirement
    encryption_algorithm=serialization.NoEncryption()       # Use NoEncryption() for an unencrypted PEM
    ).decode('utf-8')

    save_priv_key_producer(private_key_pem)

    return public_key_pem

#Ler a chave do produtor 
def save_priv_key_producer(priv_key):
    with open("priv_key_producer.pem", "w") as cert_file: cert_file.write(priv_key)

# Save certificate as a file do produtor
def save_certificate(cert_pem):
    with open("certificate_producer.pem", "w") as cert_file: cert_file.write(cert_pem)

 # read certificate gestor
def read_certificate():
    with open("certificate_producer.pem", "rb") as cert_file:
        data = cert_file.read()
        certificate_data = data.decode('utf-8') # Converter para utf-8 
    return certificate_data

#Read the private key for digital signature
def read_priv_key_prod():
   with open("priv_key_producer.pem", "rb") as cert_file:
        private_key = load_pem_private_key(cert_file.read(), password=None, backend=default_backend())
   return private_key

# Método para registar o produtor
def register_producer():
    public_key_pem = generate_key()

    response = requests.post(URL+"/produtor_certificado", json={
            "ip":"127.0.0.1",
            "porta": 6666,
            "nome":"ProdutorGOAT",
            "pubKey": public_key_pem
        })
    print("Registo no gestor:", response.status_code)

    cert_pem = response.text  # Guardar o certificado
    save_certificate(cert_pem)
    
# Listar categorias do produtor
@app.route('/categorias', methods=['GET'])
def get_categories():
    categories = set(item["categoria"] for item in stock.values())
    return jsonify(list(categories))

# Listar os produtos de uma categoria do produtor, "/produtos" da autofill para /produtos?categoria=[{categoria}]
@app.route('/produtos', methods=['GET'])
def get_produtos_categoria():
    
    categoria = request.args.get('categoria')
    
    if not categoria:
        return "1: Categoria Inexistente", 404
    
    produtos = []
    for produto, info in stock.items():
        if info["categoria"].lower() in categoria.lower():
            produtos.append({
                "categoria": info["categoria"],
                "produto": produto,
                "quantidade": info["quantidade"],
                "preco": info["preco"]
            })
    
    if not produtos:
        return "1: Categoria Inexistente", 404
        
    return jsonify(produtos)

@app.route('/secure/produtos', methods=['GET'])
def get_produtos_categoria_secure():
    
    categoria = request.args.get('categoria')
    
    if not categoria:
        return "1: Categoria Inexistente", 404
    
    produtos = []
    for produto, info in stock.items():
        if info["categoria"].lower() in categoria.lower():
            produtos.append({
                "categoria": info["categoria"],
                "preco": info["preco"],
                "produto": produto,
                "quantidade": info["quantidade"],         
            })

    signed_data_json = json.dumps(list(produtos))
    data_bytes = signed_data_json.encode('utf-8') # converter para bytes

    certificate = read_certificate()
    priv_key = read_priv_key_prod() 

    #Assinar a msg, precisamos de converter a msg para bytes com algoritm RSA
    signature = priv_key.sign(
        data_bytes,
        padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
    hashes.SHA256()
    )

    assinado = signature.decode('cp437')

    payload = {
        "assinatura": assinado,
        "certificado": certificate,
        "mensagem": list(produtos)
    }

    if not produtos:
        return "1: Categoria Inexistente", 404

    return jsonify(payload)

# Comprar produtos quando os outros grupos pedirem ou nos pedirmos ao nosso produtor registado
@app.route('/comprar/<produto>/<int:quantidade>', methods=['GET'])
def buy_product(produto, quantidade):
        
        if produto not in stock:
            return "1: Produto inexistente", 404
            
        if quantidade <= 0 or quantidade > stock[produto]["quantidade"]:
            return "2: Quantidade indisponível", 404
            
        # Atualiza o estoque
        stock[produto]["quantidade"] -= quantidade
        return "Compra realizada com sucesso", 200

@app.route('/secure/comprar/<produto>/<int:quantidade>', methods=['POST'])
def buy_product_secure(produto, quantidade):
        
        certificate = read_certificate()
        priv_key = read_priv_key_prod()

        if produto not in stock:
            return "1: Produto inexistente", 404
            
        if quantidade <= 0 or quantidade > stock[produto]["quantidade"]:
            return "2: Quantidade indisponível", 404
            
        # Atualiza o estoque
        stock[produto]["quantidade"] -= quantidade
        
        produtos = []
        produtos.append({
            "categoria": produto,
            "quantidade": quantidade       
        })

        signed_data_json = json.dumps(produtos)
        data_bytes = signed_data_json.encode('utf-8') # converter para bytes

        #Assinar a msg, precisamos de converter a msg para bytes com algoritm RSA
        signature = priv_key.sign(
                data_bytes,
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
        )
       
        assinado = signature.decode('cp437')

        payload = {
            "assinatura": assinado,
            "certificado": certificate,
            "mensagem": list(produtos)
            }
        return jsonify(payload)
        

@app.route('/secure/categorias', methods=['GET'])
def listar_category_secure():
    categories = set(item["categoria"] for item in stock.values())
    signed_data_json = json.dumps(list(categories))
    data_bytes = signed_data_json.encode('utf-8') # converter para bytes

    certificate = read_certificate()
    priv_key = read_priv_key_prod() 

    #Assinar a msg, precisamos de converter a msg para bytes com algoritm RSA
    signature = priv_key.sign(
        data_bytes,
        padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
    hashes.SHA256()
    )

    assinado = signature.decode('cp437')

    payload = {
        "assinatura": assinado,
        "certificado": certificate,
        "mensagem": list(categories)
    }

    return jsonify(payload)


# Ligar o servidor
if __name__ == '__main__':
    register_producer() # Registar produtor
    app.run(host="127.0.0.1", port=6666, debug=True)