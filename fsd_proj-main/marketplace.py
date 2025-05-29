import base64
import json
import socket
import os
import sys
import time
import threading
import traceback
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography import x509


# Definição de constantes
BYTES = 1024
FORMAT = 'utf-8'
MAX_TRIES = 5
#URL = Local IP server from the university

refresh_event = threading.Event()

lock = threading.RLock()

threads_global = list()
category_list = dict()
stock = dict()

# Subscrições
subs = [
    ('Dole Food Company', ('127.0.0.1', 5050), ('fruta')),
    ('In n Out', ('127.32.1.1', 5051), ('fruta'))
]

available_producers = list()

def clear_screen():
    operating_system = sys.platform
    if operating_system == 'win32':
        os.system('cls')
    else:
        os.system('clear')

def create_socket():
    # Criação da socket
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def checking_producer(producer):
    try:
        # Try to create a socket connection
        with socket.create_connection(producer, timeout=1):
            if producer not in available_producers:
                available_producers.append(producer)
    except (socket.timeout, socket.error):
            if producer in available_producers:
                available_producers.remove(producer)

def periodical_checking(stop_event):
    while not stop_event.is_set():
        before = len(available_producers)
        for producer in subs:
            thread = threading.Thread(target=checking_producer, args=(producer[1],))
            thread.start()
        after = len(available_producers)
        # Se a lista tiver aumentado
        if before != after:
            refresh_event.set()
        time.sleep(2)

def summing(producer, request):
    global category_list
    try:
        marketplace = create_socket()
        marketplace.connect(producer)
    except (socket.timeout, socket.error):
        pass
    else:
        marketplace.send(request.encode(FORMAT))
        msg = marketplace.recv(BYTES).decode(FORMAT)
        # Não contém essa categoria
        if msg.startswith("0"):
            pass
        else:
            # produto1;;qtd;;preço-produto2;;qtd;;preço...
            byProduct = msg.split("-")
            for product in byProduct:
                if product != "":
                    byColumn = product.split(";;")
                    if byColumn[0] in category_list.keys():
                        with lock:
                            category_list[byColumn[0]] = (category_list[byColumn[0]][0] + int(byColumn[1]), category_list[byColumn[0]][1] + float(byColumn[2]))
                    else:
                        with lock:
                            category_list[byColumn[0]] = (int(byColumn[1]), float(byColumn[2]))
        marketplace.close()

#  Listar todos os Produtores publicos       
def listar_produtor_REST():
    response = requests.get(URL + "/produtor") 
    produtores = response.json()

    for produtor in produtores:
        nome = produtor['nome']
        ip = produtor['ip']
        porta = produtor['porta']
        seguro = produtor['secure']
        print(f"[{ip}:{porta}] {nome} {seguro}")

def read_manager_pub_key():
    with open("manager_public_key.pem", "rb") as cert_file: 
        public_key = load_pem_public_key(cert_file.read())
    return public_key

# Função para verificar a validade do certificado do produtor
def verify_certificate(certificate_str):
    try:
        # Carregar o certificado do produtor (em formato PEM)
        certificate = x509.load_pem_x509_certificate(certificate_str.encode('utf-8')) 
        # Carregar a chave pública do gestor
        manager_pub_key = read_manager_pub_key()

        # Verificar a assinatura do certificado usando a chave pública do gestor
        manager_pub_key.verify(
            certificate.signature,                  # Assinatura do certificado
            certificate.tbs_certificate_bytes,      # "To be signed" do certificado
            padding.PKCS1v15(),                     # Padding utilizado para a assinatura
            certificate.signature_hash_algorithm    # Algoritmo de hash usado para a assinatura
        )

        print("Certificado do produtor é válido.")
        return True
    except Exception as e:
        print("Falha na verificação do certificado do produtor:", e)
        return False
    
# Função para verificar a assinatura da mensagem do produtor
def verify_signature_and_message(certificate_str, signature_str, signed_data_str):
  
    try:
        #Como verifciar a assinatura ver se ta certo e como os vamos converter os string para bytes
        producer_public_key = x509.load_pem_x509_certificate(certificate_str.encode('utf-8')).public_key()
        
        #Transformar para bytes
        signature_bytes = signature_str.encode('cp437')

        if isinstance(signed_data_str, str):
            signed_data_bytes = signed_data_str.encode('utf-8')
        else:
            signed_data_json = json.dumps(signed_data_str)
            signed_data_bytes = signed_data_json.encode('utf-8')
        
        # Passo 5: Verificar a assinatura usando a chave pública do produtor
        producer_public_key.verify(
            signature_bytes,                       # Assinatura
            signed_data_bytes,                     # Dados originais
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()                        # Algoritmo de hash usado
        )

        print("Assinatura da mensagem é válida.")
        return True
    except Exception as e:
        print("Falha na verificação da assinatura da mensagem:", e)
        # traceback.print_exc()  ver erros se necessario
        return False


def read_certificate():
    # read certificate
    with open("certificate_producer.pem", "rb") as cert_file: cert_file.read()
    return cert_file

# Descobrir o url
def get_base_url():
    while True:
        ip = input("\nIntroduza um IP: ")
        port = input("Introduza uma porta: ")

        if port.isdigit() and 1 <= int(port) <= 65535 and ip:
            try:
                port = int(port)
                with socket.create_connection((ip, port), timeout=5):
                    print("Conexão bem-sucedida!")
                    return f"http://{ip}:{port}"
            except (socket.timeout, ConnectionRefusedError):
                print("Erro ao conectar ao produtor")
        else:
            print("Erro: A porta deve ser um número entre 1 e 65535.")
    

def listar_categorias(base_url):
    """Lists all categories available from the given base URL."""
    response = requests.get(f"{base_url}/categorias")
    if response.ok:
        categories = response.json()
        print("Categorias disponíveis:", categories)
        return categories
    else:
        print("Erro ao listar categorias:", response.status_code)
        return []

def listar_produto_categoria_rest():
    """Lists all products in a specified category."""
    base_url = get_base_url()
    categories = listar_categorias(base_url)
    
    if categories:
        categoria = input("Escolha uma categoria: ")
        if categoria in categories:
            response = requests.get(f"{base_url}/produtos?categoria={categoria}")
            
            if response.ok:
                produtos = response.json()
                print(f"\nProdutos na categoria '{categoria}':")
                
                # Format each product's details
                for produto in produtos:
                    nome = produto.get('produto', 'Desconhecido')
                    quantidade = produto.get('quantidade', 'N/A')
                    preco = produto.get('preco', 'N/A')
                    print(f"{nome.capitalize()} -> quantidade: {quantidade}; preço: {preco}€")
            else:
                print("Erro ao listar produtos:", response.status_code)
        else:
            print("Categoria não encontrada.")
    else:
        print("Nenhuma categoria disponível.")

def listar_categorias_secure(base_url):
    
    response = requests.get(f"{base_url}/secure/categorias")

    if response.ok:
        categories = response.json()

        data = response.json()  # Assuming the server responds with JSON
        
        # Retrieve individual components
        signature = data.get("assinatura")  # Digital signature string
        certificate = data.get("certificado")    # Digital certificate string
        mensagem = data.get("mensagem") # Lista
        
        verificar_1 = verify_certificate(certificate)
        verificar_2 = verify_signature_and_message(certificate,signature, mensagem)
        if verificar_1 and verificar_2:
            print("Categorias disponíveis:", categories)
            return categories
        else:

            print("Condições nao verificadas.")
    else:
        print("Erro ao listar categorias:", response.status_code)
        return []

def listar_produto_categoria_rest_secure():
    """Lists all products in a specified category."""
    base_url = get_base_url()
    categories = listar_categorias_secure(base_url)

    if categories:
        categoria = input("Escolha uma categoria: ")
        if categoria in categories["mensagem"]:
            response = requests.get(f"{base_url}/secure/produtos?categoria={categoria}")

            data = response.json()
            # Retrieve individual components
            signature = data.get("assinatura")  # Digital signature string
            certificate = data.get("certificado")    # Digital certificate string
            mensagem = data.get("mensagem")
        
            verificar_1 = verify_certificate(certificate)
            verificar_2 = verify_signature_and_message(certificate, signature, mensagem)
            
            if verificar_1 and verificar_2:
                if response.ok:
                    print(f"Assinatura: {signature}")
                    print(f"Certificado: {certificate}")
                    print(f"\nProdutos na categoria '{categoria}':")
                    # Format each product's details
                    for produto in mensagem:
                        nome = produto.get('produto', 'Desconhecido')
                        quantidade = produto.get('quantidade', 'N/A')
                        preco = produto.get('preco', 'N/A')
                        print(f"{nome.capitalize()} -> quantidade: {quantidade}; preço: {preco}€")
                    return base_url
                else:
                    print("Erro ao listar produtos:", response.status_code)
            else:
                print("Condições nao verificadas.")
        else:
            print("Categoria não encontrada.")
    else:
        print("Nenhuma categoria disponível.")

def comprar_produto_rest():
    """Handles the purchase of a specified product in a specified quantity."""
    base_url = get_base_url()
    categories = listar_categorias(base_url)
    
    if categories:
        # Loop until a valid category is selected
        while True:
            categoria = input("Escolha uma categoria: ")
            if categoria in categories:
                # Fetch products in the chosen category
                response = requests.get(f"{base_url}/produtos?categoria={categoria}")
                
                if response.ok:
                    produtos = response.json()
                    print(f"Produtos na categoria '{categoria}':")
                    
                    # Display products in the specified format
                    for produto in produtos:
                        nome = produto.get('produto', 'Desconhecido')
                        quantidade = produto.get('quantidade', 'N/A')
                        preco = produto.get('preco', 'N/A')
                        print(f"{nome} - quantidade: {quantidade}, preço: {preco}€")
                    
                    # Exit loop after displaying products
                    break
                else:
                    print("Erro ao listar produtos:", response.status_code)
            else:
                print("Categoria não encontrada ou inválida. Tente novamente.")
        
        # Prompt for product name and quantity to purchase
        prod = input("Introduza o nome do produto: ")
        qt = input("Introduza a quantidade: ")
        
        # Send request to purchase product
        response = requests.get(f"{base_url}/comprar/{prod}/{qt}")
        if response.ok:
            print("Compra realizada com sucesso")
        else:
            print("Erro ao comprar produto:", response.status_code)
    else:
        print("Nenhuma categoria disponível.")

def comprar_produto_rest_secure():
        """Handles the purchase of a specified product in a specified quantity."""
        base_url = listar_produto_categoria_rest_secure()

        if base_url:
            # Prompt for product name and quantity to purchase
            #Case sensitive
            prod = input("Introduza o nome do produto: ")
            qt = input("Introduza a quantidade: ")
            try:
                response = requests.post(f"{base_url}/secure/comprar/{prod}/{qt}")
                if response.ok:
                # Send request to purchase product
                    data = response.json()
                    # Retrieve individual components
                    signature = data.get("assinatura")  # Digital signature string
                    certificate = data.get("certificado")    # Digital certificate string
                    mensagem = data.get("mensagem")
                    print(mensagem)
                    
                    verificar_2 = verify_signature_and_message(certificate, signature, mensagem)
                    verificar_1 = verify_certificate(certificate)
             
                    if verificar_1 and verificar_2:
                            print(f"Assinatura: {signature}")
                            print(f"Certificado: {certificate}")
                            print("Compra realizada com sucesso.")
                    else: print("Condições nao verificadas.")
                else:
                    print("Erro ao comprar produto.")
            except TypeError as e:
                print(e)
        else:
            print("Erro ao listar produtos.")

def start():
    global thread_global
    global category_list
    stop_event = threading.Event()
    periodic = threading.Thread(target=periodical_checking, args=(stop_event,))
    # Listar subscrições
    while True:
        clear_screen()
        print("Subscrições:")
        for sub in subs:
            print(f"[{subs.index(sub) + 1}] {sub[0]} -> {sub[1:3]}")
        print(f"\n[{len(subs) + 1}] Pedidos Subscrições")
        print(f"[{len(subs) + 2}] Pedidos Produtores Públicos")
        print("\n[0] Sair")
        # Selecionar produtor
        loop = True
        while loop:
            try:
                option = int(input("\nInsira uma opção válida: ").strip())
            except ValueError:
                print("[ERRO] Por favor insira uma opção válida!")
                continue
            else:
                if option == 0: 
                    stop_event.set()
                    break
                elif option == len(subs) + 1:
                    global_request = True
                    loop = False
                elif option == len(subs) + 2:
                    loop = False
                else:
                    retries = 0
                    connected = False
                    addr = subs[option - 1][1]
                    loop = False
        # Sair do loop principal
        if option == 0: break
        # Pedidos subscrições
        elif option == len(subs) + 1:
            clear_screen()
            periodic.start()
            # Criar socket
            marketplace = create_socket()
            # Verificar produtores não disponíveis e listá-los
            threads = list()
            
            for producer in subs:
                thread = threading.Thread(target=checking_producer, args=(producer[1],))
                threads.append(thread)
                thread.start()             

            for thread in threads:
                thread.join()

            while global_request:
                clear_screen()
                print("Produtores não disponíveis:")
                # Listar produtores não disponíveis
                for producer in subs:
                    if producer[1] not in available_producers:
                        print(f"\t{producer[0]} -> {producer[1]}")
                # Contactá-los periodicamente e se algum já estiver disponível ou deixar de estar atualizar ecrã
                if refresh_event.is_set():
                    refresh_event.clear()
                    continue

                print("\nFormato de pedidos:")
                print("----------------------------")
                print("listar;;categoria\nstock\nsair\n")
                request = input("\nPedido: ")

                if request.strip().lower() == "sair":
                    # Não enviar nada
                    stop_event.set()
                    periodic.join()
                    marketplace.close()
                    global_request = False
                elif request.strip().lower().startswith("listar"):
                    category = request.split(";;")
                    if len(category) == 2:
                        request = f"global;;listar;;{category[1].strip().lower()}"
                    else:
                        input("Opção inválida! Pressione enter para continuar...")
                        continue

                    for producer in available_producers:
                        thread_global = threading.Thread(target=summing, args=(producer, request))
                        threads_global.append(thread_global)
                        thread_global.start()
                    
                    for thread_global in threads_global:
                        thread_global.join()

                    threads_global.clear()
                    
                    table = (f"\n{'Produto':<10} {'Quantidade':<10} {'Preço médio':<15}\n")
                    table += "-"*30 + "\n"
                    for product, (quantity, price) in category_list.items():
                        table += (f"{product.capitalize():<10} {quantity:<10} €{price/quantity:<10.2f}\n")
                    print(table)

                    category_list.clear()
                    input("\nPressione qualquer tecla para continuar...")
        elif option == len(subs) + 2:
            while True:
                        clear_screen()
                        print("[1] Listar Produtores Públicos\n[2] Listar Produtos de uma Categoria\n[3] Comprar Produtos")
                        print("\n[4] Listar Categorias Seguras\n[5] Listar Produtos de uma Categoria Segura\n[6] Comprar Produto Seguro\n[0] Voltar")
                        try:
                            option = int(input("\nInsira uma opção válida: ").strip())
                        except ValueError:
                            print("[ERRO] Por favor insira uma opção válida!")
                            input("\nPressione enter para continuar...")
                        else:
                            if option == 1:
                                print("\n", end="")
                                listar_produtor_REST()
                                input("\nPressione enter para continuar...")
                            elif option == 2:
                                print("\nProdutores Públicos:")
                                listar_produtor_REST()
                                listar_produto_categoria_rest()
                                input("\nPressione enter para continuar...")
                            elif option == 3:
                                print("\nProdutores Públicos:")
                                listar_produtor_REST()
                                comprar_produto_rest()
                                input("\nPressione enter para continuar...")
                            elif option == 4:
                                print("\nProdutores Públicos Secure:")
                                listar_produtor_REST()
                                url = get_base_url()
                                listar_categorias_secure(url)
                                input("\nPressione enter para continuar...")
                            elif option == 5:
                                print("\nProdutores Públicos Secure:")
                                listar_produtor_REST()
                                listar_produto_categoria_rest_secure()
                                input("\nPressione enter para continuar...")
                            elif option == 6:
                                # Comprar produto secure
                                print("\nProdutores Públicos Secure:")
                                listar_produtor_REST()
                                comprar_produto_rest_secure()
                                input("\nPressione enter para continuar...")
                            elif option == 0:
                                break
                            else:
                                print("[ERRO] Por favor insira uma opção válida!")
                                input("\nPressione enter para continuar...")

        else:
            # Conectado a um produtor
            while not connected and retries < MAX_TRIES :
                # Criar socket
                marketplace = create_socket()
                # Connectar com o produtor
                try:
                    marketplace.settimeout(5)
                    marketplace.connect(addr)
                    connected = True
                except socket.timeout:
                    print(f"[ERRO] Conexão ao produtor expirou (timeout). [{retries + 1}/{MAX_TRIES}]")
                except ConnectionRefusedError:
                    if retries < MAX_TRIES - 1:
                        print(f"[ERRO] Conexão recusada pelo produtor. Tentando outra vez em 5 segundos... [{retries + 1}/{MAX_TRIES}]")
                        time.sleep(5)
                    else:
                        print(f"[ERRO] Conexão recusada pelo produtor. Tentando outra vez em 5 segundos... [{retries + 1}/{MAX_TRIES}]")
                except socket.error as e:
                    print(f"[ERRO] Falha de conexão: {e} [{retries + 1}/{MAX_TRIES}]")
                    marketplace.close()
                finally:
                    if not connected:
                        retries += 1

        
            while connected:
                clear_screen()
                print(f"[CONECTADO] Conexão estabelecida com {subs[option - 1][0]} ({addr})\n")
                print("Formato de pedidos:")
                print("----------------------------")
                print("listar\nlistar;;categoria\ncomprar;;produto;;quantidade\nsair\n")
                request = input("Pedido: ")
                '''
                Formatos de pedidos:
                LISTAR
                LISTAR;;CATEGORIA
                COMPRAR;;PRODUTO;;QUANTIDADE
                SAIR ou sair
                '''
                if request.strip().lower() == "sair":
                    # Não enviar nada
                    marketplace.close()
                    connected = False
                else:
                    # Enviar pedido
                    marketplace.send(request.strip().lower().encode(FORMAT))
                    # Resposta do produtor
                    response = marketplace.recv(BYTES).decode(FORMAT)
                    if response.startswith("[ERRO]"):
                        print(response)
                        input("\nPressione qualquer tecla para continuar...")
                    elif response.startswith("[COMPRA]"):
                        print(response)
                        input("\nPressione qualquer tecla para continuar...")
                    else:
                        print(response)
                        input("\nPressione qualquer tecla para continuar...")

start()