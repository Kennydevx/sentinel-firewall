import os
import sys
import subprocess

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    clear_screen()
    print("=" * 60)
    print(" 🛡️  Sentinel Firewall Agent — Setup Wizard")
    print("=" * 60)
    print(" Bem-vindo! Este assistente vai configurar o WAF Neural no seu")
    print(" servidor em poucos passos. Não é necessário saber programar.\n")

def run():
    print_header()
    
    # 1. API Key
    api_key = input(" 🔑 Qual é a sua API Key do Cryo-SaaS? (Cole aqui): ").strip()
    if not api_key:
        api_key = "DEMO_KEY_123"
        print(f" [!] Usando chave de demonstração: {api_key}")
    
    # 2. Server
    print("\n")
    server = input(" 🌐 Endereço do Servidor Cryo [Padrão: api.cryo-corona.com:50505]: ").strip()
    if not server:
        server = "api.cryo-corona.com:50505"
        
    # 3. Threshold
    print("\n")
    print(" 🎚️  Sensibilidade do Firewall (0.5 = Rígido, 0.9 = Tolerante)")
    threshold = input(" Qual nível de proteção deseja? [Padrão: 0.7]: ").strip()
    if not threshold:
        threshold = "0.7"
        
    # Salvar .env
    print("\n ⚙️  Gerando configurações...")
    with open(".env", "w") as f:
        f.write(f"CRYO_SERVER={server}\n")
        f.write(f"CRYO_API_KEY={api_key}\n")
        f.write(f"SENTINEL_THRESHOLD={threshold}\n")
    print(" [+] Arquivo .env criado com sucesso.")
    
    # Instalar dependências
    print("\n 📦 Instalando dependências necessárias...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print(" [+] Bibliotecas instaladas.")
    except Exception as e:
        print(f" [-] Aviso: falha ao instalar requirements. {e}")
        print("     Execute manualmente: pip install -r requirements.txt")
        
    # Finalização
    print("\n" + "=" * 60)
    print(" 🎉 Configuração Concluída!")
    print("=" * 60)
    print(" Próximos passos:")
    print(" 1. Importe o Sentinel na sua aplicação Flask/Django:")
    print("    from sentinel_agent import SentinelFirewall")
    print(" 2. Teste o agente executando: python sentinel_agent.py\n")
    input(" Pressione Enter para sair...")

if __name__ == "__main__":
    run()
