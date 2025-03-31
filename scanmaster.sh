#!/bin/bash

# Função para imprimir mensagens em cores personalizadas
print_message() {
    local color="$1"
    local message="$2"
    echo -e "\e[${color}m${message}\e[0m"
}

# Função para imprimir mensagens de status em ciano
print_status() {
    print_message "1;36" "$1"
}

# Função para imprimir mensagens de erro em vermelho
print_error() {
    print_message "1;31" "Erro: $1" >&2
}

# Função para imprimir Juicy Targets em vermelho
print_juicy_target() {
    print_message "1;31" "$1"
}

# Função para imprimir Resumo dos Findings em amarelo
print_summary() {
    print_message "1;33" "$1"
}

# Função para verificar e instalar dependências
check_dependency() {
    local program="$1"
    local package_manager="$2"

    if ! command -v "$program" &> /dev/null; then
        print_status "O programa $program não está instalado. Tentando instalar..."
        case "$package_manager" in
            "apt-get")
                sudo apt-get update
                sudo apt-get install -y "$program"
                ;;
            "yum")
                sudo yum install -y "$program"
                ;;
            "dnf")
                sudo dnf install -y "$program"
                ;;
            *)
                print_error "Gerenciador de pacotes não suportado: $package_manager"
                exit 1
                ;;
        esac
    fi
}

# Verificar e instalar dependências
dependencies=("subfinder" "assetfinder" "httprobe" "jq" "ffuf" "seclists")
package_manager="apt-get"  # Defina o gerenciador de pacotes padrão aqui
for dep in "${dependencies[@]}"; do
    check_dependency "$dep" "$package_manager"
done

# Verificar se o usuário forneceu um domínio como argumento
if [ -z "$1" ]; then
    print_error "Uso: $0 <domínio>"
    exit 1
fi

# Definir o domínio a ser pesquisado
domain="$1"

# Exibir mensagem de busca por subdomínios
print_status "Buscando Subdomínios para $domain..."
echo "-----------------------------------------------------------"

# Execute o subfinder para encontrar subdomínios
subfinder_output=$(subfinder -d "$domain" 2>/dev/null | grep -v '@')

# Execute o assetfinder para encontrar mais subdomínios
assetfinder_output=$(assetfinder --subs-only "$domain" 2>/dev/null | grep -v '@')

# Execute o ffuf para encontrar subdomínios adicionais
ffuf_output=$(ffuf -u "http://FUZZ.$domain" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200 -o json 2>/dev/null)

# Combine todos os subdomínios encontrados
all_subdomains=$(echo -e "$subfinder_output\n$assetfinder_output\n$ffuf_output" | sort -u)

# Salvar subdomínios em um arquivo
echo "$all_subdomains" > subdomains.txt

# Imprimir os sites encontrados em ciano
print_status "Sites Encontrados: ($(echo "$all_subdomains" | wc -l))"
echo "-----------------------------------------------------------"
echo "$all_subdomains"
echo "-----------------------------------------------------------"

# Execute o httprobe para verificar quais sites estão ativos
httprobe_output=$(httprobe -prefer-https < subdomains.txt)

# Salvar sites ativos em um arquivo
echo "$httprobe_output" > active_sites.txt

# Exibir os sites ativos na tela em ciano
print_status "Sites Ativos: ($(echo "$httprobe_output" | wc -l))"
echo "-----------------------------------------------------------"
echo "$httprobe_output"
echo "-----------------------------------------------------------"


# Verificar se os sites ativos contêm termos de ataque
attack_terms=("dev" "test" "jira" "public" "hml" "jenkins" "\.ci\." "tools" "gitlab" "git" "it" "support" "login" "admin" "register" "login" "beta" "sql" "db" "admin" "vpn" "test" "sandbox" "dev2" "demo")
attack_domains=()
for site in $httprobe_output; do
    for term in "${attack_terms[@]}"; do
        if [[ "$site" == *"$term"* ]]; then
            attack_domains+=("$site")
            break
        fi
    done
done

# Salvar os domínios de ataque em um arquivo e imprimir na tela
if [ ${#attack_domains[@]} -gt 0 ]; then
    print_status "Buscando Juicy Targets..."
    echo "-----------------------------------------------------------"
    for domain in "${attack_domains[@]}"; do
        print_juicy_target "$domain"
    done | tee juicytargets.txt
else
    print_status "Nenhum Juicy Target encontrado."
fi


# Resumo
echo "-----------------------------------------------------------"
print_summary "Resumo dos Findings"
echo "-----------------------------------------------------------"
echo "Sites Encontrados (subdomains.txt): $(echo "$all_subdomains" | wc -l)"
echo "Sites Ativos (active_sites.txt): $(echo "$httprobe_output" | wc -l)"
echo "JuicyTargets (juicytargets.txt): ${#attack_domains[@]}"
