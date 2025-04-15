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
dependencies=("subfinder" "assetfinder" "httprobe" "jq" "ffuf" "gowitness")
package_manager="apt-get"  # Altere conforme sua distro
for dep in "${dependencies[@]}"; do
    check_dependency "$dep" "$package_manager"
done

# Verificar se o usuário forneceu um domínio como argumento
if [ -z "$1" ]; then
    print_error "Uso: $0 <domínio>"
    exit 1
fi

domain="$1"

# Criar diretório de resultados
timestamp=$(date +%Y%m%d_%H%M%S)
output_dir="resultados/${domain}_${timestamp}"
mkdir -p "$output_dir"

# Caminhos de saída
subdomains_file="$output_dir/subdomains.txt"
active_file="$output_dir/active_sites.txt"
juicy_file="$output_dir/juicytargets.txt"
gowitness_targets="$output_dir/targets.txt"

print_status "Buscando Subdomínios para $domain..."
echo "-----------------------------------------------------------"

subfinder_output=$(subfinder -d "$domain" 2>/dev/null | grep -v '@')
assetfinder_output=$(assetfinder --subs-only "$domain" 2>/dev/null | grep -v '@')
crtsh_output=$(curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u)
ffuf_output=$(ffuf -u "http://FUZZ.$domain" -w /usr/share/wordlists/dirb/big.txt -mc 200 -o json 2>/dev/null)

all_subdomains=$(echo -e "$subfinder_output\n$assetfinder_output\n$crtsh_output\n$ffuf_output" | sort -u)
echo "$all_subdomains" > "$subdomains_file"

print_status "Sites Encontrados: ($(echo "$all_subdomains" | wc -l))"
echo "-----------------------------------------------------------"
echo "$all_subdomains"
echo "-----------------------------------------------------------"

# Verificar sites ativos
httprobe_output=$(httprobe < "$subdomains_file")
echo "$httprobe_output" > "$active_file"

print_status "Sites Ativos: ($(echo "$httprobe_output" | wc -l))"
echo "-----------------------------------------------------------"
echo "$httprobe_output"
echo "-----------------------------------------------------------"

# Buscar Juicy Targets
attack_terms=("dev" "dev1" "dev2" "dev3" "development" "test" "testing" "qa" "staging" "hml" "sandbox" "demo" "preview" "beta" "alpha" "preprod" "uat" "jenkins" "git" "gitlab" "bitbucket" "ci" "cicd" "pipeline" "artifactory" "nexus" "registry" "docker" "harbor" "login" "signin" "auth" "authentication" "sso" "saml" "oauth" "register" "signup" "password" "reset" "forgot" "token" "vpn" "remote" "access" "gateway" "firewall" "admin" "adminpanel" "manage" "dashboard" "console" "cms" "intranet" "internal" "private" "secure" "portal" "support" "help" "helpdesk" "it" "ticket" "jira" "confluence" "servicenow" "db" "database" "mysql" "postgres" "mongo" "sql" "redis" "api" "backend" "tools" "monitoring" "status" "uptime" "metrics" "grafana" "prometheus" "logs" "log" "kibana" "elastic" "public" "static" "files" "uploads" "content" "assets" "media" "old" "backup" "bak" "temp" "tmp" "archive"
)
attack_domains=()
for site in $httprobe_output; do
    for term in "${attack_terms[@]}"; do
        if [[ "$site" == *"$term"* ]]; then
            attack_domains+=("$site")
            break
        fi
    done
done

if [ ${#attack_domains[@]} -gt 0 ]; then
    print_status "Buscando Juicy Targets..."
    echo "-----------------------------------------------------------"
    for juicy in "${attack_domains[@]}"; do
        print_juicy_target "$juicy"
    done | tee "$juicy_file"
else
    print_status "Nenhum Juicy Target encontrado."
fi

# Captura de screenshots com gowitness
echo "$httprobe_output" > "$gowitness_targets"

rm -f gowitness.sqlite3
gowitness init

print_status "Capturando screenshots com gowitness (modo com banco de dados)..."
while read -r url; do
    gowitness scan single --url "$url" --write-db
done < "$gowitness_targets"

print_status "Capturas salvas no diretório: $gowitness_dir"
echo "Para visualizar com interface web, use: gowitness server"

# Comparação com scan anterior
last_file=$(ls -1 resultados | grep "$domain" | grep -v "$timestamp" | sort | tail -n 1)

if [ -n "$last_file" ]; then
    last_subs="resultados/$last_file/subdomains.txt"
    if [ -f "$last_subs" ]; then
        new_count=$(comm -13 <(sort "$last_subs") <(sort "$subdomains_file") | wc -l)
        print_status "Novos subdomínios desde o último scan: $new_count"
    fi
else
    print_status "Nenhum scan anterior encontrado para comparação."
fi

# Resumo final
echo "-----------------------------------------------------------"
print_summary "Resumo dos Findings"
echo "-----------------------------------------------------------"
echo "Sites Encontrados ($subdomains_file): $(echo "$all_subdomains" | wc -l)"
echo "Sites Ativos ($active_file): $(echo "$httprobe_output" | wc -l)"
echo "JuicyTargets ($juicy_file): ${#attack_domains[@]}"
