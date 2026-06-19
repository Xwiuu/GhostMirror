BUSINESS_IMPACTS: dict[str, str] = {
    "Missing Security Header": "Possível aumento da superfície para ataques XSS e clickjacking. Pode causar roubo de sessão e exfiltração de dados.",
    "Missing Content Security Policy": "Possível aumento da superfície para ataques XSS. Pode causar roubo de sessão e exfiltração de dados.",
    "Missing X-Frame-Options": "Vulnerabilidade a clickjacking. Pode permitir que atacantes induzam usuários a realizar ações não intencionais.",
    "Missing X-Content-Type-Options": "Possível execução de MIME-type sniffing. Pode permitir execução de scripts maliciosos.",
    "Missing Strict-Transport-Security": "Possível interceptação de tráfego via ataques MITM. Usuários podem ser redirecionados a versões HTTP inseguras.",
    "Missing Referrer-Policy": "Possível vazamento de informações sensíveis através do header Referer.",
    "Missing Permissions-Policy": "Possível abuso de APIs do navegador por scripts de terceiros.",
    "Open Database": "Possível vazamento de informações sensíveis. Pode gerar impacto regulatório, financeiro e reputacional.",
    "Open Port": "Aumento da superfície de ataque. Portas abertas podem ser utilizadas como vetor de entrada para exploração.",
    "Weak Cipher": "Possível descriptografia de tráfego. Dados sensíveis podem ser interceptados e comprometidos.",
    "Expired Certificate": "Possível perda de confiança do usuário. Navegadores podem bloquear o acesso ao serviço.",
    "Self-Signed Certificate": "Possível ataque MITM. Usuários não conseguem verificar a identidade do servidor.",
    "Directory Listing": "Possível vazamento de informações sobre a estrutura do servidor. Pode auxiliar ataques direcionados.",
    "Version Disclosure": "Possível reconhecimento de vulnerabilidades conhecidas. Atacantes podem identificar CVEs aplicáveis.",
    "Open Admin Panel": "Possível acesso administrativo não autorizado. Pode resultar em comprometimento total do sistema.",
    "Default Credentials": "Possível acesso não autorizado ao sistema. Pode resultar em comprometimento total e violação de dados.",
    "Information Disclosure": "Possível vazamento de informações sensíveis. Pode ser utilizado para ataques mais direcionados.",
}

GENERIC_BUSINESS: str = "Possível impacto na confidencialidade, integridade ou disponibilidade dos ativos. Pode gerar danos financeiros, regulatórios e de reputação."

TECHNICAL_IMPACTS: dict[str, str] = {
    "Missing Security Header": "Permite execução de scripts não confiáveis e framing da aplicação em sites maliciosos.",
    "Missing Content Security Policy": "Permite execução de scripts não confiáveis caso exista vulnerabilidade XSS na aplicação.",
    "Missing X-Frame-Options": "Permite que a aplicação seja embutida em iframes por sites maliciosos (clickjacking).",
    "Missing X-Content-Type-Options": "Navegadores podem interpretar arquivos com tipos MIME incorretos, possibilitando execução de scripts.",
    "Missing Strict-Transport-Security": "Conexões HTTP podem ser interceptadas antes do redirecionamento para HTTPS.",
    "Missing Referrer-Policy": "Informações da URL podem ser enviadas no header Referer para domínios de terceiros.",
    "Missing Permissions-Policy": "APIs sensíveis do navegador (câmera, microfone, geolocalização) podem ser abusadas.",
    "Open Database": "Permite acesso direto ao serviço de banco de dados exposto. Pode resultar em leitura, alteração ou exclusão de dados.",
    "Open Port": "Serviço exposto na rede. Pode ser utilizado como ponto de entrada para exploração de vulnerabilidades.",
    "Weak Cipher": "Criptografia fraca permite que atacantes realizam ataques de descriptografia passiva do tráfego.",
    "Expired Certificate": "Validação de certificado falha. Navegadores e clientes exibem avisos de segurança.",
    "Self-Signed Certificate": "Não é possível verificar a cadeia de confiança do certificado. Conexões não podem ser autenticadas.",
    "Directory Listing": "Permite enumeração de arquivos e diretórios no servidor web. Expõe a estrutura da aplicação.",
    "Version Disclosure": "Expõe versões de software. Facilita a correlação com CVEs e vulnerabilidades conhecidas.",
    "Open Admin Panel": "Painel administrativo exposto permite que atacantes tentem acesso não autorizado.",
    "Default Credentials": "Credenciais padrão permitem acesso imediato ao sistema sem necessidade de exploração adicional.",
    "Information Disclosure": "Informações internas são expostas, auxiliando no reconhecimento e planejamento de ataques.",
}

GENERIC_TECHNICAL: str = "Configuração insegura identificada. Pode permitir exploração remota ou local dependendo do contexto."


def get_business_impact(title: str, category: str | None = None) -> str:
    for key, impact in BUSINESS_IMPACTS.items():
        if key.lower() in title.lower():
            return impact
    if category:
        for key, impact in BUSINESS_IMPACTS.items():
            if key.lower() in category.lower():
                return impact
    return GENERIC_BUSINESS


def get_technical_impact(title: str, category: str | None = None) -> str:
    for key, impact in TECHNICAL_IMPACTS.items():
        if key.lower() in title.lower():
            return impact
    if category:
        for key, impact in TECHNICAL_IMPACTS.items():
            if key.lower() in category.lower():
                return impact
    return GENERIC_TECHNICAL
