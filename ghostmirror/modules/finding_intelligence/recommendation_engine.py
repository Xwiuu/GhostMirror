RECOMMENDATIONS: dict[str, str] = {
    "Missing Security Header": "Implementar headers de segurança HTTP adequados. Consulte as referências OWASP para configuração recomendada.",
    "Missing Content Security Policy": "Implementar Content-Security-Policy restritiva. Ex: default-src 'self'; script-src 'self'; object-src 'none'.",
    "Missing X-Frame-Options": "Adicionar header X-Frame-Options: DENY ou SAMEORIGIN para prevenir clickjacking.",
    "Missing X-Content-Type-Options": "Adicionar header X-Content-Type-Options: nosniff para prevenir MIME-type sniffing.",
    "Missing Strict-Transport-Security": "Adicionar header Strict-Transport-Security com max-age mínimo de 31536000 e includeSubDomains.",
    "Missing Referrer-Policy": "Adicionar header Referrer-Policy: strict-origin-when-cross-origin ou no-referrer.",
    "Missing Permissions-Policy": "Adicionar header Permissions-Policy restritivo, permitindo apenas APIs necessárias.",
    "Open Database": "Restringir acesso ao banco de dados por firewall. Permitir apenas IPs autorizados. Utilizar autenticação forte.",
    "Open Port": "Restringir acesso por firewall. Permitir apenas IPs autorizados. Desativar serviços não essenciais.",
    "Weak Cipher": "Desativar cifras fracas (RC4, DES, 3DES). Configurar apenas TLS 1.2+ com cifras fortes.",
    "Expired Certificate": "Renovar o certificado SSL/TLS imediatamente. Configurar renovação automática.",
    "Self-Signed Certificate": "Substituir por certificado emitido por CA confiável. Utilizar Let's Encrypt ou CA corporativa.",
    "Directory Listing": "Desativar directory listing no servidor web. Remover arquivos sensíveis do diretório público.",
    "Version Disclosure": "Ocultar versões de software nos headers de resposta. Configurar server tokens no servidor web.",
    "Open Admin Panel": "Restringir acesso ao painel administrativo por VPN ou firewall. Implementar autenticação multifator.",
    "Default Credentials": "Alterar todas as credenciais padrão imediatamente. Implementar política de senhas fortes.",
    "Information Disclosure": "Revisar e remover informações sensíveis de respostas HTTP e páginas públicas.",
}

GENERIC_RECOMMENDATION: str = "Revisar e corrigir a configuração identificada conforme as melhores práticas de segurança."


def generate_recommendation(title: str, category: str | None = None) -> str:
    for key, rec in RECOMMENDATIONS.items():
        if key.lower() in title.lower():
            return rec
    if category:
        for key, rec in RECOMMENDATIONS.items():
            if key.lower() in category.lower():
                return rec
    return GENERIC_RECOMMENDATION
