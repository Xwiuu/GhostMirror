"""Fingerprint Intelligence Engine & AI Detection Engine."""

from __future__ import annotations

from ghostmirror.core.logger import get_logger
from ghostmirror.models.technology import TechnologyModel
from ghostmirror.models.fingerprint import AIProfile

logger = get_logger()

# Mapping of normalized technology names to standard categories
CATEGORY_MAPPING = {
    # WEB SERVER
    "Apache": "WEB SERVER",
    "Nginx": "WEB SERVER",
    "LiteSpeed": "WEB SERVER",
    "IIS": "WEB SERVER",
    "Tomcat": "WEB SERVER",
    "Caddy": "WEB SERVER",
    # BACKEND LANGUAGE
    "PHP": "BACKEND LANGUAGE",
    "NodeJS": "BACKEND LANGUAGE",
    "Python": "BACKEND LANGUAGE",
    "Ruby": "BACKEND LANGUAGE",
    "Java": "BACKEND LANGUAGE",
    "Go": "BACKEND LANGUAGE",
    ".NET": "BACKEND LANGUAGE",
    # BACKEND FRAMEWORKS
    "Laravel": "BACKEND FRAMEWORKS",
    "Symfony": "BACKEND FRAMEWORKS",
    "CodeIgniter": "BACKEND FRAMEWORKS",
    "Django": "BACKEND FRAMEWORKS",
    "Flask": "BACKEND FRAMEWORKS",
    "FastAPI": "BACKEND FRAMEWORKS",
    "Express": "BACKEND FRAMEWORKS",
    "NestJS": "BACKEND FRAMEWORKS",
    "Spring": "BACKEND FRAMEWORKS",
    "Rails": "BACKEND FRAMEWORKS",
    "ASP.NET": "BACKEND FRAMEWORKS",
    # FRONTEND FRAMEWORKS
    "React": "FRONTEND FRAMEWORKS",
    "Vue": "FRONTEND FRAMEWORKS",
    "Angular": "FRONTEND FRAMEWORKS",
    "NextJS": "FRONTEND FRAMEWORKS",
    "Nuxt": "FRONTEND FRAMEWORKS",
    "Svelte": "FRONTEND FRAMEWORKS",
    "Astro": "FRONTEND FRAMEWORKS",
    # CMS
    "WordPress": "CMS",
    "WooCommerce": "CMS",
    "Drupal": "CMS",
    "Joomla": "CMS",
    "Magento": "CMS",
    "Shopify": "CMS",
    "Ghost CMS": "CMS",
    # BUILDERS
    "Elementor": "BUILDERS",
    "Divi": "BUILDERS",
    "WPBakery": "BUILDERS",
    "Bricks": "BUILDERS",
    "Framer": "BUILDERS",
    "Webflow": "BUILDERS",
    "Bubble": "BUILDERS",
    "Wix": "BUILDERS",
    # INFRASTRUCTURE
    "AWS": "INFRASTRUCTURE",
    "Azure": "INFRASTRUCTURE",
    "Google Cloud": "INFRASTRUCTURE",
    "DigitalOcean": "INFRASTRUCTURE",
    "Vercel": "INFRASTRUCTURE",
    "Netlify": "INFRASTRUCTURE",
    "Render": "INFRASTRUCTURE",
    "Cloudflare": "INFRASTRUCTURE",
    # WAF
    "Akamai": "WAF",
    "Imperva": "WAF",
    "Sucuri": "WAF",
    "AWS WAF": "WAF",
    # ANALYTICS
    "Google Analytics": "ANALYTICS",
    "Google Tag Manager": "ANALYTICS",
    "Hotjar": "ANALYTICS",
    "Microsoft Clarity": "ANALYTICS",
    "Facebook Pixel": "ANALYTICS",
    # PAYMENTS
    "Stripe": "PAYMENTS",
    "PayPal": "PAYMENTS",
    "Mercado Pago": "PAYMENTS",
    "Pagar.me": "PAYMENTS",
}

# Normalization mapping from WhatWeb plugin names (lowercase) to standard names
NORMALIZE_MAP = {
    "nginx": "Nginx",
    "apache": "Apache",
    "litespeed": "LiteSpeed",
    "microsoft-iis": "IIS",
    "apache tomcat": "Tomcat",
    "caddy": "Caddy",

    "php": "PHP",
    "node.js": "NodeJS",
    "nodejs": "NodeJS",
    "python": "Python",
    "ruby": "Ruby",
    "java": "Java",
    "go": "Go",
    "golang": "Go",
    "microsoft-.net": ".NET",

    "laravel": "Laravel",
    "symfony": "Symfony",
    "codeigniter": "CodeIgniter",
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "express": "Express",
    "nestjs": "NestJS",
    "spring-boot": "Spring",
    "spring-mvc": "Spring",
    "spring": "Spring",
    "ruby-on-rails": "Rails",
    "rails": "Rails",
    "asp.net": "ASP.NET",

    "react": "React",
    "vue.js": "Vue",
    "vuejs": "Vue",
    "vue": "Vue",
    "angularjs": "Angular",
    "angular": "Angular",
    "next.js": "NextJS",
    "nextjs": "NextJS",
    "nuxt.js": "Nuxt",
    "nuxt": "Nuxt",
    "svelte": "Svelte",
    "astro": "Astro",

    "wordpress": "WordPress",
    "woocommerce": "WooCommerce",
    "drupal": "Drupal",
    "joomla!": "Joomla",
    "joomla": "Joomla",
    "magento": "Magento",
    "shopify": "Shopify",
    "ghost": "Ghost CMS",

    "elementor": "Elementor",
    "divi": "Divi",
    "wpbakery": "WPBakery",
    "bricks": "Bricks",
    "framer": "Framer",
    "webflow": "Webflow",
    "bubble": "Bubble",
    "wix": "Wix",

    "cloudflare": "Cloudflare",
    "amazon-web-services": "AWS",
    "aws": "AWS",
    "microsoft-azure": "Azure",
    "azure": "Azure",
    "google-cloud-platform": "Google Cloud",
    "google cloud": "Google Cloud",
    "digitalocean": "DigitalOcean",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "render": "Render",

    "cloudflare-waf": "Cloudflare",
    "akamai": "Akamai",
    "imperva": "Imperva",
    "sucuri": "Sucuri",
    "aws-waf": "AWS WAF",

    "google-analytics": "Google Analytics",
    "google-tag-manager": "Google Tag Manager",
    "hotjar": "Hotjar",
    "microsoft-clarity": "Microsoft Clarity",
    "facebook-pixel": "Facebook Pixel",

    "stripe": "Stripe",
    "paypal": "PayPal",
    "mercado-pago": "Mercado Pago",
    "pagar.me": "Pagar.me",
}


class AIFingerprintEngine:
    """Detects indications of AI-assisted construction in HTML, Headers, JS, and Assets."""

    @staticmethod
    def analyze(html: str, headers: dict[str, str]) -> AIProfile:
        """Analyzes web content for AI signals and returns an AIProfile.

        Parameters
        ----------
        html : str
            The raw HTML content of the target homepage.
        headers : dict[str, str]
            HTTP headers from the target response.

        Returns
        -------
        AIProfile
            Calculated AI profile model.
        """
        signals = []
        frameworks = []
        llms = []

        html_lower = html.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        # 1. Check builder/generator signals in HTML
        if "v0.dev" in html_lower or "v0-" in html_lower or "created by v0" in html_lower or "nextjs-template" in html_lower:
            signals.append("v0")
        if "lovable.dev" in html_lower or "created-with-lovable" in html_lower or "lovable" in html_lower:
            signals.append("Lovable")
        if "bolt.new" in html_lower or "sb1.project" in html_lower or "stackblitz" in html_lower:
            signals.append("Bolt")
        if "cursor-editor" in html_lower or "cursor.sh" in html_lower:
            signals.append("Cursor")
        if "replit.app" in html_lower or "replit.com" in html_lower or "repl-" in html_lower:
            signals.append("Replit")
        if "framer ai" in html_lower or "framer-ai" in html_lower:
            signals.append("Framer AI")
        if "webflow ai" in html_lower or "webflow-ai" in html_lower:
            signals.append("Webflow AI")

        # 2. Check SDK references or LLM Integrations
        if "openai-sdk" in html_lower or "openai" in html_lower or "@openai/api" in html_lower:
            signals.append("openai-sdk")
            llms.append("OpenAI")
        if "anthropic-sdk" in html_lower or "anthropic" in html_lower or "@anthropic-ai" in html_lower:
            signals.append("anthropic-sdk")
            llms.append("Anthropic")
        if "google-ai-sdk" in html_lower or "@google/generative-ai" in html_lower or "generative-ai" in html_lower:
            signals.append("google-ai-sdk")
            llms.append("Google AI")

        # 3. Check AI/Agent Frameworks
        if "langchain" in html_lower:
            signals.append("LangChain")
            frameworks.append("LangChain")
        if "llamaindex" in html_lower or "llama-index" in html_lower:
            signals.append("LlamaIndex")
            frameworks.append("LlamaIndex")
        if "crewai" in html_lower or "crew-ai" in html_lower:
            signals.append("CrewAI")
            frameworks.append("CrewAI")

        # Check response headers for Framer/Webflow AI signals
        for k, v in headers_lower.items():
            if "framer" in k or "framer" in v:
                if "Framer AI" not in signals:
                    signals.append("Framer AI")
            if "webflow" in k or "webflow" in v:
                if "Webflow AI" not in signals:
                    signals.append("Webflow AI")

        # Calculate AI generation probability
        probability = 0.0
        builder_map = {
            "Lovable": 85.0,
            "Bolt": 80.0,
            "v0": 75.0,
            "Replit": 60.0,
            "Framer AI": 50.0,
            "Webflow AI": 50.0,
            "Cursor": 30.0,
        }

        base_prob = 0.0
        for sig in signals:
            if sig in builder_map:
                base_prob = max(base_prob, builder_map[sig])

        # Additional SDKs / frameworks boost confidence
        additional_prob = 0.0
        if "openai-sdk" in signals:
            additional_prob += 20.0
        if "anthropic-sdk" in signals:
            additional_prob += 20.0
        if "google-ai-sdk" in signals:
            additional_prob += 20.0
        if any(fw in frameworks for fw in ["LangChain", "LlamaIndex", "CrewAI"]):
            additional_prob += 25.0

        if base_prob > 0:
            probability = min(100.0, base_prob + (additional_prob * 0.5))
        else:
            # No builder detected, only SDKs/frameworks
            probability = min(60.0, additional_prob)

        signals = list(sorted(set(signals)))
        frameworks = list(sorted(set(frameworks)))
        llms = list(sorted(set(llms)))

        observations = ""
        if probability >= 70:
            observations = f"Alta probabilidade ({probability:.0f}%) de o aplicativo ter sido construído ou gerado com assistência de IA."
        elif probability >= 30:
            observations = f"Média probabilidade ({probability:.0f}%) de desenvolvimento assistido por IA ou integração com LLMs."
        elif probability > 0:
            observations = f"Baixa probabilidade ({probability:.0f}%) de desenvolvimento assistido por IA."
        else:
            observations = "Nenhum sinal de construção assistida por IA detectado."

        return AIProfile(
            ai_probability=round(probability, 1),
            signals_detected=signals,
            frameworks_detected=frameworks,
            llm_integrations=llms,
            observations=observations,
        )


class FingerprintIntelligence:
    """Classifies and correlates WhatWeb detections to enrich tech stack signatures."""

    @staticmethod
    def map_detection(plugin_name: str, version: str | None = None, confidence: float = 1.0) -> TechnologyModel | None:
        """Standardizes a WhatWeb plugin detection into a TechnologyModel.

        Parameters
        ----------
        plugin_name : str
            The WhatWeb raw plugin name.
        version : str | None
            The version discovered, if any.
        confidence : float
            Confidence level.

        Returns
        -------
        TechnologyModel | None
            Mapped technology model or None if the plugin is not recognized.
        """
        clean_name = plugin_name.strip().lower()
        normalized_name = NORMALIZE_MAP.get(clean_name)

        if not normalized_name:
            # Try a direct match if not in normalization map but in category map
            direct_name = plugin_name.strip()
            if direct_name in CATEGORY_MAPPING:
                normalized_name = direct_name
            else:
                # Fallback to Title Cased word check
                title_name = direct_name.title()
                if title_name in CATEGORY_MAPPING:
                    normalized_name = title_name

        if normalized_name:
            category = CATEGORY_MAPPING[normalized_name]
            return TechnologyModel(
                name=normalized_name,
                category=category,
                version=version,
                confidence=confidence,
                source="WhatWeb"
            )
        return None

    @staticmethod
    def correlate(technologies: list[TechnologyModel]) -> list[TechnologyModel]:
        """Correlates tech stack signatures to infer implied backend languages and platforms.

        Parameters
        ----------
        technologies : list[TechnologyModel]
            List of explicitly detected technology models.

        Returns
        -------
        list[TechnologyModel]
            Enriched list of technology models with correlated inferences.
        """
        names = {t.name for t in technologies}
        enriched = list(technologies)

        def add_tech(name: str, category: str, source: str = "Fingerprint Engine Correlation"):
            if name not in names:
                enriched.append(
                    TechnologyModel(
                        name=name,
                        category=category,
                        version=None,
                        confidence=1.0,
                        source=source
                    )
                )
                names.add(name)

        for t in technologies:
            if t.name == "WordPress":
                add_tech("PHP", "BACKEND LANGUAGE")
            elif t.name == "Laravel":
                add_tech("PHP", "BACKEND LANGUAGE")
            elif t.name == "WooCommerce":
                add_tech("WordPress", "CMS")
                add_tech("PHP", "BACKEND LANGUAGE")
            elif t.name == "NextJS":
                add_tech("NodeJS", "BACKEND LANGUAGE")
            elif t.name == "Nuxt":
                add_tech("Vue", "FRONTEND FRAMEWORKS")
                add_tech("NodeJS", "BACKEND LANGUAGE")
            elif t.name in ("Elementor", "Divi", "WPBakery", "Bricks"):
                add_tech("WordPress", "CMS")
                add_tech("PHP", "BACKEND LANGUAGE")

        return enriched
