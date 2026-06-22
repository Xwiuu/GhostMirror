from __future__ import annotations

from ghostmirror.models.bug_bounty_report import BugBountyReport


class BountyRecommendations:
    def generate(self, report: BugBountyReport) -> list[str]:
        recs: list[str] = []

        if report.total_routes == 0:
            recs.append("No routes were discovered. Consider increasing max_depth or checking if the target is accessible.")

        if report.sourcemap_findings:
            exposed = [s for s in report.sourcemap_findings if s.get("exposed")]
            if exposed:
                recs.append(
                    f"Remove {len(exposed)} exposed source map(s) from production. "
                    "Exposed source maps leak application source code and internal API paths."
                )

        if report.total_apis > 0:
            recs.append(
                f"Review the {report.total_apis} discovered API endpoints for authorization, "
                "rate limiting, and input validation weaknesses."
            )

        if report.total_secrets > 0:
            recs.append(
                f"Review {report.total_secrets} potential secret(s) found in client-side code. "
                "Rotate any production keys immediately."
            )

        payment_routes = [r for r in report.headless_routes if any(
            kw in r.url.lower() for kw in ["payment", "checkout", "cart", "basket", "order", "wallet"]
        )]
        if payment_routes:
            recs.append(
                f"Found {len(payment_routes)} payment/business logic route(s). "
                "Business logic flaws in payment flows often yield critical bounties."
            )

        admin_routes = [r for r in report.headless_routes if any(
            kw in r.url.lower() for kw in ["admin", "dashboard"]
        )]
        if admin_routes:
            recs.append(
                f"Found {len(admin_routes)} admin/dashboard route(s). "
                "Test for privilege escalation and improper access controls."
            )

        if report.total_opportunities == 0:
            recs.append(
                "No high-value opportunities were identified. "
                "Consider running the 'bounty' profile with a wider scope."
            )
        else:
            high_opps = [o for o in report.opportunities if o.score >= 15]
            if high_opps:
                recs.append(
                    f"Prioritize the {len(high_opps)} high-score opportunity(ies) identified. "
                    "These represent the most promising bug bounty targets."
                )

        return recs
