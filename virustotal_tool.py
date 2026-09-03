"""
Custom CrewAI tool that checks a URL's reputation using the free VirusTotal API v3.
Get a free API key at: https://www.virustotal.com/gui/join-us
"""
import base64
import os
import time

import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field


class URLCheckInput(BaseModel):
    url: str = Field(..., description="The full URL to check, e.g. https://example.com/login")


class VirusTotalURLTool(BaseTool):
    name: str = "VirusTotal URL Reputation Checker"
    description: str = (
        "Checks a URL against the VirusTotal database of 70+ antivirus/security engines. "
        "Returns how many engines flagged it as malicious/phishing/suspicious, plus category info. "
        "Use this for ANY link found in a message before judging if it's safe."
    )
    args_schema: type[BaseModel] = URLCheckInput

    def _run(self, url: str) -> str:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return (
                "ERROR: VIRUSTOTAL_API_KEY not set. Cannot verify URL reputation. "
                "Treat this URL with caution based on text patterns only."
            )

        headers = {"x-apikey": api_key}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        report_resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=15
        )

        if report_resp.status_code == 404:
            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15,
            )
            if submit_resp.status_code not in (200, 201):
                return f"Could not submit URL for scanning (HTTP {submit_resp.status_code})."

            time.sleep(15)
            report_resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=15
            )

        if report_resp.status_code != 200:
            return f"VirusTotal lookup failed (HTTP {report_resp.status_code}) for {url}"

        data = report_resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        categories = data["data"]["attributes"].get("categories", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = sum(stats.values())

        return (
            f"URL: {url}\n"
            f"Engines flagging MALICIOUS: {malicious}/{total}\n"
            f"Engines flagging SUSPICIOUS: {suspicious}/{total}\n"
            f"Engines flagging HARMLESS: {harmless}/{total}\n"
            f"Categories: {categories if categories else 'none reported'}"
        )