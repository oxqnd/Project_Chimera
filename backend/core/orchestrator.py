import os
import sys
import openai
import json
from dotenv import load_dotenv
from ..db.database import get_db_connection

# Load environment variables from .env file in the scripts directory
load_dotenv(dotenv_path="scripts/.env")

def ask_llm(
    prompt: str,
    system_prompt: str = "You are a helpful assistant acting as a senior penetration tester that outputs JSON."
) -> str | None:
    """Generic function to call the OpenAI API."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or api_key == "YOUR_API_KEY_HERE":
        print("[!] Error: OPENAI_API_KEY not found or not set.", file=sys.stderr)
        return None

    client = openai.OpenAI(api_key=api_key)
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[!] An error occurred while calling the OpenAI API: {e}", file=sys.stderr)
        return None

def create_scan_plan(domain: str) -> dict | None:
    """
    Analyzes the current state of the database and asks the LLM to create a scan plan.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get all assets for the domain
    cursor.execute("SELECT id, subdomain FROM assets WHERE domain = ?", (domain,))
    assets = cursor.fetchall()
    
    if not assets:
        print("[*] No assets found in DB for domain to create a plan.", file=sys.stderr)
        conn.close()
        return None

    # Get all existing vulnerabilities for these assets
    asset_ids = [asset['id'] for asset in assets]
    placeholders = ', '.join('?' for _ in asset_ids)
    cursor.execute(f"SELECT asset_id, finding, severity FROM vulnerabilities WHERE asset_id IN ({placeholders})", asset_ids)
    vulnerabilities = cursor.fetchall()
    conn.close()

    # Build a context for the LLM
    attack_context = {
        "target_domain": domain,
        "assets": [dict(row) for row in assets],
        "findings": [dict(row) for row in vulnerabilities]
    }

    prompt = f"""
    You are a senior penetration tester. Your target is {domain}.
    You have already discovered the following assets and findings:
    {json.dumps(attack_context, indent=2)}

    Your available tools are: ['nmap', 'zap_spider', 'zap_scan', 'zap_custom_scan', 'zap_fuzzer', 'curl', 'auth_login', 'zap_run_script', 'zap_load_script'].
    - 'nmap -F <target>': Fast port scan.
    - 'zap_spider --target <target_url>': Discover URLs on a target.
    - 'zap_scan --target <target_url>': Baseline active scan.
    - 'zap_custom_scan --target <target_url> --policy <sqli|xss>': Focused active scan.
    - 'zap_fuzzer --target_url <url_with_FUZZ_placeholder> --payloads '["payload1", "payload2"]'': Fuzz a URL with a JSON array of payloads.
    - 'curl ...': Specific, creative probes.
    - 'auth_login --domain <root> --login-url <https://target/login> --method POST --json-body {{...}}': Perform authentication and persist session cookies/tokens.
    - 'zap_run_script --name <script_name>': Execute a stored ZAP script.
    - 'zap_load_script --payload '{{"name": "...", "script_type": "...", "script_engine": "...", "content": "..."}}'': Register an inline ZAP script (content must be JSON-safe).

    Based on the current findings, create a concise JSON plan for the *next one or two logical steps*. 
    Focus on reconnaissance and initial vulnerability identification. Do not try to test for logical vulnerabilities with curl yet.
    
    Format: {{"plan": [{{"target": "<subdomain>", "rationale": "<why this is the next logical step>", "actions": ["<command_string>"]}}]}}
    Example action: "nmap -F api.example.com" or "zap_fuzzer --target_url https://shop.example.com/FUZZ --payloads '[\"admin\", \"backup\"]'"
    """

    plan_json = ask_llm(prompt)
    if not plan_json:
        return None
    
    try:
        plan = json.loads(plan_json)
        return plan
    except json.JSONDecodeError:
        print("[!] LLM returned invalid JSON for the plan.", file=sys.stderr)
        return None

def create_hypothesis_and_action(domain: str, history: list) -> dict | None:
    """
    Analyzes the history of actions and asks the LLM to form a hypothesis and a command to test it.
    """
    attack_context = {
        "target_domain": domain,
        "history": history
    }

    analysis_prompt = f"""
    You are a senior penetration tester. Here is the history of your actions and their summarized results:
    {json.dumps(attack_context, indent=2)}

    Based on these results, it's time to stop broad scanning and start probing for logical (0-day) vulnerabilities.
    Formulate a creative hypothesis about a potential flaw (e.g., IDOR, parameter tampering, authentication bypass).
    Then, propose a single, specific command to test this hypothesis. You can use:
      - 'auth_login --domain <root> --login-url <https://target/login> --method POST --json-body {{...}}' to establish an authenticated session.
      - 'curl ...' for manual HTTP exploration (sessions are automatically attached if present).
      - 'zap_send_request --target_url ... --method ... --headers {...}' to replay traffic via the ZAP proxy.
      - 'zap_fuzzer --target_url https://app/FUZZ --payloads '[\"payload1\"]'' for targeted fuzzing.
      - 'zap_run_script --name <script_name>' if a preloaded ZAP script is the best follow-up.

    Your output MUST be a JSON object with two keys:
    1. "hypothesis": A string describing your theory (e.g., "The endpoint /api/users/{{id}} might be vulnerable to IDOR").
    2. "next_action": The single command to test the hypothesis (e.g., "curl -X GET ..." or "zap_fuzzer --target_url https://api.example.com/users/FUZZ --payloads '[\"123\", \"456\"]'").
    """

    next_action_json = ask_llm(analysis_prompt)
    if not next_action_json:
        return None
    
    try:
        next_action_plan = json.loads(next_action_json)
        return next_action_plan
    except json.JSONDecodeError:
        print("[!] LLM returned invalid JSON for the hypothesis.", file=sys.stderr)
        return None
