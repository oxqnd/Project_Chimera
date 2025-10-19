import subprocess
import sys
import os
import json
import shlex
import shutil
from dotenv import load_dotenv
import openai

# --- 1. Tool Discovery ---
def get_available_tools():
    """Checks for a predefined list of tools and returns a list of available ones."""
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = original_path + os.pathsep + "/snap/bin"
    tools = ['nmap', 'feroxbuster', 'nuclei', 'curl']
    available_tools = [tool for tool in tools if shutil.which(tool)]
    os.environ["PATH"] = original_path
    print(f"[*] Available tools: {available_tools}")
    return available_tools

# --- 2. Reconnaissance ---
def run_subfinder(domain):
    """Runs subfinder to get subdomains."""
    subfinder_path = os.path.expanduser("~/go/bin/subfinder")
    if not os.path.exists(subfinder_path):
        print("[!] Error: 'subfinder' not found at ~/go/bin/subfinder", file=sys.stderr)
        return []
    command = [subfinder_path, "-d", domain, "-silent"]
    print(f"[*] Running subfinder on {domain}...")
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print(f"[!] Error running subfinder: {stderr}", file=sys.stderr)
            return []
        subdomains = stdout.strip().split('\n')
        print(f"[*] Found {len(subdomains)} subdomains.")
        return subdomains
    except Exception as e:
        print(f"[!] An unexpected error occurred during subfinder: {e}", file=sys.stderr)
        return []

# --- 3. LLM-driven Planning ---
def ask_llm(
    prompt,
    system_prompt="You are a helpful assistant acting as a senior penetration tester that outputs JSON."
):
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

# --- 4. Execution & Summarization ---
def summarize_output(action, stdout, stderr):
    """Summarizes the output of a command to reduce token count."""
    if "nuclei" in action:
        return "\n".join([line for line in stdout.split('\n') if any(sev in line for sev in ["[critical]", "[high]", "[medium]"])])
    if "nmap" in action:
        return "\n".join([line for line in stdout.split('\n') if "/tcp" in line and "open" in line])
    if "feroxbuster" in action:
        return "\n".join([line for line in stdout.split('\n') if line.startswith("2") or line.startswith("3")])
    if stderr and not stdout:
        return f"Execution failed with error: {stderr[:500]}"
    return stdout[:2000]

def execute_actions(actions):
    """Executes a list of action commands and returns their summarized results."""
    results = []
    for action in actions:
        print(f"    -> Executing: {action}")
        try:
            command_parts = shlex.split(action)
            process = subprocess.Popen(command_parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
            stdout, stderr = process.communicate(timeout=600) # Increased timeout for potentially long scans
            
            summary = summarize_output(action, stdout, stderr)
            results.append({"action": action, "output": summary})
            
            print("      [Raw Output Snippet]")
            print(stdout[:500] + ("..." if len(stdout) > 500 else ""))

        except FileNotFoundError:
            results.append({"action": action, "output": f"Error: Command not found: {shlex.split(action)[0]}"})
        except Exception as e:
            results.append({"action": action, "output": f"Error: {e}"})
    return results

# --- Main Loop ---
def main():
    """Main function to drive the agent's loop."""
    load_dotenv(dotenv_path=os.path.join('llm_pentest_agent', '.env'))

    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <domain>")
        sys.exit(1)

    target_domain = sys.argv[1]
    available_tools = get_available_tools()
    wordlist_path = "llm_pentest_agent/wordlist.txt"
    attack_context = {"target": target_domain, "history": []}

    print("\n--- Round 1: Initial Reconnaissance ---")
    subdomains = run_subfinder(target_domain)
    if not subdomains:
        return
    attack_context["history"].append({"action": f"run_subfinder {target_domain}", "output": "\n".join(subdomains)})

    print("\n--- Round 1: Initial Planning ---")
    initial_prompt = f"""
    You are a senior penetration tester. Your target is {target_domain}.
    You have discovered the following subdomains:
    {subdomains}
    
    Your available tools are: {available_tools}.
    - Use 'nuclei -u <URL>' for broad, fast scanning of known vulnerabilities (1-day).
    - Use 'nmap', 'feroxbuster', and 'curl' for deeper, manual-like investigation (0-day).
    - For feroxbuster, you MUST use the wordlist at '{wordlist_path}'.

    Create a JSON plan that mixes these tools. For example, run nuclei on the main domain and nmap on the API domain.
    Format: {{"plan": [{{"target": "<subdomain>", "rationale": "<why>", "actions": ["<command>"]}}]}}
    Limit the initial plan to 2-3 high-impact actions.
    """
    strategy_json = ask_llm(initial_prompt)
    if not strategy_json: return
    try:
        plan = json.loads(strategy_json)
        initial_actions = [action for target in plan.get("plan", []) for action in target.get("actions", [])]
    except (json.JSONDecodeError, AttributeError): return

    print("\n--- Round 1: Execution ---")
    round_1_results = execute_actions(initial_actions)
    attack_context["history"].extend(round_1_results)

    print("\n--- Round 2: Analysis and Planning ---")
    analysis_prompt = f"""
    You are a senior penetration tester. Here is the history of your actions and their summarized results:
    {json.dumps(attack_context, indent=2)}

    Based on these results, it's time to stop scanning and start probing for logical (0-day) vulnerabilities.
    Formulate a creative hypothesis about a potential flaw (e.g., IDOR, parameter tampering, authentication bypass).
    Then, propose a single, specific `curl` command to test this hypothesis.

    Your output MUST be a JSON object with two keys:
    1. "hypothesis": A string describing your theory (e.g., "The endpoint /api/users/{{id}} might be vulnerable to IDOR").
    2. "next_action": The single `curl` command to test the hypothesis.
    """
    next_action_json = ask_llm(analysis_prompt)
    if not next_action_json: return
    try:
        next_action = json.loads(next_action_json).get("next_action")
    except (json.JSONDecodeError, AttributeError): return

    if next_action:
        print("\n--- Round 2: Execution ---")
        execute_actions([next_action])
    else:
        print("\n[*] LLM concluded there are no more actions to take.")

    print("\n[*] Agent has completed its planned execution cycles.")

if __name__ == "__main__":
    main()