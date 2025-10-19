import sys
from fastapi import APIRouter, HTTPException
import shlex
import argparse
import json

from ..models.scan import ScanRequest
from ..models.auth import LoginRequest
from ..core.orchestrator import create_scan_plan, create_hypothesis_and_action
from ..core.authentication import login_and_store_session
from ..core.scanner import (
    run_nmap,
    run_zap_scan,
    run_curl,
    run_zap_spider,
    run_zap_custom_scan,
    run_zap_send_request,
    run_zap_fuzzer,
    run_zap_script as execute_zap_script,
    load_zap_script as upload_zap_script,
)
from ..db.database import get_db_connection

router = APIRouter()

def execute_plan(plan: dict):
    """
    Executes a plan from the LLM.
    """
    results = []
    for target_info in plan.get("plan", []):
        actions = target_info.get("actions", [])
        
        for action_str in actions:
            print(f"[*] Orchestrator executing: {action_str}")
            parts = shlex.split(action_str)
            tool = parts[0]

            try:
                if tool == "nmap":
                    parser = argparse.ArgumentParser()
                    parser.add_argument("-F", dest="target")
                    args = parser.parse_args(parts[1:])
                    output = run_nmap(args.target)
                    # Save results
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("SELECT id FROM assets WHERE subdomain = ?", (args.target,))
                    asset_id_row = cursor.fetchone()
                    asset_id = asset_id_row["id"] if asset_id_row else None
                    if asset_id:
                        for port_info in output:
                            cursor.execute("INSERT INTO vulnerabilities (asset_id, finding, severity) VALUES (?, ?, ?)",
                                           (asset_id, f"Open Port: {port_info}", "info"))
                        conn.commit()
                    conn.close()
                    results.append({"action": action_str, "status": "success", "output": output})

                elif tool == "zap_scan":
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--target", "--url")
                    args = parser.parse_args(parts[1:])
                    output = run_zap_scan(args.target)
                    results.append({"action": action_str, "status": "success", "output": output})

                elif tool == "zap_spider":
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--target", "--url")
                    args = parser.parse_args(parts[1:])
                    output = run_zap_spider(args.target)
                    results.append({"action": action_str, "status": "success", "output": output})

                elif tool == "zap_custom_scan":
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--target", "--url")
                    parser.add_argument("--policy")
                    args = parser.parse_args(parts[1:])
                    output = run_zap_custom_scan(args.target, args.policy)
                    results.append({"action": action_str, "status": "success", "output": output})
                
                elif tool == "zap_fuzzer":
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--target_url", "--url")
                    parser.add_argument("--payloads", type=json.loads)
                    args = parser.parse_args(parts[1:])
                    output = run_zap_fuzzer(args.target_url, args.payloads)
                    results.append({"action": action_str, "status": "success", "output": output})

                elif tool == "auth_login":
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--domain", required=True)
                    parser.add_argument("--login-url", dest="login_url", required=True)
                    parser.add_argument("--method", default="POST")
                    parser.add_argument("--headers", type=json.loads, default=None)
                    parser.add_argument("--body", default=None)
                    parser.add_argument("--json-body", dest="json_body", type=json.loads, default=None)
                    parser.add_argument("--token-path", dest="token_path", default=None)
                    parser.add_argument("--token-prefix", dest="token_prefix", default="Bearer ")
                    parser.add_argument("--token-header", dest="token_header", default="Authorization")
                    parser.add_argument("--persist-headers", dest="persist_headers", type=json.loads, default=None)
                    args = parser.parse_args(parts[1:])
                    login_payload = LoginRequest(
                        domain=args.domain,
                        login_url=args.login_url,
                        method=args.method,
                        headers=args.headers,
                        body=args.body,
                        json_body=args.json_body,
                        token_path=args.token_path,
                        token_prefix=args.token_prefix,
                        token_header_name=args.token_header,
                        persist_response_headers=args.persist_headers,
                    )
                    output = login_and_store_session(login_payload)
                    results.append({"action": action_str, "status": "success", "output": output.dict()})

                elif tool == "zap_run_script":
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--name", required=True)
                    args = parser.parse_args(parts[1:])
                    output = execute_zap_script(args.name)
                    results.append({"action": action_str, "status": "success", "output": output})

                elif tool == "zap_load_script":
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--payload", type=json.loads, required=True)
                    args = parser.parse_args(parts[1:])
                    payload = args.payload
                    try:
                        script_name = payload["name"]
                        script_type = payload.get("script_type") or payload.get("type")
                        script_engine = payload.get("script_engine") or payload.get("engine")
                        script_content = payload["content"]
                        description = payload.get("description")
                    except KeyError as missing:
                        raise ValueError(f"Missing script field: {missing}") from missing
                    if not script_type or not script_engine:
                        raise ValueError("Payload must include 'script_type' and 'script_engine'.")

                    output = upload_zap_script(
                        script_name=script_name,
                        script_type=script_type,
                        script_engine=script_engine,
                        script_content=script_content,
                        description=description,
                    )
                    results.append({"action": action_str, "status": "success", "output": output})

                elif tool == "curl":
                    output = run_curl(action_str)
                    results.append({"action": action_str, "status": "success", "output": output})

                elif tool == "zap_send_request":
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--target_url", "--url")
                    parser.add_argument("--method", default="GET")
                    parser.add_argument("--headers", default="{}")
                    parser.add_argument("--body", default="")
                    args = parser.parse_args(parts[1:])
                    headers = args.headers
                    if not isinstance(headers, dict):
                        headers = json.loads(headers or "{}")
                    output = run_zap_send_request(args.target_url, args.method, headers, args.body)
                    results.append({"action": action_str, "status": "success", "output": output})

                else:
                    print(f"[!] Orchestrator: Unknown tool '{tool}'")
                    results.append({"action": action_str, "status": "error", "output": f"Error: Unknown tool '{tool}'"})
            
            except Exception as e:
                error_msg = f"Error executing action '{action_str}': {e}"
                print(f"[!] {error_msg}", file=sys.stderr)
                results.append({"action": action_str, "status": "error", "output": error_msg})

    return results


@router.post("/orchestrate/next-step")
def orchestrate_next_step(scan_request: ScanRequest):
    """
    Gets the next logical step from the orchestrator and executes it.
    """
    try:
        # 1. Get a plan from the LLM based on current DB state
        print(f"[*] Orchestrator creating plan for {scan_request.domain}...")
        initial_plan = create_scan_plan(scan_request.domain)
        if not initial_plan or not initial_plan.get("plan"):
            return {"message": "Orchestrator did not produce a valid initial plan."}
        
        print(f"[*] Orchestrator received initial plan: {initial_plan}")

        # 2. Execute the initial plan
        initial_execution_results = execute_plan(initial_plan)

        # 3. Create a history for the hypothesis generation
        history = [{
            "plan": initial_plan,
            "execution_results": initial_execution_results
        }]

        # 4. Generate a hypothesis and a specific curl action
        print("[*] Orchestrator creating hypothesis...")
        hypothesis_plan = create_hypothesis_and_action(scan_request.domain, history)
        if not hypothesis_plan or not hypothesis_plan.get("next_action"):
            return {
                "message": "Orchestrator did not produce a hypothesis.",
                "initial_plan": initial_plan,
                "initial_execution_results": initial_execution_results
            }
        
        print(f"[*] Orchestrator received hypothesis: {hypothesis_plan}")

        # 5. Execute the hypothesis action
        hypothesis_action = hypothesis_plan.get("next_action")
        hypothesis_execution_result = execute_plan({"plan": [{"actions": [hypothesis_action]}]})

        return {
            "initial_plan": initial_plan,
            "initial_execution_results": initial_execution_results,
            "hypothesis_plan": hypothesis_plan,
            "hypothesis_execution_result": hypothesis_execution_result
        }
    except Exception as e:
        print(f"[!] Error in orchestration: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail=str(e))
