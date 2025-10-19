## Project Chimera – 작업 노트

### 왜 만들었나
- 레드팀 업무 중 **정찰 → 스캔 → 인증 유지 → 후속 공격** 흐름이 끊기지 않도록 자동화해보고 싶었다.
- LLM을 보고서용이 아니라, 내가 쓰는 도구들을 **순서대로 돌려주는 조수**로 쓰자고 마음먹었다.

### 어떻게 굴러가는가
1. 도메인을 넣으면 `subfinder`가 하위 호스트를 모은다.  
2. 열린 포트는 `nmap -F`로 빠르게 체크한다.  
3. OWASP ZAP 컨테이너를 띄워 Spider/Active Scan/Fuzzer를 API로 호출한다.  
4. 로그인 세션은 쿠키/토큰 형태로 DB에 저장하고, 이후 `curl`, `zap_send_request`, `zap_fuzzer` 실행 시 자동으로 붙인다.  
5. 필요한 경우 ZAP 스크립트를 대시보드에서 바로 등록해서 주입 공격이나 맞춤 검사에 사용한다.  
6. LLM은 DB 내용(자산, 포트, 취약점)을 보고 다음에 어떤 명령을 실행할지 JSON 형식으로 전달하고, API가 그대로 수행한다.

### 내가 구현한 것
- FastAPI 백엔드와 Next.js 대시보드, SQLite 스키마 설계.
- ZAP Docker 환경과 API 연동, 스크립트 파일을 임시 생성해 업로드하는 로직.
- 세션 저장소(`sessions` 테이블)와 자동 헤더 주입 함수 (`run_curl`, `run_zap_send_request`, `run_zap_fuzzer`).
- LLM 프롬프트: 사용할 명령을 명시해서 엉뚱한 호출을 막고, 결과는 JSON만 받도록 강제.
- UI: 자산/세션/오케스트레이션/정찰/공격 경로/스크립트 탭으로 나눠 JSON 덤프 대신 요약 정보를 보여준다.

### 세부 구현 메모
- **DB 스키마**  
  ```sql
  assets(id, domain, subdomain UNIQUE)  
  vulnerabilities(id, asset_id FK, finding, severity)  
  sessions(id, domain UNIQUE, cookies JSON, headers JSON, updated_at)
  ```  
  `sessions`가 생기면서 `auth_login`으로 들어온 쿠키/토큰을 도메인 단위로 덮어쓴다. 하위 호스트는 `foo.api.example.com` → `api.example.com` → `example.com` 순으로 검색.

- **세션 주입 코드**  
  ```python
  session_headers = get_session_headers_for_host(parsed.hostname)
  parts = _inject_session_into_curl(parts, session_headers)
  ```
  `curl` 호출 시 이미 `-H "Authorization: ..."`이 있으면 덮어쓰지 않는다. 쿠키는 `--cookie`가 없으면 붙인다.

- **ZAP 요청**  
  `zap_send_request`와 `zap_fuzzer` 두 군데에서 `_merge_headers_with_session()`을 호출한다. Host 헤더가 비어 있으면 직접 넣어줘야 ZAP가 제대로 중계한다.

- **스크립트 업로드**  
  ZAP API가 파일 경로를 요구해서 `tempfile.NamedTemporaryFile(delete=False)`로 임시 파일 작성 → `zap.script.load(...)` 호출 → `finally`에서 파일 삭제. LLM이 payload로 `{name, script_type, script_engine, content}`를 넘겨주면 그대로 처리.

- **오케스트레이터 명령 세트**  
  ```
  nmap -F target.com
  zap_scan --target https://target.com
  zap_fuzzer --target_url https://app/FUZZ --payloads '["admin","backup"]'
  auth_login --domain target.com --login-url https://target.com/login --json-body '{"id":"tester","pw":"pass"}'
  zap_load_script --payload '{"name":"xsser","script_type":"standalone","script_engine":"ECMAScript","content":"..."}'
  ```
  FastAPI에서 `shlex.split` 후 argparse로 파싱하고, 모르는 명령은 그대로 에러 처리.

- **프롬프트 예시**  
  ```
  Your available tools are [...].
  Format: {"plan":[{"target":"<subdomain>","actions":["command ..."]}]}
  ```
  Hypothesis 단계에서는 “auth_login, curl, zap_send_request, zap_fuzzer, zap_run_script 중에서 한 가지”를 선택하도록 안내.

### 사용 기술
- FastAPI + SQLite  
- OWASP ZAP (Docker)  
- subfinder, nmap  
- OpenAI GPT-4o (JSON 응답 모드)  
- Next.js + Tailwind

### 실행 순서
```bash
docker compose up zap -d
cd backend && uvicorn backend.main:app --reload --port 8000
cd frontend && npm run dev
```
- `scripts/.env`에 `OPENAI_API_KEY` 필수.

### 써보면서 알게 된 점
- 세션이 끊기지 않으니 인증이 필요한 API에서도 LLM이 바로 다음 테스트로 넘어갈 수 있었다.
- ZAP 스크립트를 바로 올려 쓰니까 페이로드 커스터마이징이 빨라졌다.
- 탭 UI 덕분에 팀 공유가 쉬워졌고, 이전처럼 JSON을 통째로 복붙하지 않아도 됐다.

### 앞으로 보완하고 싶은 부분
- 정찰 점수(휴리스틱) 보정: 실 데이터로 가중치 튜닝 + LLM 검증 레이어 추가.
- Docker Compose 기반 CI: ZAP까지 띄운 뒤 API 헬스체크 자동화.
- 세션/자산 멀티 테넌트 처리: 사용자별로 격리.
- 오케스트레이션 로그 뷰어: 액션 기록을 타임라인으로 재가공.
