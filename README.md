# Project Chimera: LLM 기반 위협 오케스트레이션 플랫폼

> 넓게 보고(Broad Reconnaissance), 깊게 찌르며(Deep Strikes), 지능적으로 지휘한다(Intelligent Orchestration).

## 1. 핵심 컨셉 (Core Concept)

'Project Chimera'는 최신 LLM 기술을 활용하여, 기존의 공격 표면 관리(ASM)와 자동 침투 테스트를 유기적으로 결합한 차세대 보안 플랫폼입니다.

본 플랫폼은 LLM이 단순히 스크립트를 실행하는 것을 넘어, 여러 전문 보안 도구들을 목적에 맞게 지휘하는 **'오케스트레이터(Orchestrator)'** 역할을 수행합니다. 이를 통해, 넓은 범위의 자산을 지속적으로 관리하면서도, 발견된 핵심 위협에 대해서는 인간 전문가처럼 깊이 있는 공격을 자동으로 수행합니다.

## 2. 아키텍처 (Architecture)

플랫폼은 세 가지 핵심 엔진과 하나의 중앙 지능으로 구성됩니다.

### 2.1. ASM 엔진 (The Net - 정찰 및 1-day 스캔)
- **역할:** 조직의 전체 디지털 자산을 식별하고, 알려진 위협에 대해 지속적으로 모니터링합니다.
- **주요 도구:** `subfinder`, `nmap`
- **프로세스:**
    1. 주기적으로 전체 자산에 대한 하위 도메인, 오픈 포트를 스캔합니다.
    2. 모든 결과를 데이터베이스(SQLite)에 저장하고, 대시보드에 표시합니다.

### 2.2. Active Scan 엔진 (The Spear - 능동적 분석 및 0-day 탐색)
- **역할:** 식별된 고위험 타겟에 대해 심층적인 동적 분석 및 익스플로잇을 시도합니다.
- **주요 도구:** **OWASP ZAP (API)**, `curl`
- **상세 기능:** 백엔드는 ZAP API와 연동하여 LLM에게 다음과 같은 버프슈트와 유사한 정밀 제어 기능을 제공합니다:
    - `zap_scan`: 타겟에 대한 기본 액티브 스캔을 수행합니다.
    - `zap_custom_scan`: SQL 인젝션, XSS 등 특정 정책으로 스캔을 집중합니다.
    - `zap_spider`: 타겟의 URL 구조를 파악합니다.
    - `zap_fuzzer`: LLM이 생성한 동적 페이로드로 특정 엔드포인트를 퍼징합니다.
    - `zap_send_request`: 특정 요청을 가로채서 수정 후 재전송하는 것과 유사한 기능을 수행합니다.

### 2.3. LLM 오케스트레이터 (The Brain - 분석 및 지휘)
- **역할:** 두 엔진의 지휘관이자, 데이터 분석가, 그리고 모의 해커의 역할을 모두 수행합니다.
- **프로세스:**
    1. **(초기 계획 수립):** DB의 자산 및 취약점 정보를 분석하여 `nmap`, `zap_scan` 등을 사용한 초기 정찰 및 스캔 계획을 수립하고 실행합니다.
    2. **(가설 수립 및 검증):** 초기 실행 결과를 분석하여 IDOR, 파라미터 변조 등 논리적 취약점에 대한 가설을 세웁니다.
    3. **(심층 공격):** 수립된 가설을 검증하기 위해 `curl`, `zap_fuzzer`, `zap_send_request` 등을 사용한 구체적인 다음 행동(Next Action)을 생성하고 실행합니다.

## 3. 고도화된 주요 기능 (Key Features)

- **능동적 익스플로잇 (Active Exploit):**
  - OWASP ZAP과의 연동을 통해, 단순 스캔을 넘어 안전한 범위 내에서 실제 취약점 공격을 시도하고 성공 여부를 검증합니다.
- **인증 및 세션 관리 (Authentication & Session Management):**
  - LLM이 로그인 과정을 수행하고, 획득한 세션 쿠키/토큰을 후속 ZAP 요청에 자동으로 포함하여 인증된 엔드포인트를 테스트합니다.
- **ZAP 스크립팅 엔진 연동 (ZAP Scripting Engine Integration):**
  - LLM이 사전 정의된 ZAP 스크립트를 실행하거나, 상황에 맞는 스크립트를 동적으로 생성하여 복잡하고 창의적인 공격을 수행합니다.
- **공격 경로 모델링 (Attack Path Modeling):**
  - LLM이 개별 취약점을 넘어, 'A서버의 정보 유출'과 'B서버의 SSRF 취약점'을 조합하여 내부망에 침투하는 것과 같은 연계 공격 시나리오를 예측하고 검증합니다.
- **고급 정찰 (Advanced Reconnaissance):**
  - GitHub 코드 유출, 클라우드 스토리지 설정 오류, JavaScript 내 숨겨진 정보 분석 등 비전통적인 경로로 공격 표면을 확장합니다.
- **세션 기반 오케스트레이션 (Session-Aware Orchestration):**
  - 대시보드에서 인증 정보를 등록하면 백엔드가 쿠키·토큰을 저장하고, 이후 `curl`, `zap_send_request`, `zap_fuzzer` 호출에 자동으로 포함시켜 인증된 경로를 지속적으로 테스트합니다.

## 4. 제안 기술 스택 (Tech Stack)

- **Backend:** Python (FastAPI)
- **Frontend:** TypeScript, Next.js (React)
- **Database:** SQLite (초기) -> PostgreSQL (확장)
- **Core Engines:** `subfinder`, `nmap`, `OWASP ZAP` (API via Docker), `curl`
- **LLM:** GPT-4o 또는 후속 모델

## 5. 개발 로드맵 (Roadmap)

1.  **Phase 1 (Foundation):**
    -   [x] FastAPI 백엔드, Next.js 프론트엔드, SQLite DB 기본 프로젝트 구조 설정.
2.  **Phase 2 (Basic ASM):**
    -   [x] 자산 발견(`subfinder`) 및 기본 포트 스캔(`nmap`) 기능 구현.
    -   [x] 스캔 결과를 DB에 저장하고, 대시보드에 시각화.
    -   *Note: `nuclei`는 더 정교한 ZAP 연동을 위해 현재 구현에서 제외됨.*
3.  **Phase 3 (Orchestration & Active Scan):**
    -   [x] **분석가 모드:** LLM이 DB 데이터를 분석하여 위험 타겟을 선정하고 초기 스캔 계획을 수립하는 기능 구현.
    -   [x] **오케스트레이터 모드:** OWASP ZAP API와 연동하여 `zap_scan`, `zap_custom_scan`, `zap_spider`, `zap_fuzzer` 등 다양한 스캔을 지휘하는 기능 구현.
    -   [x] **모의 해커 모드:** 스캔 결과를 바탕으로 LLM이 가설을 수립하고, `curl` 또는 `zap_send_request`를 통해 검증하는 2단계 공격 흐름 구현.
4.  **Phase 4 (Advanced Features):**
    -   [x] '고급 정찰' 및 '공격 경로 모델링' 기능 탑재.
5.  **Phase 5 (Future Work):**
    -   [x] **인증 및 세션 관리:** LLM이 인증된 세션을 유지하며 테스트를 수행하는 기능 구현.
    -   [x] **ZAP 스크립팅:** LLM이 ZAP 스크립트를 선택하거나 직접 생성하여 공격을 수행하는 기능 구현.
    -   [ ] **고급 정찰 정확도 향상:** 휴리스틱 튜닝 및 LLM 검증 단계를 도입하여 우선순위 신뢰도를 높입니다.

## 6. 다른 프로젝트 이름 제안 (Alternative Names)

- Synapse-ASM
- Cortex-Vanguard
- Threat-Orchestrator
