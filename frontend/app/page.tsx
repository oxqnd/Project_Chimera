'use client'

import { useEffect, useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

type Vulnerability = {
  finding: string
  severity: string
}

interface Asset {
  subdomain: string
  vulnerabilities: Vulnerability[] | null
  scanStatus: "idle" | "scanned" | "scanning"
}

type ReconInsight = {
  asset: string | null
  signals: string[]
  recommended_actions: string[]
  confidence: "low" | "medium" | "high"
  score: number
}

type AttackPathStep = {
  step: number
  description: string
  asset?: string | null
  evidence?: string | null
}

type AttackPath = {
  name: string
  risk: "low" | "medium" | "high"
  narrative: string
  steps: AttackPathStep[]
}

type SessionInfo = {
  domain: string
  status_code: number
  cookies: Record<string, string>
  headers: Record<string, string>
  body_preview: string
}

type ZapScript = {
  name: string
  type?: string
  engine?: string
  enabled?: string | boolean
  description?: string
}

const RESULT_TABS = ["assets", "session", "orchestration", "recon", "paths", "scripts"] as const
type ResultTab = (typeof RESULT_TABS)[number]

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
const SCRIPT_TYPES = ["standalone", "proxy", "targeted", "authentication", "passive"]
const SCRIPT_ENGINES = ["ECMAScript", "Python", "Zest", "WebSockets"]

const textareaStyle = "w-full min-h-[120px] rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
const selectStyle = "h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"

export default function ChimeraDashboard() {
  const [domain, setDomain] = useState("")
  const [assets, setAssets] = useState<Asset[]>([])
  const [error, setError] = useState<string | null>(null)
  const [isDiscovering, setIsDiscovering] = useState(false)
  const [isScanningZap, setIsScanningZap] = useState<Record<string, boolean>>({})
  const [isScanningNmap, setIsScanningNmap] = useState<Record<string, boolean>>({})
  const [isOrchestrating, setIsOrchestrating] = useState(false)
  const [orchestrationResult, setOrchestrationResult] = useState<any | null>(null)
  const [reconInsights, setReconInsights] = useState<ReconInsight[]>([])
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([])
  const [isRunningRecon, setIsRunningRecon] = useState(false)
  const [isModelingAttackPaths, setIsModelingAttackPaths] = useState(false)
  const [activeResultTab, setActiveResultTab] = useState<ResultTab>("assets")

  const [sessionInfo, setSessionInfo] = useState<SessionInfo | null>(null)
  const [isAuthenticating, setIsAuthenticating] = useState(false)
  const [isFetchingSession, setIsFetchingSession] = useState(false)
  const [isClearingSession, setIsClearingSession] = useState(false)
  const [authConfig, setAuthConfig] = useState({
    loginUrl: "",
    method: "POST",
    mode: "json" as "json" | "raw",
    body: "",
    contentType: "application/json",
    customHeaders: "{}",
    tokenPath: "",
    tokenPrefix: "Bearer ",
    tokenHeader: "Authorization",
    persistHeaders: "[]",
  })

  const [availableScripts, setAvailableScripts] = useState<ZapScript[]>([])
  const [isSubmittingScript, setIsSubmittingScript] = useState(false)
  const [isLoadingScriptList, setIsLoadingScriptList] = useState(false)
  const [isRunningScript, setIsRunningScript] = useState(false)
  const [isDeletingScript, setIsDeletingScript] = useState(false)
  const [scriptRunResult, setScriptRunResult] = useState<any | null>(null)
  const [scriptForm, setScriptForm] = useState({
    name: "",
    type: "standalone",
    engine: "ECMAScript",
    content: "",
    description: "",
  })

  const resetResults = () => {
    setOrchestrationResult(null)
    setReconInsights([])
    setAttackPaths([])
    setSessionInfo(null)
    setAvailableScripts([])
    setScriptRunResult(null)
    setActiveResultTab("assets")
  }

  const handleDiscoverAssets = async () => {
    if (!domain.trim()) {
      setError("Please enter a valid domain")
      return
    }
    setError(null)
    setIsDiscovering(true)
    setAssets([])
    resetResults()

    try {
      const response = await fetch("http://localhost:8000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      })
      if (!response.ok) {
        const errText = await response.text()
        throw new Error(`API Error: ${errText}`)
      }
      const data = await response.json()
      if (data.error) throw new Error(data.error)
      setAssets(data.subdomains.map((sub: string) => ({ subdomain: sub, vulnerabilities: [], scanStatus: "idle" })))
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsDiscovering(false)
    }
  }

  const handleRunNmapScan = async (subdomain: string) => {
    setIsScanningNmap(prev => ({ ...prev, [subdomain]: true }))
    setError(null)

    try {
      const response = await fetch("http://localhost:8000/api/scan/nmap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: subdomain }),
      })
      if (!response.ok) {
        const errText = await response.text()
        throw new Error(`API Error: ${errText}`)
      }
      const data = await response.json()
      if (data.error) throw new Error(data.error)

      const newVulnerabilities: Vulnerability[] = (data.open_ports || []).map((port: string) => ({
        finding: `Open Port: ${port}`,
        severity: "info",
      }))

      setAssets(prevAssets =>
        prevAssets.map(asset =>
          asset.subdomain === subdomain
            ? { ...asset, vulnerabilities: [...(asset.vulnerabilities || []), ...newVulnerabilities], scanStatus: "scanned" }
            : asset,
        ),
      )
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsScanningNmap(prev => ({ ...prev, [subdomain]: false }))
    }
  }

  const handleRunZapScan = async (subdomain: string) => {
    setIsScanningZap(prev => ({ ...prev, [subdomain]: true }))
    setError(null)

    try {
      const response = await fetch("http://localhost:8000/api/scan/zap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: subdomain }),
      })
      if (!response.ok) {
        const errText = await response.text()
        throw new Error(`API Error: ${errText}`)
      }
      const data = await response.json()
      if (data.error) throw new Error(data.error)

      setAssets(prevAssets =>
        prevAssets.map(asset =>
          asset.subdomain === subdomain ? { ...asset, vulnerabilities: data.vulnerabilities || [], scanStatus: "scanned" } : asset,
        ),
      )

      setReconInsights([])
      setAttackPaths([])
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsScanningZap(prev => ({ ...prev, [subdomain]: false }))
    }
  }

  const handleOrchestrate = async () => {
    if (!domain.trim()) {
      setError("Please enter a domain and discover assets first.")
      return
    }
    setError(null)
    setIsOrchestrating(true)
    setOrchestrationResult(null)

    try {
      const response = await fetch("http://localhost:8000/api/orchestrate/next-step", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      })
      if (!response.ok) {
        const errText = await response.text()
        throw new Error(`API Error: ${errText}`)
      }
      const data = await response.json()
      if (data.error) throw new Error(data.error)
      setOrchestrationResult(data)
      setActiveResultTab("orchestration")
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsOrchestrating(false)
    }
  }

  const handleAdvancedRecon = async () => {
    if (!domain.trim()) {
      setError("Please enter a domain before running advanced reconnaissance.")
      return
    }
    setError(null)
    setIsRunningRecon(true)

    try {
      const response = await fetch("http://localhost:8000/api/advanced/recon", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      })
      if (!response.ok) {
        const message = await response.text()
        throw new Error(`Advanced Recon Error: ${message}`)
      }
      const data = await response.json()
      setReconInsights(data)
      setActiveResultTab("recon")
    } catch (e: any) {
      setError(e.message)
      setReconInsights([])
    } finally {
      setIsRunningRecon(false)
    }
  }

  const handleAttackPathModeling = async () => {
    if (!domain.trim()) {
      setError("Please enter a domain before modeling attack paths.")
      return
    }
    setError(null)
    setIsModelingAttackPaths(true)

    try {
      const response = await fetch("http://localhost:8000/api/advanced/attack-paths", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      })
      if (!response.ok) {
        const message = await response.text()
        throw new Error(`Attack Path Error: ${message}`)
      }
      const data = await response.json()
      setAttackPaths(data)
      setActiveResultTab("paths")
    } catch (e: any) {
      setError(e.message)
      setAttackPaths([])
    } finally {
      setIsModelingAttackPaths(false)
    }
  }

  const parseJsonInput = <T,>(value: string, fallback: T): T => {
    try {
      return value.trim() ? (JSON.parse(value) as T) : fallback
    } catch (err) {
      throw new Error("Invalid JSON input.")
    }
  }

  const handleAuthenticate = async () => {
    if (!domain.trim()) {
      setError("Please provide a domain before authenticating.")
      return
    }
    if (!authConfig.loginUrl.trim()) {
      setError("Login URL is required.")
      return
    }

    setError(null)
    setIsAuthenticating(true)

    try {
      const payload: Record<string, any> = {
        domain: domain.trim(),
        login_url: authConfig.loginUrl.trim(),
        method: authConfig.method,
      }

      let headers: Record<string, string> = {}
      if (authConfig.mode === "json") {
        const jsonBody = parseJsonInput<Record<string, any>>(authConfig.body || "{}", {})
        payload.json_body = jsonBody
        headers["Content-Type"] = "application/json"
      } else {
        payload.body = authConfig.body
        if (authConfig.contentType.trim()) {
          headers["Content-Type"] = authConfig.contentType.trim()
        }
      }

      if (authConfig.customHeaders.trim()) {
        const custom = parseJsonInput<Record<string, string>>(authConfig.customHeaders, {})
        headers = { ...headers, ...custom }
      }

      if (Object.keys(headers).length > 0) {
        payload.headers = headers
      }

      if (authConfig.tokenPath.trim()) {
        payload.token_path = authConfig.tokenPath.trim()
      }
      if (authConfig.tokenPrefix !== undefined) {
        payload.token_prefix = authConfig.tokenPrefix
      }
      if (authConfig.tokenHeader.trim()) {
        payload.token_header_name = authConfig.tokenHeader.trim()
      }

      if (authConfig.persistHeaders.trim()) {
        const persist = parseJsonInput<string[]>(authConfig.persistHeaders, [])
        if (persist.length > 0) {
          payload.persist_response_headers = persist
        }
      }

      const response = await fetch("http://localhost:8000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })
      if (!response.ok) {
        const message = await response.text()
        throw new Error(`Authentication Error: ${message}`)
      }
      const data = await response.json()
      setSessionInfo(data)
      setActiveResultTab("session")
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsAuthenticating(false)
    }
  }

  const handleFetchSession = async () => {
    if (!domain.trim()) {
      setError("Provide a domain to inspect stored session data.")
      return
    }
    setError(null)
    setIsFetchingSession(true)
    try {
      const response = await fetch(`http://localhost:8000/api/auth/sessions/${domain.trim()}`)
      if (!response.ok) {
        const message = await response.text()
        throw new Error(`Session Fetch Error: ${message}`)
      }
      const data = await response.json()
      if (!data) {
        setSessionInfo(null)
        setError("No session stored for the provided domain.")
        return
      }
      setSessionInfo(data)
      setActiveResultTab("session")
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsFetchingSession(false)
    }
  }

  const handleClearSession = async () => {
    if (!domain.trim()) {
      setError("Provide a domain to clear a session.")
      return
    }
    setError(null)
    setIsClearingSession(true)
    try {
      const response = await fetch(`http://localhost:8000/api/auth/sessions/${domain.trim()}`, {
        method: "DELETE",
      })
      if (!response.ok) {
        const message = await response.text()
        throw new Error(`Session Clear Error: ${message}`)
      }
      setSessionInfo(null)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsClearingSession(false)
    }
  }

  const normalizeScripts = (payload: any): ZapScript[] => {
    if (!payload) return []
    if (Array.isArray(payload)) return payload as ZapScript[]
    if (Array.isArray(payload.scripts)) return payload.scripts as ZapScript[]
    return []
  }

  const fetchScripts = async () => {
    setError(null)
    setIsLoadingScriptList(true)
    try {
      const response = await fetch("http://localhost:8000/api/zap/scripts")
      if (!response.ok) {
        const message = await response.text()
        throw new Error(`ZAP Script Error: ${message}`)
      }
      const data = await response.json()
      const scripts = normalizeScripts(data)
      setAvailableScripts(
        scripts.map(script => ({
          name: script.name || (script as any).scriptname || "",
          type: script.type || (script as any).type,
          engine: script.engine || (script as any).engine,
          enabled: script.enabled ?? (script as any).enabled,
          description: script.description,
        })),
      )
      if (scripts.length > 0) {
        setActiveResultTab("scripts")
      }
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsLoadingScriptList(false)
    }
  }

  const handleLoadScript = async () => {
    if (!scriptForm.name.trim()) {
      setError("Script name is required.")
      return
    }
    if (!scriptForm.content.trim()) {
      setError("Script content is required.")
      return
    }
    setError(null)
    setIsSubmittingScript(true)
    try {
      const payload = {
        name: scriptForm.name.trim(),
        script_type: scriptForm.type,
        script_engine: scriptForm.engine,
        content: scriptForm.content,
        description: scriptForm.description || undefined,
      }
      const response = await fetch("http://localhost:8000/api/zap/scripts/load", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })
      if (!response.ok) {
        const message = await response.text()
        throw new Error(`ZAP Script Upload Error: ${message}`)
      }
      const data = await response.json()
      setScriptRunResult({ message: "Script registered successfully.", response: data })
      await fetchScripts()
      setActiveResultTab("scripts")
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsSubmittingScript(false)
    }
  }

  const handleRunScript = async () => {
    if (!scriptForm.name.trim()) {
      setError("Provide the script name you wish to execute.")
      return
    }
    setError(null)
    setIsRunningScript(true)
    try {
      const response = await fetch("http://localhost:8000/api/zap/scripts/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: scriptForm.name.trim() }),
      })
      if (!response.ok) {
        const message = await response.text()
        throw new Error(`ZAP Script Run Error: ${message}`)
      }
      const data = await response.json()
      setScriptRunResult({ script: scriptForm.name.trim(), response: data })
      setActiveResultTab("scripts")
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsRunningScript(false)
    }
  }

  const handleDeleteScript = async () => {
    if (!scriptForm.name.trim()) {
      setError("Provide the script name you wish to delete.")
      return
    }
    setError(null)
    setIsDeletingScript(true)
    try {
      const response = await fetch(`http://localhost:8000/api/zap/scripts/${encodeURIComponent(scriptForm.name.trim())}`, {
        method: "DELETE",
      })
      if (!response.ok) {
        const message = await response.text()
        throw new Error(`ZAP Script Delete Error: ${message}`)
      }
      setScriptRunResult({ message: `Script ${scriptForm.name.trim()} removed.` })
      await fetchScripts()
      setActiveResultTab("scripts")
    } catch (e: any) {
      setError(e.message)
    } finally {
      setIsDeletingScript(false)
    }
  }

  const getBadgeVariant = (severity: string): "destructive" | "secondary" | "default" => {
    switch (severity.toLowerCase()) {
      case "high":
        return "destructive"
      case "medium":
        return "secondary"
      case "low":
        return "default"
      case "info":
        return "default"
      default:
        return "default"
    }
  }

  const riskBadgeVariant = useMemo(
    () =>
      ({
        high: "destructive" as const,
        medium: "secondary" as const,
        low: "default" as const,
      }),
    [],
  )

  const resultTabs = useMemo(
    () =>
      [
        { key: "assets" as ResultTab, label: `자산 (${assets.length})`, disabled: assets.length === 0 },
        { key: "session" as ResultTab, label: "세션", disabled: !sessionInfo },
        { key: "orchestration" as ResultTab, label: "오케스트레이션", disabled: !orchestrationResult },
        { key: "recon" as ResultTab, label: "고급 정찰", disabled: reconInsights.length === 0 },
        { key: "paths" as ResultTab, label: "공격 경로", disabled: attackPaths.length === 0 },
        {
          key: "scripts" as ResultTab,
          label: availableScripts.length > 0 ? `스크립트 (${availableScripts.length})` : "스크립트",
          disabled: availableScripts.length === 0 && !scriptRunResult,
        },
      ],
    [assets.length, sessionInfo, orchestrationResult, reconInsights.length, attackPaths.length, availableScripts.length, scriptRunResult],
  )

  useEffect(() => {
    const current = resultTabs.find(tab => tab.key === activeResultTab)
    if (current && !current.disabled) return

    const firstEnabled = resultTabs.find(tab => !tab.disabled)
    if (firstEnabled) {
      setActiveResultTab(firstEnabled.key)
    } else {
      setActiveResultTab("assets")
    }
  }, [resultTabs, activeResultTab])

  const renderAssetsTable = () => {
    if (assets.length === 0) {
      return <p className="text-sm text-muted-foreground">아직 수집된 자산이 없습니다. 먼저 `Discover Assets` 버튼으로 도메인을 정찰하세요.</p>
    }

    return (
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Subdomain</TableHead>
            <TableHead>Actions</TableHead>
            <TableHead>Vulnerabilities</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {assets.map(asset => (
            <TableRow key={asset.subdomain}>
              <TableCell className="font-mono text-sm">{asset.subdomain}</TableCell>
              <TableCell>
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => handleRunNmapScan(asset.subdomain)}
                    disabled={isScanningNmap[asset.subdomain]}
                  >
                    {isScanningNmap[asset.subdomain] ? "Scanning..." : "Run Nmap"}
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => handleRunZapScan(asset.subdomain)}
                    disabled={isScanningZap[asset.subdomain]}
                  >
                    {isScanningZap[asset.subdomain] ? "Scanning..." : "Run ZAP"}
                  </Button>
                </div>
              </TableCell>
              <TableCell>
                {asset.vulnerabilities && asset.vulnerabilities.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {asset.vulnerabilities.map((vuln, index) => (
                      <Badge key={index} variant={getBadgeVariant(vuln.severity)}>
                        {vuln.finding}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <span className="text-sm text-muted-foreground">No findings yet</span>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    )
  }

  const renderOrchestrationResult = () => {
    if (!orchestrationResult) {
      return <p className="text-sm text-muted-foreground">오케스트레이션 기록이 없습니다. 좌측 카드에서 `Let Chimera Decide`를 실행하세요.</p>
    }

    const planEntries = orchestrationResult.initial_plan?.plan || []
    const executionResults = orchestrationResult.initial_execution_results || []
    const hypothesisPlan = orchestrationResult.hypothesis_plan
    const hypothesisExecution = orchestrationResult.hypothesis_execution_result || []

    const renderOutput = (output: any) => {
      if (output === null || output === undefined) return "No output"
      if (typeof output === "string") return output
      try {
        return JSON.stringify(output, null, 2)
      } catch {
        return String(output)
      }
    }

    return (
      <div className="space-y-6">
        <section className="space-y-3">
          <h4 className="text-sm font-semibold text-foreground uppercase tracking-wide">Initial Plan</h4>
          {planEntries.length === 0 ? (
            <p className="text-sm text-muted-foreground">LLM이 실행할 계획을 반환하지 않았습니다.</p>
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {planEntries.map((entry: any, index: number) => (
                <div key={index} className="rounded-md border border-border/60 bg-muted/40 p-4 space-y-3">
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground">Target</p>
                    <p className="font-mono text-sm">{entry.target ?? "N/A"}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground">Rationale</p>
                    <p className="text-sm text-foreground">{entry.rationale ?? "—"}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground">Actions</p>
                    {Array.isArray(entry.actions) && entry.actions.length > 0 ? (
                      entry.actions.map((action: string, actionIndex: number) => (
                        <pre key={actionIndex} className="mt-1 rounded bg-background/80 p-2 text-xs font-mono whitespace-pre-wrap break-all">
                          {action}
                        </pre>
                      ))
                    ) : (
                      <p className="text-sm text-muted-foreground">No actions recorded.</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="space-y-3">
          <h4 className="text-sm font-semibold text-foreground uppercase tracking-wide">Execution Summary</h4>
          {executionResults.length === 0 ? (
            <p className="text-sm text-muted-foreground">실행된 액션이 없습니다.</p>
          ) : (
            <div className="space-y-2">
              {executionResults.map((result: any, index: number) => (
                <div key={index} className="rounded-md border border-border/60 bg-background/80 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <pre className="flex-1 rounded bg-muted/60 p-2 text-xs font-mono whitespace-pre-wrap break-all">{result.action}</pre>
                    <Badge variant={result.status === "success" ? "secondary" : "destructive"}>
                      {result.status?.toUpperCase?.() ?? "UNKNOWN"}
                    </Badge>
                  </div>
                  <details className="mt-2">
                    <summary className="cursor-pointer text-xs text-muted-foreground">View output</summary>
                    <pre className="mt-2 max-h-64 overflow-auto rounded bg-muted/40 p-3 text-xs font-mono whitespace-pre-wrap break-all">
                      {renderOutput(result.output)}
                    </pre>
                  </details>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="space-y-3">
          <h4 className="text-sm font-semibold text-foreground uppercase tracking-wide">Hypothesis</h4>
          {hypothesisPlan ? (
            <div className="space-y-4">
              <div className="rounded-md border border-border/60 bg-muted/30 p-4 space-y-3">
                <div>
                  <p className="text-xs uppercase tracking-wide text-muted-foreground">Theory</p>
                  <p className="mt-1 text-sm text-foreground">{hypothesisPlan.hypothesis ?? "—"}</p>
                </div>
                {hypothesisPlan.next_action && (
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground">Proposed Action</p>
                    <pre className="mt-1 rounded bg-background/80 p-2 text-xs font-mono whitespace-pre-wrap break-all">
                      {hypothesisPlan.next_action}
                    </pre>
                  </div>
                )}
              </div>
              {hypothesisExecution.length > 0 && (
                <div className="space-y-2">
                  {hypothesisExecution.map((result: any, index: number) => (
                    <div key={index} className="rounded-md border border-border/60 bg-background/80 p-4">
                      <div className="flex items-center justify-between gap-3">
                        <pre className="flex-1 rounded bg-muted/60 p-2 text-xs font-mono whitespace-pre-wrap break-all">{result.action}</pre>
                        <Badge variant={result.status === "success" ? "secondary" : "destructive"}>
                          {result.status?.toUpperCase?.() ?? "UNKNOWN"}
                        </Badge>
                      </div>
                      <details className="mt-2">
                        <summary className="cursor-pointer text-xs text-muted-foreground">View output</summary>
                        <pre className="mt-2 max-h-64 overflow-auto rounded bg-muted/40 p-3 text-xs font-mono whitespace-pre-wrap break-all">
                          {renderOutput(result.output)}
                        </pre>
                      </details>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">가설을 생성하지 않았습니다.</p>
          )}
        </section>
      </div>
    )
  }

  const renderReconInsights = () => {
    if (reconInsights.length === 0) {
      return <p className="text-sm text-muted-foreground">고급 정찰 데이터가 없습니다. 좌측 카드에서 `Derive Recon Insights`를 실행해 보세요.</p>
    }

    return (
      <div className="grid gap-4 md:grid-cols-2">
        {reconInsights.map((insight, index) => (
          <div key={`${insight.asset ?? "global"}-${index}`} className="rounded-md border border-border bg-muted/20 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs uppercase text-muted-foreground tracking-wide">Priority Score</p>
                <p className="text-2xl font-semibold text-foreground">{insight.score}</p>
              </div>
              <Badge variant={riskBadgeVariant[insight.confidence]}>
                {insight.confidence.toUpperCase()}
              </Badge>
            </div>
            <div>
              <p className="text-xs uppercase text-muted-foreground tracking-wide">Asset</p>
              <p className="font-mono text-sm">{insight.asset ?? "Domain-wide Insight"}</p>
            </div>
            <div className="space-y-2">
              <p className="text-xs uppercase text-muted-foreground tracking-wide">Signals</p>
              <ul className="list-disc pl-5 text-sm space-y-1">
                {insight.signals.map((signal, sIndex) => (
                  <li key={sIndex}>{signal}</li>
                ))}
              </ul>
            </div>
            <div className="space-y-2">
              <p className="text-xs uppercase text-muted-foreground tracking-wide">Recommended Actions</p>
              <ul className="list-disc pl-5 text-sm space-y-1">
                {insight.recommended_actions.map((action, aIndex) => (
                  <li key={aIndex}>{action}</li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>
    )
  }

  const renderAttackPaths = () => {
    if (attackPaths.length === 0) {
      return <p className="text-sm text-muted-foreground">공격 경로 모델링 결과가 없습니다. `Model Attack Paths` 버튼을 실행해 데이터를 모아보세요.</p>
    }

    return (
      <div className="space-y-4">
        {attackPaths.map((path, index) => (
          <div key={`${path.name}-${index}`} className="rounded-md border border-border bg-muted/20 p-4 space-y-3">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h4 className="text-lg font-semibold text-foreground">{path.name}</h4>
                <p className="text-sm text-muted-foreground">{path.narrative}</p>
              </div>
              <Badge variant={riskBadgeVariant[path.risk]}>
                {path.risk.toUpperCase()}
              </Badge>
            </div>
            <div className="space-y-2">
              {path.steps.map(step => (
                <div key={step.step} className="rounded-sm border border-border/60 bg-background/70 p-3">
                  <p className="text-sm font-medium text-foreground">
                    Step {step.step}: {step.description}
                  </p>
                  <div className="mt-1 flex flex-col gap-1 text-xs text-muted-foreground">
                    {step.asset && (
                      <span>
                        Asset: <span className="font-mono">{step.asset}</span>
                      </span>
                    )}
                    {step.evidence && <span>Evidence: {step.evidence}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    )
  }

  const renderSessionPanel = () => {
    if (!sessionInfo) {
      return <p className="text-sm text-muted-foreground">저장된 세션이 없습니다. 인증을 수행하거나 세션을 가져오세요.</p>
    }

    const renderKeyValue = (entries: [string, string][], emptyLabel: string) =>
      entries.length === 0 ? (
        <p className="text-sm text-muted-foreground">{emptyLabel}</p>
      ) : (
        <ul className="space-y-1 text-sm">
          {entries.map(([key, value]) => (
            <li key={key}>
              <span className="font-medium">{key}:</span> {value}
            </li>
          ))}
        </ul>
      )

    return (
      <div className="space-y-4">
        <div>
          <p className="text-xs uppercase tracking-wide text-muted-foreground">Domain</p>
          <p className="font-mono text-sm">{sessionInfo.domain}</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-muted-foreground">Last Status</p>
          <Badge variant={sessionInfo.status_code < 400 ? "secondary" : "destructive"}>
            {sessionInfo.status_code}
          </Badge>
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-muted-foreground">Cookies</p>
          {renderKeyValue(Object.entries(sessionInfo.cookies), "No cookies stored.")}
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-muted-foreground">Headers</p>
          {renderKeyValue(Object.entries(sessionInfo.headers), "No persistent headers stored.")}
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-muted-foreground">Body Preview</p>
          <pre className="mt-2 max-h-48 overflow-auto rounded bg-muted/40 p-3 text-xs font-mono whitespace-pre-wrap break-all">
            {sessionInfo.body_preview || "No response body captured."}
          </pre>
        </div>
      </div>
    )
  }

  const renderScriptsPanel = () => {
    if (availableScripts.length === 0 && !scriptRunResult) {
      return <p className="text-sm text-muted-foreground">등록된 스크립트가 없습니다. 좌측 카드에서 스크립트를 로드하세요.</p>
    }

    return (
      <div className="space-y-4">
        {availableScripts.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Available Scripts</p>
            <div className="space-y-2">
              {availableScripts.map(script => (
                <div key={script.name} className="rounded-md border border-border/60 bg-background/70 p-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-foreground">{script.name}</span>
                    {script.enabled !== undefined && (
                      <Badge variant={script.enabled ? "secondary" : "default"}>
                        {String(script.enabled).toUpperCase()}
                      </Badge>
                    )}
                  </div>
                  <div className="mt-1 flex flex-wrap gap-3 text-xs text-muted-foreground">
                    {script.type && <span>Type: {script.type}</span>}
                    {script.engine && <span>Engine: {script.engine}</span>}
                  </div>
                  {script.description && <p className="mt-2 text-xs text-muted-foreground">{script.description}</p>}
                </div>
              ))}
            </div>
          </div>
        )}
        {scriptRunResult && (
          <div>
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Last Script Response</p>
            <pre className="mt-2 max-h-64 overflow-auto rounded bg-muted/40 p-3 text-xs font-mono whitespace-pre-wrap break-all">
              {typeof scriptRunResult === "string" ? scriptRunResult : JSON.stringify(scriptRunResult, null, 2)}
            </pre>
          </div>
        )}
      </div>
    )
  }

  const renderResultsContent = () => {
    switch (activeResultTab) {
      case "assets":
        return renderAssetsTable()
      case "session":
        return renderSessionPanel()
      case "orchestration":
        return renderOrchestrationResult()
      case "recon":
        return renderReconInsights()
      case "paths":
        return renderAttackPaths()
      case "scripts":
        return renderScriptsPanel()
      default:
        return null
    }
  }

  const hasResults =
    assets.length > 0 ||
    sessionInfo !== null ||
    orchestrationResult ||
    reconInsights.length > 0 ||
    attackPaths.length > 0 ||
    availableScripts.length > 0 ||
    !!scriptRunResult

  return (
    <div className="dark min-h-screen bg-background py-12 px-4">
      <div className="mx-auto max-w-5xl space-y-8">
        <div className="space-y-2 text-center">
          <h1 className="text-4xl font-bold tracking-tight text-foreground">Project Chimera</h1>
          <p className="text-lg text-muted-foreground">LLM-Powered Threat Orchestration Platform</p>
        </div>

        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <Input
                placeholder="e.g., hackerone.com"
                value={domain}
                onChange={e => setDomain(e.target.value)}
                onKeyDown={e => {
                  if (e.key === "Enter") {
                    handleDiscoverAssets()
                  }
                }}
                className="flex-1"
              />
              <Button onClick={handleDiscoverAssets} disabled={isDiscovering} className="sm:w-40">
                {isDiscovering ? "Discovering..." : "Discover Assets"}
              </Button>
            </div>
          </CardContent>
        </Card>

        {error && (
          <Card className="border-destructive">
            <CardHeader>
              <CardTitle className="text-destructive">Error</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-destructive-foreground font-mono whitespace-pre-wrap break-words">{error}</p>
            </CardContent>
          </Card>
        )}

        <div className="grid gap-6 lg:grid-cols-[minmax(260px,1fr)_2fr]">
          <div className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Orchestrator</CardTitle>
                <CardDescription>현재 수집된 데이터를 기반으로 LLM이 다음 스텝을 제안합니다.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button onClick={handleOrchestrate} disabled={isOrchestrating || assets.length === 0} className="w-full">
                  {isOrchestrating ? "Orchestrating..." : "Let Chimera Decide"}
                </Button>
                {assets.length === 0 && (
                  <p className="text-xs text-muted-foreground">먼저 자산을 수집해야 오케스트레이션을 실행할 수 있습니다.</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Advanced Reconnaissance</CardTitle>
                <CardDescription>고위험 후보 자산을 자동으로 추려냅니다.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button onClick={handleAdvancedRecon} disabled={isRunningRecon || assets.length === 0} className="w-full">
                  {isRunningRecon ? "Running Recon..." : "Derive Recon Insights"}
                </Button>
                {assets.length === 0 && (
                  <p className="text-xs text-muted-foreground">자산이 수집된 이후 정찰을 실행할 수 있습니다.</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Attack Path Modeling</CardTitle>
                <CardDescription>발견된 요소들을 연결해 침투 시나리오를 구성합니다.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button onClick={handleAttackPathModeling} disabled={isModelingAttackPaths || assets.length === 0} className="w-full">
                  {isModelingAttackPaths ? "Modeling Paths..." : "Model Attack Paths"}
                </Button>
                {assets.length === 0 && (
                  <p className="text-xs text-muted-foreground">자산과 정찰 결과가 있어야 공격 경로를 모델링할 수 있습니다.</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Session Management</CardTitle>
                <CardDescription>로그인을 수행하고 획득한 세션을 저장합니다.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Input
                  placeholder="https://target/login"
                  value={authConfig.loginUrl}
                  onChange={e => setAuthConfig(prev => ({ ...prev, loginUrl: e.target.value }))}
                />
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <select
                    value={authConfig.method}
                    onChange={e => setAuthConfig(prev => ({ ...prev, method: e.target.value }))}
                    className={selectStyle}
                  >
                    {HTTP_METHODS.map(method => (
                      <option key={method} value={method}>
                        {method}
                      </option>
                    ))}
                  </select>
                  <select
                    value={authConfig.mode}
                    onChange={e =>
                      setAuthConfig(prev => ({
                        ...prev,
                        mode: e.target.value as "json" | "raw",
                        contentType: e.target.value === "json" ? "application/json" : prev.contentType,
                      }))
                    }
                    className={selectStyle}
                  >
                    <option value="json">JSON Body</option>
                    <option value="raw">Raw Body</option>
                  </select>
                </div>
                <textarea
                  className={textareaStyle}
                  placeholder={authConfig.mode === "json" ? '{"username": "alice", "password": "secret"}' : "username=alice&password=secret"}
                  value={authConfig.body}
                  onChange={e => setAuthConfig(prev => ({ ...prev, body: e.target.value }))}
                />
                <Input
                  placeholder="Content-Type"
                  value={authConfig.contentType}
                  disabled={authConfig.mode === "json"}
                  onChange={e => setAuthConfig(prev => ({ ...prev, contentType: e.target.value }))}
                />
                <Input
                  placeholder='Additional headers (JSON), e.g., {"X-Forwarded-For": "1.1.1.1"}'
                  value={authConfig.customHeaders}
                  onChange={e => setAuthConfig(prev => ({ ...prev, customHeaders: e.target.value }))}
                />
                <Input
                  placeholder="Token JSON path (e.g., data.access_token)"
                  value={authConfig.tokenPath}
                  onChange={e => setAuthConfig(prev => ({ ...prev, tokenPath: e.target.value }))}
                />
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <Input
                    placeholder="Token prefix"
                    value={authConfig.tokenPrefix}
                    onChange={e => setAuthConfig(prev => ({ ...prev, tokenPrefix: e.target.value }))}
                  />
                  <Input
                    placeholder="Header name"
                    value={authConfig.tokenHeader}
                    onChange={e => setAuthConfig(prev => ({ ...prev, tokenHeader: e.target.value }))}
                  />
                </div>
                <Input
                  placeholder='Persist response headers (JSON array), e.g., ["Set-Cookie"]'
                  value={authConfig.persistHeaders}
                  onChange={e => setAuthConfig(prev => ({ ...prev, persistHeaders: e.target.value }))}
                />
                <div className="flex flex-wrap gap-2">
                  <Button onClick={handleAuthenticate} disabled={isAuthenticating} className="flex-1">
                    {isAuthenticating ? "Authenticating..." : "Authenticate"}
                  </Button>
                  <Button onClick={handleFetchSession} disabled={isFetchingSession} variant="secondary">
                    {isFetchingSession ? "Loading..." : "Fetch Session"}
                  </Button>
                  <Button onClick={handleClearSession} disabled={isClearingSession} variant="ghost">
                    {isClearingSession ? "Clearing..." : "Clear Session"}
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>ZAP Scripting</CardTitle>
                <CardDescription>스크립트를 등록하거나 실행하여 맞춤형 로직을 적용합니다.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Input
                  placeholder="Script name"
                  value={scriptForm.name}
                  onChange={e => setScriptForm(prev => ({ ...prev, name: e.target.value }))}
                />
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <select
                    value={scriptForm.type}
                    onChange={e => setScriptForm(prev => ({ ...prev, type: e.target.value }))}
                    className={selectStyle}
                  >
                    {SCRIPT_TYPES.map(type => (
                      <option key={type} value={type}>
                        {type}
                      </option>
                    ))}
                  </select>
                  <select
                    value={scriptForm.engine}
                    onChange={e => setScriptForm(prev => ({ ...prev, engine: e.target.value }))}
                    className={selectStyle}
                  >
                    {SCRIPT_ENGINES.map(engine => (
                      <option key={engine} value={engine}>
                        {engine}
                      </option>
                    ))}
                  </select>
                </div>
                <textarea
                  className={textareaStyle}
                  placeholder="// Paste your ZAP script content here"
                  value={scriptForm.content}
                  onChange={e => setScriptForm(prev => ({ ...prev, content: e.target.value }))}
                />
                <Input
                  placeholder="Description (optional)"
                  value={scriptForm.description}
                  onChange={e => setScriptForm(prev => ({ ...prev, description: e.target.value }))}
                />
                <div className="flex flex-wrap gap-2">
                  <Button onClick={handleLoadScript} disabled={isSubmittingScript} className="flex-1">
                    {isSubmittingScript ? "Registering..." : "Register Script"}
                  </Button>
                  <Button onClick={handleRunScript} disabled={isRunningScript} variant="secondary">
                    {isRunningScript ? "Running..." : "Run Script"}
                  </Button>
                  <Button onClick={handleDeleteScript} disabled={isDeletingScript} variant="ghost">
                    {isDeletingScript ? "Removing..." : "Delete Script"}
                  </Button>
                </div>
                <Button onClick={fetchScripts} disabled={isLoadingScriptList} variant="outline" className="w-full">
                  {isLoadingScriptList ? "Refreshing..." : "Refresh Script List"}
                </Button>
              </CardContent>
            </Card>
          </div>

          <Card className="h-full">
            <CardHeader className="space-y-0">
              <CardTitle>Analysis Output</CardTitle>
              <CardDescription>정찰, 인증, 스크립트 실행 이후 산출물을 탭으로 살펴보세요.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap gap-2">
                {resultTabs.map(tab => (
                  <Button
                    key={tab.key}
                    size="sm"
                    variant={tab.key === activeResultTab ? "secondary" : "ghost"}
                    disabled={tab.disabled}
                    onClick={() => setActiveResultTab(tab.key)}
                  >
                    {tab.label}
                  </Button>
                ))}
              </div>
              <div className="space-y-4">
                {hasResults ? (
                  renderResultsContent()
                ) : (
                  <p className="text-sm text-muted-foreground">
                    도메인을 정찰하거나 인증/스크립트를 실행하면 결과가 여기에 표시됩니다.
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {!hasResults && assets.length === 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Getting Started</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                도메인을 입력하고 <span className="font-semibold">Discover Assets</span>를 실행하면 나머지 기능들이 활성화됩니다. 로그인 세션이 필요하다면 좌측 카드를 통해 먼저 인증을 수행하세요.
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
